import hashlib
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from files_app.models import StoredFile
from files_app.services.storage import FileStorageService

from .contracts import ScannerError
from .credentials import decrypt_api_key, encrypt_api_key
from .models import AntivirusProvider, ScanResult
from .remote import HttpGatewayScanner, VirusTotalScanner


def api_response(payload, status=200, headers=None):
    return httpx.Response(status, stream=httpx.ByteStream(json.dumps(payload).encode()), headers=headers)


def mocked_http(handler):
    return patch("scanning.remote._client", side_effect=lambda: httpx.Client(transport=httpx.MockTransport(handler)))


class RemoteScannerTests(SimpleTestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.enterContext(override_settings(FILE_STORAGE_ROOT=directory.name))
        storage = FileStorageService()
        self.content = b"Benign package bytes for HTTP adapter tests"
        with storage.download_workspace() as workspace:
            path = Path(workspace) / "fixture.bin"
            path.write_bytes(self.content)
            saved = storage.save_file(source_path=path, zone=StoredFile.StorageZone.QUARANTINE, extension="bin")
        self.stored = SimpleNamespace(
            storage_path=storage.relative_path(saved), storage_zone=StoredFile.StorageZone.QUARANTINE,
            stored_filename=saved.name, size_bytes=len(self.content), extension="bin",
            original_filename="original-private-filename.bin",
            file_hash_sha256=hashlib.sha256(self.content).hexdigest(),
        )
        self.provider = AntivirusProvider(encrypted_api_key=encrypt_api_key("example-test-key"), allow_public_uploads=True)

    def analysis(self, *, sha256=None, malicious=0, suspicious=0, undetected=9):
        return {
            "data": {"attributes": {
                "status": "completed",
                "stats": {"malicious": malicious, "suspicious": suspicious, "undetected": undetected, "harmless": 0},
                "results": {"FixtureEngine": {"category": "undetected", "engine_version": "1.0", "result": None}},
            }},
            "meta": {"file_info": {"sha256": sha256 or self.stored.file_hash_sha256}},
        }

    def test_virustotal_upload_then_fetch_engine_report(self):
        calls = []

        def serve(request):
            calls.append((request.method, request.url.path))
            self.assertEqual(request.headers["x-apikey"], "example-test-key")
            if request.method == "POST":
                body = request.read()
                self.assertIn(self.content, body)
                self.assertNotIn(b"original-private-filename", body)
                return api_response({"data": {"id": "fixture-analysis=="}})
            if len(calls) == 2:
                return api_response({"data": {"attributes": {"status": "queued"}}})
            return api_response(self.analysis())

        with mocked_http(serve):
            scanner = VirusTotalScanner(self.provider)
            analysis_id = scanner.submit(self.stored)
            self.assertIsNone(scanner.poll(analysis_id, self.stored.file_hash_sha256))
            outcome = scanner.poll(analysis_id, self.stored.file_hash_sha256)
        self.assertEqual([method for method, _ in calls], ["POST", "GET", "GET"])
        self.assertEqual(outcome.verdict, ScanResult.Verdict.CLEAN)
        self.assertEqual(outcome.summary["stats"]["undetected"], 9)
        self.assertIn("FixtureEngine", outcome.report["results"])

    def test_mismatched_file_and_empty_assessment_are_never_clean(self):
        with mocked_http(lambda _: api_response(self.analysis(sha256="0" * 64))):
            with self.assertRaisesMessage(ScannerError, "SHA-256"):
                VirusTotalScanner(self.provider).poll("fixture", self.stored.file_hash_sha256)
        for stats, expected in [
            ({"undetected": 0}, ScanResult.Verdict.UNKNOWN),
            ({"suspicious": 1}, ScanResult.Verdict.SUSPICIOUS),
            ({"malicious": 1}, ScanResult.Verdict.MALICIOUS),
        ]:
            with self.subTest(stats=stats), mocked_http(lambda _: api_response(self.analysis(**stats))):
                outcome = VirusTotalScanner(self.provider).poll("fixture", self.stored.file_hash_sha256)
                self.assertEqual(outcome.verdict, expected)

    @patch.object(VirusTotalScanner, "DIRECT_UPLOAD_LIMIT", 1)
    def test_large_file_uses_provider_upload_url_over_tls(self):
        calls = []

        def serve(request):
            calls.append(request.url)
            if request.method == "GET":
                return api_response({"data": "http://www.virustotal.com/_ah/upload/fixture"})
            self.assertEqual(request.url.scheme, "https")
            self.assertIn(self.content, request.read())
            return api_response({"data": {"id": "fixture"}})

        with mocked_http(serve):
            self.assertEqual(VirusTotalScanner(self.provider).submit(self.stored), "fixture")
        self.assertEqual([url.path for url in calls], ["/api/v3/files/upload_url", "/_ah/upload/fixture"])

    @patch.object(VirusTotalScanner, "DIRECT_UPLOAD_LIMIT", 1)
    def test_large_upload_rejects_url_outside_provider(self):
        with mocked_http(lambda _: api_response({"data": "https://other.example/upload"})):
            with self.assertRaisesMessage(ScannerError, "неподдерживаемый адрес"):
                VirusTotalScanner(self.provider).submit(self.stored)

    def test_rate_limit_provides_retry_delay(self):
        with mocked_http(lambda _: api_response({}, 429, {"Retry-After": "47"})):
            with self.assertRaises(ScannerError) as result:
                VirusTotalScanner(self.provider).poll("fixture", self.stored.file_hash_sha256)
        self.assertTrue(result.exception.retryable)
        self.assertEqual(result.exception.retry_after, 47)

    def test_ambiguous_post_timeout_is_not_automatically_retried(self):
        def timeout(request):
            raise httpx.ReadTimeout("Fixture", request=request)

        with mocked_http(timeout), self.assertRaises(ScannerError) as result:
            VirusTotalScanner(self.provider).submit(self.stored)
        self.assertFalse(result.exception.retryable)

    def test_local_gateway_uses_configured_base_url_and_returns_details(self):
        self.provider.endpoint = "https://antivirus.example/connector"
        seen = []

        def serve(request):
            self.assertEqual(request.headers["authorization"], "Bearer example-test-key")
            seen.append(request.url.path)
            if request.method == "POST":
                self.assertIn(self.stored.file_hash_sha256.encode(), request.read())
                return api_response({"id": "local-report"}, 202)
            return api_response({
                "status": "completed", "sha256": self.stored.file_hash_sha256,
                "verdict": "CLEAN", "summary": "Проверено локально", "details": {"engine_version": "2026.1"},
            })

        with mocked_http(serve):
            scanner = HttpGatewayScanner(self.provider)
            remote_id = scanner.submit(self.stored)
            outcome = scanner.poll(remote_id, self.stored.file_hash_sha256)
        self.assertEqual(seen, ["/connector/v1/scans", "/connector/v1/scans/local-report"])
        self.assertEqual(outcome.summary["message"], "Проверено локально")
        self.assertEqual(outcome.report["details"]["engine_version"], "2026.1")

    def test_public_upload_requires_explicit_configuration(self):
        self.provider.allow_public_uploads = False
        with self.assertRaisesMessage(ScannerError, "не разрешена"):
            VirusTotalScanner(self.provider)


class AntivirusAdminTests(TestCase):
    def test_admin_saves_a_key_without_returning_it_to_the_browser(self):
        user = get_user_model().objects.create_superuser("provider-admin")
        self.client.force_login(user)
        url = reverse("admin:scanning_antivirusprovider_add")
        data = {"name": "VirusTotal test", "kind": "VIRUSTOTAL", "enabled": "on", "api_key": "example-test-key"}
        response = self.client.post(url, data)
        self.assertContains(response, "Подтверди разрешение")
        self.assertFalse(AntivirusProvider.objects.filter(kind="VIRUSTOTAL").exists())
        self.assertEqual(self.client.post(url, {**data, "allow_public_uploads": "on"}).status_code, 302)
        provider = AntivirusProvider.objects.get(kind="VIRUSTOTAL")
        self.assertNotEqual(provider.encrypted_api_key, data["api_key"])
        self.assertEqual(decrypt_api_key(provider.encrypted_api_key), data["api_key"])
        edit = reverse("admin:scanning_antivirusprovider_change", args=[provider.pk])
        self.assertNotContains(self.client.get(edit), data["api_key"])
        self.assertNotContains(self.client.get(edit), provider.encrypted_api_key)
        self.assertEqual(self.client.post(edit, {
            "name": "VirusTotal renamed", "enabled": "on", "allow_public_uploads": "on",
        }).status_code, 302)
        provider.refresh_from_db()
        self.assertEqual(decrypt_api_key(provider.encrypted_api_key), data["api_key"])

    def test_staff_cannot_manage_provider_configuration(self):
        staff = get_user_model().objects.create_user("staff", is_staff=True)
        staff.user_permissions.add(*Permission.objects.filter(content_type__model="antivirusprovider"))
        self.client.force_login(staff)
        self.assertEqual(self.client.get(reverse("admin:scanning_antivirusprovider_changelist")).status_code, 403)
