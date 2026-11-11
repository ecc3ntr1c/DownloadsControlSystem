import hashlib
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from django.test import SimpleTestCase, TestCase, override_settings

from files_app.downloaders.exceptions import (
    DownloadContentRejectedError,
    DownloadHttpStatusError,
    DownloadSizeExceededError,
    InvalidDownloadUrlError,
    ProtectedDownloadError,
)
from files_app.downloaders.http import HttpDownloader
from files_app.downloaders.protected_rules import ProtectedDownloadRuleService
from files_app.models import ProtectedDownloadRule, StoredFile
from files_app.services.policies import DownloadPolicyConfig
from files_app.services.storage import FileStorageError, FileStorageService
from files_app.validators.url_validator import DownloadUrlValidator


class DownloadTests(TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name).resolve()
        self.policy = DownloadPolicyConfig(
            allow_http=False, allow_https=True, allow_file_scheme=False,
            allow_url_credentials=False, reject_auth_required=True, reject_html_pages=True,
            allow_private_networks=False, max_file_size_bytes=32, max_redirects=2,
            allowed_domains=["software.example"], allowed_ports=[443],
        )
        self.validator = DownloadUrlValidator(ProtectedDownloadRuleService())
        self.downloader = HttpDownloader(self.validator, chunk_size=4)

    def download(self, handler):
        with (
            patch("files_app.downloaders.http._PinnedDnsTransport", return_value=httpx.MockTransport(handler)),
            patch.object(self.validator, "_resolve_addresses", return_value={"93.184.216.34"}),
        ):
            return self.downloader.download(
                url="https://software.example/package.bin?ticket=test",
                destination_dir=self.path, policy=self.policy,
            )

    def test_streams_and_hashes_file_after_valid_redirect(self):
        content = b"Software package test fixture"
        seen = []

        def respond(request):
            seen.append(request.url.host)
            if len(seen) == 1:
                return httpx.Response(302, headers={"location": "https://cdn.software.example/package.bin"})
            return httpx.Response(200, content=content)

        result = self.download(respond)
        self.assertEqual(seen, ["software.example", "cdn.software.example"])
        self.assertEqual(result.file_path.read_bytes(), content)
        self.assertEqual(result.sha256, hashlib.sha256(content).hexdigest())
        self.assertEqual(result.size, len(content))
        self.assertNotIn("ticket", result.original_url)
        self.assertEqual(list(self.path.iterdir()), [result.file_path])

    def test_limits_stream_without_content_length_and_removes_partial_file(self):
        def respond(_request):
            return httpx.Response(200, stream=httpx.ByteStream(b"x" * 33))

        with self.assertRaises(DownloadSizeExceededError):
            self.download(respond)
        self.assertEqual(list(self.path.iterdir()), [])

    def test_rejects_invalid_content_length_as_http_error(self):
        with self.assertRaises(DownloadHttpStatusError):
            self.download(lambda _: httpx.Response(200, headers={"content-length": "unknown"}, content=b"data"))

    def test_rejects_empty_content(self):
        with self.assertRaises(DownloadContentRejectedError):
            self.download(lambda _: httpx.Response(200, content=b""))

    def test_source_policy_rejects_private_dns_result(self):
        with patch.object(self.validator, "_resolve_addresses", return_value={"10.0.0.2"}):
            with self.assertRaises(InvalidDownloadUrlError):
                self.validator.validate(url="https://software.example/package.bin", policy=self.policy)

    def test_protected_rules_match_any_host_and_domain_suffix(self):
        for pattern in ["", ".software.example"]:
            with self.subTest(pattern=pattern):
                rule = ProtectedDownloadRule.objects.create(name="Stop", host_pattern=pattern, reason="Политика")
                with self.assertRaises(ProtectedDownloadError):
                    self.validator.validate(url="https://cdn.software.example/package.bin", policy=self.policy)
                rule.delete()


class StorageTests(SimpleTestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.enterContext(override_settings(FILE_STORAGE_ROOT=directory.name))
        self.storage = FileStorageService()
        self.storage.ensure_structure()
        self.content = b"Test file bytes"

    def stored_file(self):
        with self.storage.download_workspace() as workspace:
            staging = Path(workspace) / "package.bin"
            staging.write_bytes(self.content)
            path = self.storage.save_file(
                source_path=staging, zone=StoredFile.StorageZone.QUARANTINE, extension=".BIN",
            )
            self.assertFalse(staging.exists())
        return SimpleNamespace(
            storage_path=self.storage.relative_path(path),
            stored_filename=path.name, storage_zone=StoredFile.StorageZone.QUARANTINE,
            size_bytes=len(self.content), file_hash_sha256=hashlib.sha256(self.content).hexdigest(),
        )

    def test_publication_verifies_the_scanned_bytes(self):
        stored_file = self.stored_file()
        original = self.storage.path_for(stored_file)
        approved = self.storage.copy_for_decision(stored_file, StoredFile.StorageZone.APPROVED)
        self.assertEqual(approved.read_bytes(), self.content)
        self.assertTrue(original.exists())

        original.write_bytes(b"X" * len(self.content))
        with self.assertRaises(FileStorageError):
            self.storage.copy_for_decision(stored_file, StoredFile.StorageZone.APPROVED)
        self.assertEqual(approved.read_bytes(), self.content)
        self.assertEqual(list(approved.parent.iterdir()), [approved])

    def test_storage_refuses_a_path_outside_the_recorded_zone(self):
        stored_file = self.stored_file()
        stored_file.storage_path = "/tmp/package.bin"
        with self.assertRaises(FileStorageError):
            self.storage.open_file(stored_file)

    def test_open_accepts_an_existing_absolute_path_inside_the_correct_zone(self):
        stored_file = self.stored_file()
        stored_file.storage_path = str(self.storage.path_for(stored_file))
        with self.storage.open_file(stored_file) as content:
            self.assertEqual(content.read(), self.content)
