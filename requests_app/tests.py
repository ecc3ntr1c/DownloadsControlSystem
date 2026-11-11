import hashlib
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from kombu.exceptions import OperationalError
from rest_framework.test import APIClient

from audit.models import AuditLog
from files_app.downloaders.base import DownloadResult
from files_app.downloaders.exceptions import DownloadNetworkError
from files_app.models import FileTypePolicy, ProhibitedSoftwareRule, StoredFile
from files_app.services.storage import FileStorageService
from scanning.clamav import ScanOutcome, ScannerError
from scanning.models import ProviderScan, ScanResult

from .models import SoftwareRequest
from .processing import _claim_request, process_request
from .services import SoftwareRequestService
from .tasks import dispatch_pending_requests


def download_fixture(*, source, destination_dir):
    content = b"Benign installation package fixture"
    path = Path(destination_dir) / "test.bin"
    path.write_bytes(content)
    return DownloadResult(
        file_path=path, original_url="https://downloads.example/test.bin",
        final_url="https://downloads.example/test.bin", filename="test.bin",
        extension="bin", size=len(content), sha256=hashlib.sha256(content).hexdigest(),
        mime_type="application/octet-stream", declared_content_type="application/octet-stream",
    )


class ProcessingTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("employee")
        self.payload = {
            "source_url": "https://downloads.example/test.bin?temporary=token",
            "description": "Package fixture",
            "business_reason": "Development",
        }

    def create_request(self):
        return SoftwareRequestService.create_request(user=self.user, validated_data=self.payload)

    def test_request_enqueue_waits_for_commit_and_recovers_broker_failure(self):
        with (
            patch("requests_app.tasks.process_software_request_task.apply_async", side_effect=OperationalError) as queue,
            self.assertLogs("requests_app.tasks", level="WARNING"),
        ):
            with self.captureOnCommitCallbacks(execute=True):
                request = self.create_request()
                queue.assert_not_called()
                self.assertTrue(request.file_sources.exists())
            queue.assert_called_once()
        request.refresh_from_db()
        self.assertIsNone(request.last_queued_at)
        with patch("requests_app.tasks.process_software_request_task.apply_async") as queue:
            dispatch_pending_requests.run()
        queue.assert_called_once()
        self.assertNotIn("token", str(AuditLog.objects.get(action="REQUEST_CREATED").details))

    def test_request_fetches_quarantines_and_scans_once(self):
        request = self.create_request()
        with (
            patch("files_app.services.downloads.build_download_manager") as factory,
            patch("requests_app.processing.ClamAVScanner.scan", return_value=ScanOutcome(ScanResult.Verdict.CLEAN)),
        ):
            factory.return_value.download.side_effect = download_fixture
            self.assertEqual(process_request(request.pk), "review_ready")
            self.assertEqual(process_request(request.pk), "skipped")
            factory.return_value.download.assert_called_once()
        request.refresh_from_db()
        self.assertEqual(request.request_status, SoftwareRequest.RequestStatus.WAITING_SECURITY_DECISION)
        self.assertEqual(request.scan_status, SoftwareRequest.ScanStatus.SCAN_COMPLETED)
        stored_file = request.review_file
        self.assertEqual(stored_file.storage_zone, StoredFile.StorageZone.QUARANTINE)
        self.assertFalse(stored_file.is_available)
        self.assertTrue(FileStorageService().path_for(stored_file).is_file())
        result = request.scan_results.get()
        self.assertEqual(result.file_id, stored_file.pk)
        self.assertEqual(result.file_sha256, stored_file.file_hash_sha256)
        self.assertEqual(result.provider, ScanResult.Provider.CLAMAV)

    def test_transient_download_failure_retries_then_finishes_as_failed(self):
        request = self.create_request()
        with patch("files_app.services.downloads.build_download_manager") as factory:
            factory.return_value.download.side_effect = DownloadNetworkError("Temporary")
            self.assertEqual(process_request(request.pk), "retry_scheduled")
            self.assertEqual(process_request(request.pk), "skipped")
            for expected in ("retry_scheduled", "failed"):
                SoftwareRequest.objects.filter(pk=request.pk).update(processing_due_at=timezone.now())
                self.assertEqual(process_request(request.pk), expected)
        request.refresh_from_db()
        self.assertEqual(request.processing_attempts, 3)
        self.assertEqual(request.scan_status, SoftwareRequest.ScanStatus.SCAN_FAILED)
        self.assertIsNone(request.processing_due_at)
        self.assertFalse(request.files.exists())

    def test_scanner_error_retries_using_the_same_quarantined_file(self):
        request = self.create_request()
        with (
            patch("files_app.services.downloads.build_download_manager") as factory,
            patch("requests_app.processing.ClamAVScanner.scan", side_effect=[
                ScannerError("Scanner temporarily unavailable", retryable=True),
                ScanOutcome(ScanResult.Verdict.CLEAN),
            ]),
        ):
            factory.return_value.download.side_effect = download_fixture
            self.assertEqual(process_request(request.pk), "retry_scheduled")
            SoftwareRequest.objects.filter(pk=request.pk).update(processing_due_at=timezone.now())
            ProviderScan.objects.filter(file__request=request).update(next_check_at=timezone.now())
            self.assertEqual(process_request(request.pk), "review_ready")
            factory.return_value.download.assert_called_once()
        self.assertEqual(request.files.count(), 1)
        self.assertEqual(list(request.scan_results.order_by("pk").values_list("verdict", flat=True)), ["FAILED", "CLEAN"])

    def test_hard_registry_match_skips_download_and_is_visible_for_review(self):
        ProhibitedSoftwareRule.objects.create(
            name="Rule", match_type=ProhibitedSoftwareRule.MatchType.DOMAIN,
            pattern="downloads.example", reason="Заблокировано", allow_security_override=False,
        )
        request = self.create_request()
        with patch("files_app.services.downloads.build_download_manager") as factory:
            self.assertEqual(process_request(request.pk), "failed")
            factory.assert_not_called()
        request.refresh_from_db()
        self.assertEqual(request.prohibited_matches.count(), 1)
        self.assertEqual(request.request_status, SoftwareRequest.RequestStatus.WAITING_SECURITY_DECISION)
        self.assertEqual(request.scan_status, SoftwareRequest.ScanStatus.SCAN_FAILED)

    def test_file_type_block_retains_quarantined_file_and_skips_scanner(self):
        FileTypePolicy.objects.create(extension=".BIN", is_allowed=False)
        request = self.create_request()
        with (
            patch("files_app.services.downloads.build_download_manager") as factory,
            patch("requests_app.processing.ClamAVScanner.scan") as scan,
        ):
            factory.return_value.download.side_effect = download_fixture
            self.assertEqual(process_request(request.pk), "failed")
            scan.assert_not_called()
        request.refresh_from_db()
        self.assertFalse(request.review_file.is_available)
        self.assertIn("Тип файла", request.processing_error)

    def test_processing_lease_excludes_duplicate_and_can_be_reclaimed_after_worker_loss(self):
        request = self.create_request()
        first_claim = _claim_request(request.pk)
        self.assertIsNone(_claim_request(request.pk))
        SoftwareRequest.objects.filter(pk=request.pk).update(processing_due_at=timezone.now())
        second_claim = _claim_request(request.pk)
        self.assertNotEqual(first_claim.processing_token, second_claim.processing_token)
        self.assertEqual(second_claim.processing_attempts, 2)

    def test_api_rejects_unsupported_source_scheme(self):
        client = APIClient()
        client.force_authenticate(self.user)
        response = client.post("/api/v1/requests/create/", {**self.payload, "source_url": "ftp://downloads.example/file"})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(SoftwareRequest.objects.exists())
