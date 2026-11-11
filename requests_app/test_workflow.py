import tempfile
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.db import connections
from django.test import Client, TestCase, TransactionTestCase, override_settings, skipUnlessDBFeature
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from accounts.roles import SOFTWARE_CONTROL_SECURITY_GROUP
from audit.models import AuditLog
from files_app.models import ProhibitedSoftwareRule, StoredFile
from files_app.services.retention import cleanup_expired_files
from files_app.services.storage import FileStorageService
from notifications.models import Notification
from scanning.clamav import ScanOutcome
from scanning.models import ScanResult

from .models import SoftwareRequest
from .processing import _claim_request, process_request
from .services import ApprovalService, SoftwareRequestService
from .tests import download_fixture

PAYLOAD = {
    "source_url": "https://software.example/test.bin?ticket=private",
    "description": "Test package",
    "business_reason": "Development",
}


class WorkflowTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        call_command("init_roles", verbosity=0)
        cls.owner = get_user_model().objects.create_user("owner", password="local-owner-test")
        cls.other_user = get_user_model().objects.create_user("other")
        cls.officer = get_user_model().objects.create_user("officer")
        cls.officer.groups.add(Group.objects.get(name=SOFTWARE_CONTROL_SECURITY_GROUP))

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.enterContext(override_settings(FILE_STORAGE_ROOT=directory.name))
        self.storage = FileStorageService()
        self.browser = Client()
        self.api = APIClient()

    def create_request(self):
        return SoftwareRequestService.create_request(user=self.owner, validated_data=PAYLOAD)

    def process(self, request, verdict=ScanResult.Verdict.CLEAN):
        with (
            patch("files_app.services.downloads.build_download_manager") as factory,
            patch("requests_app.processing.ClamAVScanner.scan", return_value=ScanOutcome(verdict)),
        ):
            factory.return_value.download.side_effect = download_fixture
            self.assertEqual(process_request(request.pk), "review_ready")
        request.refresh_from_db()

    def decision(self, request, *, action="approve", user=None, comment=""):
        self.api.force_authenticate(user or self.officer)
        with self.captureOnCommitCallbacks(execute=True):
            return self.api.post(
                reverse(f"security-request-{action}", args=[request.pk]),
                {"security_comment": comment}, format="json",
            )

    def test_portal_to_approval_and_authorized_delivery(self):
        browser = Client(enforce_csrf_checks=True)
        self.assertRedirects(browser.get("/"), "/login/?next=/", fetch_redirect_response=False)
        browser.get("/login/")
        login = browser.post("/login/", {
            "username": "owner", "password": "local-owner-test",
            "csrfmiddlewaretoken": browser.cookies["csrftoken"].value,
        })
        self.assertRedirects(login, "/", fetch_redirect_response=False)
        self.assertEqual(browser.post("/requests/new/", PAYLOAD).status_code, 403)
        create = browser.post("/requests/new/", {**PAYLOAD, "csrfmiddlewaretoken": browser.cookies["csrftoken"].value})
        request = SoftwareRequest.objects.get()
        self.assertRedirects(create, reverse("portal-request", args=[request.pk]), fetch_redirect_response=False)
        self.process(request)
        stored_file = request.review_file
        quarantine = self.storage.path_for(stored_file)
        link = reverse("approved-file-download", args=[stored_file.pk])
        self.assertEqual(browser.get(link).status_code, 404)
        self.assertNotContains(browser.get(create.url), link)
        self.assertEqual(browser.get("/security/").status_code, 403)

        self.browser.force_login(self.officer)
        review_url = reverse("portal-security-request", args=[request.pk])
        self.assertContains(self.browser.get(review_url), "ClamAV")
        with self.captureOnCommitCallbacks(execute=True):
            decision = self.browser.post(
                reverse("portal-security-action", args=[request.pk, "approve"]),
                {"security_comment": "Проверено"},
            )
        self.assertRedirects(decision, review_url)
        self.assertFalse(quarantine.exists())
        stored_file.refresh_from_db()
        self.assertEqual(stored_file.storage_zone, StoredFile.StorageZone.APPROVED)
        self.assertContains(browser.get(create.url), link)
        self.assertContains(browser.get("/notifications/"), "ИБ разрешила выдачу")
        self.assertEqual(self.browser.get(link).status_code, 404)
        self.browser.force_login(self.other_user)
        self.assertEqual(self.browser.get(link).status_code, 404)
        self.assertEqual(self.browser.get(create.url).status_code, 404)

        self.api.force_authenticate(self.owner)
        request_data = self.api.get(reverse("software-request-detail", args=[request.pk])).data
        self.assertTrue(request_data["download_url"].endswith(link))
        self.assertNotIn("ticket", request_data["source_url"])

        head = browser.head(link)
        self.assertEqual(head.status_code, 200)
        stored_file.refresh_from_db()
        self.assertEqual(stored_file.download_count, 0)
        response = browser.get(link)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(b"".join(response.streaming_content), b"Benign installation package fixture")
        self.assertIn("attachment", response.headers["Content-Disposition"])
        self.assertEqual(response.headers["Cache-Control"], "private, no-store")
        self.assertEqual(AuditLog.objects.get(action="FILE_DOWNLOAD_AUTHORIZED").actor_id, self.owner.pk)
        stored_file.refresh_from_db()
        self.assertEqual(stored_file.download_count, 1)
        request.refresh_from_db()
        self.assertEqual(request.request_status, SoftwareRequest.RequestStatus.DOWNLOADED)
        self.assertEqual(browser.post(link, {"csrfmiddlewaretoken": browser.cookies["csrftoken"].value}).status_code, 405)

    def test_decisions_require_completed_processing_and_security_permission(self):
        request = self.create_request()
        self.assertEqual(self.decision(request).status_code, 409)
        self.assertEqual(self.decision(request, action="reject", comment="Нет").status_code, 409)
        self.process(request)
        self.assertEqual(self.decision(request, user=self.owner).status_code, 403)
        self.assertEqual(self.decision(request).status_code, 200)
        self.assertEqual(self.decision(request).status_code, 409)
        self.assertEqual(self.decision(request, action="reject", comment="Нет").status_code, 409)
        self.assertEqual(AuditLog.objects.filter(action="REQUEST_APPROVED").count(), 1)

    def test_infected_file_cannot_be_approved_and_can_be_rejected(self):
        request = self.create_request()
        self.process(request, ScanResult.Verdict.MALICIOUS)
        self.api.force_authenticate(self.officer)
        review = self.api.get(reverse("security-request-detail", args=[request.pk])).data
        self.assertEqual(review["scan"]["verdict"], ScanResult.Verdict.MALICIOUS)
        self.assertIsNone(review["download_url"])
        self.assertEqual(self.decision(request).status_code, 409)
        self.assertEqual(self.decision(request, action="reject").status_code, 400)
        self.assertEqual(self.decision(request, action="reject", comment="Обнаружена сигнатура").status_code, 200)
        request.refresh_from_db()
        self.assertEqual(request.request_status, SoftwareRequest.RequestStatus.REJECTED)
        self.assertEqual(request.review_file.storage_zone, StoredFile.StorageZone.REJECTED)
        self.assertFalse(request.review_file.is_available)

    def test_legacy_mock_record_requires_real_reprocessing(self):
        request = self.create_request()
        SoftwareRequest.objects.filter(pk=request.pk).update(
            request_status=SoftwareRequest.RequestStatus.WAITING_SECURITY_DECISION,
            scan_status=SoftwareRequest.ScanStatus.SCAN_COMPLETED, processing_due_at=None,
        )
        ScanResult.objects.create(request=request, provider=ScanResult.Provider.MOCK, verdict=ScanResult.Verdict.CLEAN)
        self.assertEqual(self.decision(request).status_code, 409)
        with patch("requests_app.tasks.process_software_request_task.apply_async"):
            self.assertEqual(self.decision(request, action="reprocess").status_code, 200)
        self.process(request)
        self.assertEqual(request.scan_results.count(), 2)
        self.assertEqual(self.decision(request).status_code, 200)

    def test_override_requires_comment_and_is_audited(self):
        rule = ProhibitedSoftwareRule.objects.create(
            name="Registry rule", match_type=ProhibitedSoftwareRule.MatchType.CONTAINS,
            pattern="Test package", reason="Требует решения ИБ", allow_security_override=True,
        )
        request = self.create_request()
        self.process(request)
        self.assertEqual(self.decision(request).status_code, 409)
        self.assertEqual(self.decision(request, comment="Согласовано исключение").status_code, 200)
        match = request.prohibited_matches.get()
        self.assertEqual(match.overridden_by_id, self.officer.pk)
        self.assertEqual(AuditLog.objects.get(action="REQUEST_APPROVED").details["overridden_rule_ids"], [rule.pk])

    def test_altered_file_is_not_published(self):
        request = self.create_request()
        self.process(request)
        stored_file = request.review_file
        self.storage.path_for(stored_file).write_bytes(b"x" * stored_file.size_bytes)
        self.assertEqual(self.decision(request).status_code, 503)
        stored_file.refresh_from_db()
        self.assertFalse(stored_file.is_available)
        self.assertFalse(self.storage.zone_path(StoredFile.StorageZone.APPROVED, stored_file.stored_filename).exists())

    def test_approval_database_failure_removes_uncommitted_copy(self):
        request = self.create_request()
        self.process(request)
        stored_file = request.review_file
        with (
            patch("requests_app.services.notify_request_owner", side_effect=RuntimeError),
            self.assertRaises(RuntimeError),
        ):
            ApprovalService.approve_request(software_request=request, security_user=self.officer)
        stored_file.refresh_from_db()
        self.assertFalse(stored_file.is_available)
        self.assertTrue(self.storage.path_for(stored_file).is_file())
        self.assertFalse(self.storage.zone_path(StoredFile.StorageZone.APPROVED, stored_file.stored_filename).exists())

    @override_settings(FILE_DELIVERY_ACCEL=True)
    def test_expiration_blocks_before_cleanup_and_removes_bytes(self):
        request = self.create_request()
        self.process(request)
        self.assertEqual(self.decision(request).status_code, 200)
        stored_file = StoredFile.objects.get(pk=request.review_file_id)
        link = reverse("approved-file-download", args=[stored_file.pk])
        self.browser.force_login(self.owner)
        response = self.browser.get(link)
        self.assertEqual(response.headers["X-Accel-Redirect"], f"/_approved/{stored_file.stored_filename}")
        path = self.storage.path_for(stored_file)
        StoredFile.objects.filter(pk=stored_file.pk).update(delete_after=timezone.now())
        self.assertEqual(self.browser.get(link).status_code, 404)
        self.assertEqual(cleanup_expired_files(), 1)
        self.assertEqual(cleanup_expired_files(), 0)
        self.assertFalse(path.exists())
        stored_file.refresh_from_db()
        request.refresh_from_db()
        self.assertEqual(stored_file.storage_zone, StoredFile.StorageZone.DELETED)
        self.assertEqual(request.request_status, SoftwareRequest.RequestStatus.CLOSED)
        self.assertTrue(Notification.objects.filter(request=request, event=Notification.Event.EXPIRED).exists())


class ConcurrentClaimTests(TransactionTestCase):
    @skipUnlessDBFeature("has_select_for_update")
    def test_two_worker_connections_cannot_claim_the_same_request(self):
        owner = get_user_model().objects.create_user("concurrency")
        with patch("requests_app.tasks.publish_request"):
            request = SoftwareRequestService.create_request(user=owner, validated_data=PAYLOAD)
        barrier = Barrier(2)

        def claim():
            try:
                barrier.wait(timeout=5)
                return _claim_request(request.pk)
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as executor:
            first, second = [executor.submit(claim) for _ in range(2)]
            results = [first.result(timeout=10), second.result(timeout=10)]
        self.assertEqual(sum(result is not None for result in results), 1)
