from datetime import timedelta
from unittest.mock import patch

from billiard.exceptions import SoftTimeLimitExceeded
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from accounts.roles import SOFTWARE_CONTROL_SECURITY_GROUP
from scanning.contracts import ScanOutcome, ScannerError
from scanning.models import AntivirusProvider, ProviderScan, ScanResult

from .models import SoftwareRequest
from .processing import process_request
from .services import SoftwareRequestService
from .test_workflow import PAYLOAD
from .tests import download_fixture


class AntivirusWorkflowTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        call_command("init_roles", verbosity=0)
        cls.owner = get_user_model().objects.create_user("av-owner")
        cls.officer = get_user_model().objects.create_user("av-officer")
        cls.officer.groups.add(Group.objects.get(name=SOFTWARE_CONTROL_SECURITY_GROUP))
        cls.provider = AntivirusProvider.objects.create(
            name="VirusTotal Lab", kind=AntivirusProvider.Kind.VIRUSTOTAL, enabled=True, allow_public_uploads=True,
        )

    def setUp(self):
        self.request = SoftwareRequestService.create_request(user=self.owner, validated_data=PAYLOAD)
        self.api = APIClient()
        self.api.force_authenticate(self.officer)
        factory = self.enterContext(patch("files_app.services.downloads.build_download_manager"))
        factory.return_value.download.side_effect = download_fixture
        self.download = factory.return_value.download
        self.local_scan = self.enterContext(patch(
            "requests_app.processing.ClamAVScanner.scan", return_value=ScanOutcome(ScanResult.Verdict.CLEAN),
        ))
        self.remote = self.enterContext(patch("requests_app.processing.remote_scanner")).return_value
        self.remote.submit.return_value = "remote-fixture"

    def advance(self):
        SoftwareRequest.objects.filter(pk=self.request.pk).update(processing_due_at=timezone.now())
        ProviderScan.objects.filter(file__request=self.request).update(next_check_at=timezone.now())

    def approve(self):
        return self.api.post(reverse("security-request-approve", args=[self.request.pk]), {}, format="json")

    def test_waits_for_all_providers_and_displays_expanded_report_only_to_security(self):
        self.remote.poll.side_effect = [
            None,
            ScanOutcome(
                ScanResult.Verdict.CLEAN, summary={"stats": {"malicious": 0, "undetected": 1}},
                report={"results": {"FixtureEngine": {"category": "undetected", "engine_version": "1.0"}}},
            ),
        ]
        self.assertEqual(process_request(self.request.pk), "scan_pending")
        self.assertEqual(self.approve().status_code, 409)
        detail = reverse("security-request-detail", args=[self.request.pk])
        self.assertEqual(self.api.get(detail).data["reports"][1]["status"], "waiting_report")

        self.advance()
        self.assertEqual(process_request(self.request.pk), "scan_pending")
        self.advance()
        self.assertEqual(process_request(self.request.pk), "review_ready")
        self.remote.submit.assert_called_once()
        self.local_scan.assert_called_once()
        self.download.assert_called_once()
        response = self.api.get(detail)
        reports = response.data["reports"]
        self.assertEqual([item["result"]["verdict"] for item in reports], ["CLEAN", "CLEAN"])
        self.client.force_login(self.officer)
        page = self.client.get(reverse("portal-security-request", args=[self.request.pk]))
        self.assertContains(page, "<details>")
        self.assertContains(page, "FixtureEngine")
        report = reverse("security-scan-report", args=[self.request.pk, reports[1]["result"]["id"]])
        self.assertIn("FixtureEngine", self.api.get(report).data["raw_result"]["results"])
        self.assertEqual(self.approve().status_code, 200)
        self.api.force_authenticate(self.owner)
        self.assertEqual(self.api.get(report).status_code, 403)
        self.client.force_login(self.owner)
        self.assertNotContains(self.client.get(reverse("portal-request", args=[self.request.pk])), "FixtureEngine")

    def test_detection_by_one_provider_prevents_release(self):
        self.remote.poll.return_value = ScanOutcome(ScanResult.Verdict.MALICIOUS)
        self.assertEqual(process_request(self.request.pk), "scan_pending")
        self.advance()
        self.assertEqual(process_request(self.request.pk), "review_ready")
        self.assertEqual(self.approve().status_code, 409)
        self.request.refresh_from_db()
        self.assertEqual(self.request.risk_level, SoftwareRequest.RiskLevel.CRITICAL)
        self.assertFalse(self.request.review_file.is_available)

    def test_transient_poll_failure_does_not_upload_file_again(self):
        self.remote.poll.side_effect = [
            ScannerError("Временный лимит", retryable=True, retry_after=60),
            ScanOutcome(ScanResult.Verdict.CLEAN),
        ]
        self.assertEqual(process_request(self.request.pk), "scan_pending")
        self.advance()
        self.assertEqual(process_request(self.request.pk), "retry_scheduled")
        self.advance()
        self.assertEqual(process_request(self.request.pk), "review_ready")
        self.remote.submit.assert_called_once()
        self.assertEqual(self.remote.poll.call_count, 2)

    def test_disabling_pending_provider_does_not_silently_skip_its_report(self):
        self.assertEqual(process_request(self.request.pk), "scan_pending")
        AntivirusProvider.objects.filter(pk=self.provider.pk).update(enabled=False)
        self.advance()
        self.assertEqual(process_request(self.request.pk), "failed")
        self.remote.poll.assert_not_called()
        self.assertEqual(self.approve().status_code, 409)

    def test_disabling_provider_during_local_scan_prevents_unsent_upload(self):
        def local_outcome(_file):
            AntivirusProvider.objects.filter(pk=self.provider.pk).update(enabled=False)
            return ScanOutcome(ScanResult.Verdict.CLEAN)

        self.local_scan.side_effect = local_outcome
        self.assertEqual(process_request(self.request.pk), "failed")
        self.remote.submit.assert_not_called()

    def test_report_timeout_does_not_start_a_second_submission(self):
        self.assertEqual(process_request(self.request.pk), "scan_pending")
        ProviderScan.objects.filter(provider=self.provider).update(created_at=timezone.now() - timedelta(hours=1))
        self.advance()
        self.assertEqual(process_request(self.request.pk), "failed")
        self.remote.submit.assert_called_once()
        self.remote.poll.assert_not_called()

    def test_worker_interrupted_during_upload_does_not_repeat_it(self):
        self.remote.submit.side_effect = SoftTimeLimitExceeded
        self.assertEqual(process_request(self.request.pk), "retry_scheduled")
        self.advance()
        self.assertEqual(process_request(self.request.pk), "failed")
        self.remote.submit.assert_called_once()

    def test_no_configured_antivirus_fails_closed(self):
        AntivirusProvider.objects.update(enabled=False)
        self.assertEqual(process_request(self.request.pk), "failed")
        self.local_scan.assert_not_called()
        self.remote.submit.assert_not_called()
        self.assertEqual(self.approve().status_code, 409)
