import logging
import uuid
from datetime import timedelta

from billiard.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from audit.models import AuditLog
from audit.services import AuditService
from files_app.downloaders.exceptions import DownloadError
from files_app.models import FileSource, ProhibitedSoftwareMatch, StoredFile
from files_app.services.downloads import DownloadService
from files_app.services.policies import DownloadPolicyUnavailable
from files_app.services.review_policies import (
    RuleConfigurationError,
    file_type_blockers,
    find_prohibited_matches,
    prevents_release,
)
from notifications.models import Notification
from notifications.services import notify_request_owner
from scanning.clamav import ClamAVScanner
from scanning.contracts import ScanOutcome, ScannerError
from scanning.models import AntivirusProvider, ProviderScan, ScanResult
from scanning.remote import remote_scanner

from .models import SoftwareRequest
from .source_urls import parse_source_url

logger = logging.getLogger(__name__)
RequestStatus = SoftwareRequest.RequestStatus
ScanStatus = SoftwareRequest.ScanStatus
Risk = SoftwareRequest.RiskLevel


class LeaseLost(Exception):
    pass


class ProcessingBlocked(Exception):
    pass


def process_request(request_id):
    """Одна попытка обработки. Повторная доставка безопасна благодаря блокировке и токену."""
    claimed = _claim_request(request_id)
    if claimed is None:
        return "skipped"

    source = None
    stored_file = None
    try:
        source = _get_source(claimed)
        if claimed.review_file_id is None or not ProviderScan.objects.filter(file_id=claimed.review_file_id).exists():
            _check_registry(claimed, source)
        stored_file = claimed.review_file or _download(claimed, source)
        if stored_file.request_id != claimed.pk or stored_file.storage_zone != StoredFile.StorageZone.QUARANTINE:
            raise ProcessingBlocked("Проверять можно только файл этой заявки из карантина.")
        if stored_file.delete_after is not None and stored_file.delete_after <= timezone.now():
            raise ProcessingBlocked("Истёк срок хранения файла в карантине.")
        blockers = file_type_blockers(stored_file)
        if blockers:
            raise ProcessingBlocked(" ".join(blockers))
        return _process_antiviruses(claimed, stored_file)
    except LeaseLost:
        return "skipped"
    except (DownloadError, DownloadPolicyUnavailable) as exc:
        return _record_failure(claimed, download_failure=(source, exc))
    except (ProcessingBlocked, RuleConfigurationError) as exc:
        return _record_failure(claimed, str(exc))
    except SoftTimeLimitExceeded:
        return _record_failure(claimed, "Истекло время обработки заявки.", retryable=True)
    except Exception as exc:
        logger.error("Ошибка обработки заявки %s (%s)", request_id, type(exc).__name__)
        return _record_failure(claimed, "Внутренняя ошибка обработки заявки.")


@transaction.atomic
def _claim_request(request_id):
    now = timezone.now()
    request = SoftwareRequest.objects.select_for_update().filter(
        pk=request_id, request_status=RequestStatus.UNDER_SECURITY_REVIEW, processing_due_at__lte=now,
    ).first()
    if request is None:
        return None
    if request.processing_attempts >= settings.PROCESS_MAX_ATTEMPTS:
        _finish_failure(request, "Не удалось завершить обработку после повторных попыток.")
        return None

    request.processing_token = uuid.uuid4()
    request.processing_due_at = now + timedelta(seconds=settings.PROCESS_LEASE_SECONDS)
    request.processing_attempts += 1
    request.processing_error = ""
    request.scan_status = ScanStatus.SCANNING if request.review_file_id else ScanStatus.URL_VALIDATION
    request.save(update_fields=[
        "processing_token", "processing_due_at", "processing_attempts", "processing_error",
        "scan_status", "updated_at",
    ])
    _audit(request, "PROCESSING_STARTED", attempt=request.processing_attempts)
    return request


def _locked_request(claimed):
    request = SoftwareRequest.objects.select_for_update().filter(
        pk=claimed.pk, request_status=RequestStatus.UNDER_SECURITY_REVIEW,
        processing_token=claimed.processing_token,
    ).first()
    if request is None:
        raise LeaseLost
    return request


def _get_source(request):
    try:
        return request.file_sources.get()
    except (FileSource.DoesNotExist, FileSource.MultipleObjectsReturned) as exc:
        raise ProcessingBlocked("Заявка должна содержать один источник файла.") from exc


def _check_registry(claimed, source):
    try:
        parsed = parse_source_url(source.original_url)
    except ValueError as exc:
        raise ProcessingBlocked(str(exc)) from exc
    matches = find_prohibited_matches(claimed, parsed.hostname)
    with transaction.atomic():
        request = _locked_request(claimed)
        request.prohibited_matches.all().delete()
        if matches:
            ProhibitedSoftwareMatch.objects.bulk_create(matches)
            _audit(request, "PROHIBITED_SOFTWARE_MATCHED", rule_ids=[match.rule_id for match in matches])
    if any(prevents_release(match.rule) for match in matches):
        raise ProcessingBlocked("Заявка совпала с запрещающим правилом без права исключения.")


def _download(claimed, source):
    with transaction.atomic():
        request = _locked_request(claimed)
        request.scan_status = ScanStatus.DOWNLOADING
        request.save(update_fields=["scan_status", "updated_at"])
        source.status = FileSource.SourceStatus.DOWNLOAD_STARTED
        source.error_message = ""
        source.save(update_fields=["status", "error_message", "updated_at"])
        _audit(request, "FILE_DOWNLOAD_STARTED", file_source_id=source.pk)

    with DownloadService.fetch(source) as result, DownloadService.quarantine(result) as quarantined:
        with transaction.atomic():
            request = _locked_request(claimed)
            stored_file = DownloadService.register(source, quarantined)
            stored_file.delete_after = timezone.now() + timedelta(days=settings.QUARANTINE_RETENTION_DAYS)
            stored_file.save(update_fields=["delete_after"])
            request.review_file = stored_file
            request.scan_status = ScanStatus.DOWNLOADED
            request.save(update_fields=["review_file", "scan_status", "updated_at"])
            return stored_file


def _process_antiviruses(claimed, stored_file):
    _start_scan(claimed, stored_file)
    checks = stored_file.antivirus_checks.filter(result__isnull=True).select_related("provider")
    for check in checks:
        now = timezone.now()
        deadline = check.created_at + timedelta(seconds=settings.ANTIVIRUS_MAX_WAIT_SECONDS)
        if check.next_check_at > now and deadline > now:
            continue
        try:
            if deadline <= now:
                raise ScannerError("Истекло время ожидания отчёта антивируса.")
            if not check.provider.enabled:
                raise ScannerError("Подключение антивируса отключено администратором.")
            if check.provider.kind == AntivirusProvider.Kind.CLAMAV:
                outcome = ClamAVScanner().scan(stored_file)
            else:
                outcome = _scan_remote(claimed, check, stored_file)
            if outcome is not None:
                _save_scan_outcome(claimed, check, outcome)
        except ScannerError as exc:
            _save_scan_error(claimed, check, exc)
    return _finish_or_defer_scans(claimed, stored_file)


@transaction.atomic
def _start_scan(claimed, stored_file):
    request = _locked_request(claimed)
    if stored_file.antivirus_checks.exists():
        return
    providers = list(AntivirusProvider.objects.filter(enabled=True))
    if not providers:
        raise ProcessingBlocked("Администратор не подключил ни одного антивируса.")
    ProviderScan.objects.bulk_create([
        ProviderScan(file=stored_file, provider=provider, provider_name=provider.name) for provider in providers
    ])
    request.scan_status = ScanStatus.SCANNING
    request.save(update_fields=["scan_status", "updated_at"])
    _audit(request, "SCAN_STARTED", stored_file_id=stored_file.pk, providers=[provider.pk for provider in providers])


def _scan_remote(claimed, check, stored_file):
    scanner = remote_scanner(check.provider)
    if not check.remote_id:
        if check.submitting:
            raise ScannerError("Предыдущая отправка не подтверждена. Проверь историю у антивируса.")
        # Если процесс оборвётся между POST и сохранением ID, файл не отправится повторно автоматически.
        with transaction.atomic():
            _locked_request(claimed)
            check.submitting = True
            check.save(update_fields=["submitting"])
        remote_id = scanner.submit(stored_file)
        _wait_for_report(claimed, check, remote_id)
        return None

    outcome = scanner.poll(check.remote_id, stored_file.file_hash_sha256)
    if outcome is None:
        _wait_for_report(claimed, check, check.remote_id)
    return outcome


@transaction.atomic
def _wait_for_report(claimed, check, remote_id):
    _locked_request(claimed)
    check.remote_id = remote_id
    check.submitting = False
    check.failures = 0
    check.last_error = ""
    check.next_check_at = timezone.now() + timedelta(seconds=settings.ANTIVIRUS_POLL_SECONDS)
    check.save(update_fields=["remote_id", "submitting", "failures", "last_error", "next_check_at"])


RISKS = {
    ScanResult.Verdict.CLEAN: (Risk.LOW, 0),
    ScanResult.Verdict.UNKNOWN: (Risk.UNKNOWN, 0),
    ScanResult.Verdict.FAILED: (Risk.UNKNOWN, 0),
    ScanResult.Verdict.SUSPICIOUS: (Risk.HIGH, 75),
    ScanResult.Verdict.MALICIOUS: (Risk.CRITICAL, 100),
}


def _new_result(request, check, outcome):
    risk, score = RISKS[outcome.verdict]
    summary = dict(outcome.summary)
    if outcome.signature:
        summary["signature"] = outcome.signature
    return ScanResult.objects.create(
        request=request, file=check.file,
        file_sha256=check.file.file_hash_sha256 if outcome.verdict != ScanResult.Verdict.FAILED else "",
        provider=check.provider.kind, verdict=outcome.verdict, risk_level=risk, risk_score=score,
        normalized_result=summary, raw_result=outcome.report,
    )


@transaction.atomic
def _save_scan_outcome(claimed, check, outcome):
    request = _locked_request(claimed)
    check.result = _new_result(request, check, outcome)
    check.last_error = ""
    check.save(update_fields=["result", "last_error"])
    _audit(request, "ANTIVIRUS_SCAN_COMPLETED", provider_id=check.provider_id, scan_result_id=check.result_id)


@transaction.atomic
def _save_scan_error(claimed, check, error):
    request = _locked_request(claimed)
    check.failures += 1
    check.last_error = str(error)[:512]
    result = _new_result(request, check, ScanOutcome(ScanResult.Verdict.FAILED, summary={"error": check.last_error}))
    if error.retryable and check.failures < settings.PROCESS_MAX_ATTEMPTS:
        delay = error.retry_after or 15 * 2 ** (check.failures - 1)
        check.submitting = False
        check.next_check_at = timezone.now() + timedelta(seconds=delay)
    else:
        check.result = result
    check.save(update_fields=["failures", "last_error", "result", "submitting", "next_check_at"])
    _audit(request, "ANTIVIRUS_SCAN_FAILED", provider_id=check.provider_id, scan_result_id=result.pk)


@transaction.atomic
def _finish_or_defer_scans(claimed, stored_file):
    request = _locked_request(claimed)
    checks = list(stored_file.antivirus_checks.select_related("result"))
    pending = [check for check in checks if check.result_id is None]
    if pending:
        request.processing_due_at = min(
            min(check.next_check_at, check.created_at + timedelta(seconds=settings.ANTIVIRUS_MAX_WAIT_SECONDS))
            for check in pending
        )
        request.processing_token = None
        request.processing_attempts = 0
        request.last_queued_at = None
        request.save(update_fields=[
            "processing_due_at", "processing_token", "processing_attempts", "last_queued_at", "updated_at",
        ])
        return "retry_scheduled" if any(check.last_error for check in pending) else "scan_pending"

    results = [check.result for check in checks]
    verdicts = [result.verdict for result in results]
    if ScanResult.Verdict.MALICIOUS in verdicts:
        risk = Risk.CRITICAL
    elif ScanResult.Verdict.SUSPICIOUS in verdicts:
        risk = Risk.HIGH
    elif all(verdict == ScanResult.Verdict.CLEAN for verdict in verdicts):
        risk = Risk.LOW
    else:
        risk = Risk.UNKNOWN
    if ScanResult.Verdict.FAILED in verdicts:
        _finish(request, ScanStatus.SCAN_FAILED, risk=risk, message="Не все антивирусы завершили проверку.")
        _audit(request, "PROCESSING_FAILED", scan_result_ids=[result.pk for result in results])
        return "failed"
    _finish(request, ScanStatus.SCAN_COMPLETED, risk=risk)
    _audit(request, "SCAN_COMPLETED", scan_result_ids=[result.pk for result in results])
    return "review_ready"


def _record_failure(claimed, message="", *, retryable=False, download_failure=None):
    try:
        with transaction.atomic():
            request = _locked_request(claimed)
            if download_failure:
                source, exception = download_failure
                failure = DownloadService.record_failure(source, exception)
                message, retryable = failure.message, failure.retryable
            if retryable and request.processing_attempts < settings.PROCESS_MAX_ATTEMPTS:
                delay = 15 * 2 ** (request.processing_attempts - 1)
                request.processing_token = None
                request.last_queued_at = None
                request.processing_due_at = timezone.now() + timedelta(seconds=delay)
                request.processing_error = message[:512]
                request.scan_status = ScanStatus.PENDING
                request.save(update_fields=[
                    "processing_token", "last_queued_at", "processing_due_at",
                    "processing_error", "scan_status", "updated_at",
                ])
                _audit(request, "PROCESSING_RETRY_SCHEDULED", attempt=request.processing_attempts, delay=delay)
                return "retry_scheduled"

            _finish_failure(request, message)
            return "failed"
    except LeaseLost:
        return "skipped"


def _finish_failure(request, message):
    _finish(request, ScanStatus.SCAN_FAILED, message=message)
    _audit(request, "PROCESSING_FAILED", message=message[:512])


def _finish(request, status, *, risk=Risk.UNKNOWN, message=""):
    request.scan_status = status
    request.request_status = RequestStatus.WAITING_SECURITY_DECISION
    request.processing_due_at = None
    request.processing_token = None
    request.processing_error = message[:512]
    request.risk_level = risk
    request.save(update_fields=[
        "scan_status", "request_status", "processing_due_at", "processing_token",
        "processing_error", "risk_level", "updated_at",
    ])
    notify_request_owner(request, Notification.Event.REVIEW_READY)


def _audit(request, action, **details):
    AuditService.log(
        action=action, actor_type=AuditLog.ActorType.WORKER,
        object_type="SoftwareRequest", object_id=request.pk, details=details,
    )
