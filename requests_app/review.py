from django.utils import timezone

from files_app.models import StoredFile
from files_app.services.review_policies import file_type_blockers, prevents_release
from scanning.models import ScanResult

from .models import SoftwareRequest

RequestStatus = SoftwareRequest.RequestStatus
ScanStatus = SoftwareRequest.ScanStatus


def decision_ready(request):
    return (
        request.request_status == RequestStatus.WAITING_SECURITY_DECISION
        and request.scan_status in (ScanStatus.SCAN_COMPLETED, ScanStatus.SCAN_FAILED)
        and request.decided_at is None
    )


def latest_scan(request):
    return request.scan_results.order_by("-pk").first()


def scan_reports(request):
    checks = list(request.review_file.antivirus_checks.select_related("provider", "result")) if request.review_file_id else []
    if checks:
        return [{
            "name": check.provider_name,
            "provider": check.provider.kind,
            "status": "finished" if check.result_id else "waiting_report" if check.remote_id else "pending",
            "last_error": check.last_error,
            "result": check.result,
        } for check in checks]
    result = latest_scan(request)
    if result is None:
        return []
    return [{
        "name": result.get_provider_display(), "provider": result.provider, "status": "finished",
        "last_error": "", "result": result,
    }]


def approval_blockers(request, stored_file, scan, matches):
    if not decision_ready(request):
        return ["Решение доступно после автоматической обработки заявки."]
    if request.scan_status != ScanStatus.SCAN_COMPLETED:
        return ["Автоматическая обработка не завершилась успешной проверкой."]
    if (
        stored_file is None or stored_file.request_id != request.pk
        or stored_file.storage_zone != StoredFile.StorageZone.QUARANTINE
        or stored_file.deleted_at is not None or stored_file.is_available
    ):
        return ["В карантине нет проверенного файла этой заявки."]
    if stored_file.delete_after is None or stored_file.delete_after <= timezone.now():
        return ["Истёк срок хранения файла в карантине."]
    checks = list(stored_file.antivirus_checks.select_related("provider", "result"))
    if checks:
        blocking_providers = [
            check.provider_name for check in checks
            if not _clean_result(check.result, stored_file, check.provider.kind)
        ]
        if blocking_providers:
            names = ", ".join(blocking_providers)
            return [f"Для выдачи нужны чистые отчёты всех назначенных антивирусов. Требуется: {names}."]
    elif not _clean_result(scan, stored_file, ScanResult.Provider.CLAMAV):
        return ["Для выдачи нужен подтверждённый чистый отчёт для этого файла."]
    if any(prevents_release(match.rule) for match in matches):
        return ["Запрещающее правило не допускает исключения."]
    return file_type_blockers(stored_file)


def _clean_result(result, stored_file, provider):
    return (
        result is not None and result.request_id == stored_file.request_id
        and result.file_id == stored_file.pk and result.provider == provider
        and result.verdict == ScanResult.Verdict.CLEAN and bool(result.file_sha256)
        and result.file_sha256 == stored_file.file_hash_sha256
    )


def can_reprocess(request):
    if (
        request.decided_at is not None or request.processing_due_at is not None
        or request.request_status not in (
            RequestStatus.CREATED, RequestStatus.UNDER_SECURITY_REVIEW,
            RequestStatus.WAITING_SECURITY_DECISION, RequestStatus.PROHIBITED_SOFTWARE_REVIEW,
            RequestStatus.APPROVED,
        )
    ):
        return False
    return (
        request.scan_status == ScanStatus.SCAN_FAILED
        or request.review_file_id is None
        or request.review_file.storage_zone == StoredFile.StorageZone.DELETED
    )
