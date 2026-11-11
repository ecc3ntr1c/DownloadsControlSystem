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
    if (
        scan is None or scan.file_id != stored_file.pk or scan.provider != ScanResult.Provider.CLAMAV
        or scan.verdict != ScanResult.Verdict.CLEAN or not scan.file_sha256
        or scan.file_sha256 != stored_file.file_hash_sha256
    ):
        return ["Для выдачи нужен вердикт «Чистый» от ClamAV для этого файла."]
    if any(prevents_release(match.rule) for match in matches):
        return ["Запрещающее правило не допускает исключения."]
    return file_type_blockers(stored_file)


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
