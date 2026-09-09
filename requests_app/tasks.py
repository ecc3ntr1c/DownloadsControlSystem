import time

from celery import shared_task
from django.db import transaction

from audit.models import AuditLog
from audit.services import AuditService
from files_app.models import FileSource
from scanning.models import ScanResult

from .models import SoftwareRequest


@shared_task
def process_software_request_task(request_id: int) -> None:
    """
    Первая версия фоновой обработки заявки.

    Пока это имитация:
    1. проверка URL;
    2. скачивание;
    3. антивирусная проверка;
    4. сохранение mock-результата.

    Позже здесь появятся реальные:
    - URL validator;
    - DownloadManager;
    - FileStorageService;
    - AntivirusManager.
    """

    try:
        software_request = SoftwareRequest.objects.get(id=request_id)
    except SoftwareRequest.DoesNotExist:
        return

    file_source = software_request.file_sources.first()

    if software_request.request_status == SoftwareRequest.RequestStatus.REJECTED:
        software_request.scan_status = SoftwareRequest.ScanStatus.CANCELLED
        software_request.save(update_fields=["scan_status", "updated_at"])
        return

    software_request.scan_status = SoftwareRequest.ScanStatus.URL_VALIDATION
    software_request.save(update_fields=["scan_status", "updated_at"])

    if file_source:
        file_source.status = FileSource.SourceStatus.VALIDATING
        file_source.save(update_fields=["status", "updated_at"])

    AuditService.log(
        action="URL_VALIDATION_STARTED",
        actor_type=AuditLog.ActorType.WORKER,
        object_type="SoftwareRequest",
        object_id=software_request.id,
        details={"source_url": software_request.source_url},
    )

    time.sleep(2)

    if software_request.request_status == SoftwareRequest.RequestStatus.REJECTED:
        software_request.scan_status = SoftwareRequest.ScanStatus.CANCELLED
        software_request.save(update_fields=["scan_status", "updated_at"])
        return

    if file_source:
        file_source.status = FileSource.SourceStatus.VALID
        file_source.save(update_fields=["status", "updated_at"])

    software_request.scan_status = SoftwareRequest.ScanStatus.DOWNLOADING
    software_request.save(update_fields=["scan_status", "updated_at"])

    if file_source:
        file_source.status = FileSource.SourceStatus.DOWNLOAD_STARTED
        file_source.save(update_fields=["status", "updated_at"])

    AuditService.log(
        action="FILE_DOWNLOAD_STARTED",
        actor_type=AuditLog.ActorType.WORKER,
        object_type="SoftwareRequest",
        object_id=software_request.id,
        details={
            "source_type": file_source.source_type if file_source else "UNKNOWN",
        },
    )

    time.sleep(2)

    if software_request.request_status == SoftwareRequest.RequestStatus.REJECTED:
        software_request.scan_status = SoftwareRequest.ScanStatus.CANCELLED
        software_request.save(update_fields=["scan_status", "updated_at"])
        return

    if file_source:
        file_source.status = FileSource.SourceStatus.DOWNLOADED
        file_source.save(update_fields=["status", "updated_at"])

    software_request.scan_status = SoftwareRequest.ScanStatus.SCANNING
    software_request.save(update_fields=["scan_status", "updated_at"])

    AuditService.log(
        action="SCAN_STARTED",
        actor_type=AuditLog.ActorType.WORKER,
        object_type="SoftwareRequest",
        object_id=software_request.id,
        details={"provider": "MOCK"},
    )

    time.sleep(2)

    with transaction.atomic():
        software_request = SoftwareRequest.objects.select_for_update().get(
            id=request_id
        )

        if software_request.request_status == SoftwareRequest.RequestStatus.REJECTED:
            software_request.scan_status = (
                SoftwareRequest.ScanStatus.COMPLETED_AFTER_REJECTION
            )
            software_request.save(update_fields=["scan_status", "updated_at"])

            AuditService.log(
                action="SCAN_COMPLETED_AFTER_REJECTION",
                actor_type=AuditLog.ActorType.WORKER,
                object_type="SoftwareRequest",
                object_id=software_request.id,
            )
            return

        ScanResult.objects.create(
            request=software_request,
            provider=ScanResult.Provider.MOCK,
            verdict=ScanResult.Verdict.CLEAN,
            risk_score=0,
            risk_level=SoftwareRequest.RiskLevel.LOW,
            raw_result={
                "message": "Mock scan completed successfully",
            },
            normalized_result={
                "verdict": "CLEAN",
                "risk_score": 0,
                "risk_level": "LOW",
                "recommendation": "manual_review_required",
            },
        )

        software_request.scan_status = SoftwareRequest.ScanStatus.SCAN_COMPLETED
        software_request.request_status = (
            SoftwareRequest.RequestStatus.WAITING_SECURITY_DECISION
        )
        software_request.risk_level = SoftwareRequest.RiskLevel.LOW
        software_request.save(
            update_fields=[
                "scan_status",
                "request_status",
                "risk_level",
                "updated_at",
            ]
        )

    AuditService.log(
        action="SCAN_COMPLETED",
        actor_type=AuditLog.ActorType.WORKER,
        object_type="SoftwareRequest",
        object_id=software_request.id,
        details={
            "provider": "MOCK",
            "verdict": "CLEAN",
            "risk_level": "LOW",
        },
    )