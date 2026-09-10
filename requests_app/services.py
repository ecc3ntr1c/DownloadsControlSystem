from django.db import transaction
from django.utils import timezone

from urllib.parse import urlparse

from audit.models import AuditLog
from audit.services import AuditService

from files_app.models import FileSource

from .models import SoftwareRequest


class SoftwareRequestService:
    """
    Бизнес-логика работы с заявками.
    """

    @staticmethod
    def detect_source_type(url: str) -> str:
        """
        Предварительное определение типа источника.

        Пока простая логика:
        - disk.yandex.ru или yadi.sk считаем Яндекс.Диском;
        - остальные http/https считаем обычной ссылкой.
        """
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()

        if "disk.yandex.ru" in domain or "yadi.sk" in domain:
            return FileSource.SourceType.YANDEX_DISK

        if parsed_url.scheme in ("http", "https"):
            return FileSource.SourceType.HTTP

        return FileSource.SourceType.UNKNOWN

    @staticmethod
    def create_request(*, user, validated_data, request_meta=None) -> SoftwareRequest:
        software_request = SoftwareRequest.objects.create(
            user=user,
            source_url=validated_data["source_url"],
            description=validated_data["description"],
            business_reason=validated_data["business_reason"],
            external_system=validated_data.get("external_system", ""),
            external_request_id=validated_data.get("external_request_id", ""),
            request_status=SoftwareRequest.RequestStatus.UNDER_SECURITY_REVIEW,
            scan_status=SoftwareRequest.ScanStatus.PENDING,
        )

        parsed_url = urlparse(software_request.source_url)

        FileSource.objects.create(
            request=software_request,
            original_url=software_request.source_url,
            source_type=SoftwareRequestService.detect_source_type(
                software_request.source_url
            ),
            status=FileSource.SourceStatus.CREATED,
            domain=parsed_url.netloc.lower(),
        )

        AuditService.log(
            action="REQUEST_CREATED",
            actor=user,
            actor_type=AuditLog.ActorType.USER,
            object_type="SoftwareRequest",
            object_id=software_request.id,
            ip_address=(request_meta or {}).get("ip_address"),
            user_agent=(request_meta or {}).get("user_agent", ""),
            details={
                "source_url": software_request.source_url,
                "external_system": software_request.external_system,
                "external_request_id": software_request.external_request_id,
            },
        )

        from .tasks import process_software_request_task

        process_software_request_task.delay(software_request.id)

        return software_request


class ApprovalService:
    """
    Сервис решений ИБ по заявке.
    """

    @staticmethod
    def approve_request(
        *,
        software_request: SoftwareRequest,
        security_user,
        security_comment: str = "",
        request_meta: dict | None = None,
    ) -> SoftwareRequest:
        request_meta = request_meta or {}

        with transaction.atomic():
            software_request = SoftwareRequest.objects.select_for_update().get(
                id=software_request.id
            )

            if software_request.request_status in (
                SoftwareRequest.RequestStatus.APPROVED,
                SoftwareRequest.RequestStatus.REJECTED,
                SoftwareRequest.RequestStatus.CLOSED,
                SoftwareRequest.RequestStatus.DOWNLOADED,
            ):
                raise ValueError(
                    f"Заявку нельзя согласовать из статуса "
                    f"{software_request.request_status}"
                )

            software_request.request_status = SoftwareRequest.RequestStatus.APPROVED
            software_request.security_comment = security_comment
            software_request.save(
                update_fields=[
                    "request_status",
                    "security_comment",
                    "updated_at",
                ]
            )

            AuditService.log(
                action="REQUEST_APPROVED",
                actor=security_user,
                actor_type=AuditLog.ActorType.SECURITY,
                object_type="SoftwareRequest",
                object_id=software_request.id,
                ip_address=request_meta.get("ip_address"),
                user_agent=request_meta.get("user_agent", ""),
                details={
                    "security_comment": security_comment,
                },
            )

        return software_request

    @staticmethod
    def reject_request(
        *,
        software_request: SoftwareRequest,
        security_user,
        security_comment: str,
        request_meta: dict | None = None,
    ) -> SoftwareRequest:
        request_meta = request_meta or {}

        with transaction.atomic():
            software_request = SoftwareRequest.objects.select_for_update().get(
                id=software_request.id
            )

            if software_request.request_status in (
                SoftwareRequest.RequestStatus.DOWNLOADED,
                SoftwareRequest.RequestStatus.CLOSED,
            ):
                raise ValueError(
                    f"Заявку нельзя отклонить из статуса "
                    f"{software_request.request_status}"
                )

            software_request.request_status = SoftwareRequest.RequestStatus.REJECTED
            software_request.security_comment = security_comment
            software_request.closed_at = timezone.now()
            software_request.save(
                update_fields=[
                    "request_status",
                    "scan_status",
                    "security_comment",
                    "closed_at",
                    "updated_at",
                ]
            )

            AuditService.log(
                action="REQUEST_REJECTED",
                actor=security_user,
                actor_type=AuditLog.ActorType.SECURITY,
                object_type="SoftwareRequest",
                object_id=software_request.id,
                ip_address=request_meta.get("ip_address"),
                user_agent=request_meta.get("user_agent", ""),
                details={
                    "security_comment": security_comment,
                },
            )

        return software_request