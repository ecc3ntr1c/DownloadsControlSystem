from django.db import transaction
from django.utils import timezone

from audit.models import AuditLog
from audit.services import AuditService
from files_app.models import FileSource

from .models import SoftwareRequest
from .source_urls import parse_source_url


class SoftwareRequestService:
    @staticmethod
    def detect_source_type(url):
        try:
            hostname = parse_source_url(url).hostname.rstrip(".")
        except ValueError:
            return FileSource.SourceType.UNKNOWN
        if hostname in {"disk.yandex.ru", "yadi.sk"}:
            return FileSource.SourceType.YANDEX_DISK
        return FileSource.SourceType.HTTP

    @staticmethod
    @transaction.atomic
    def create_request(*, user, validated_data, request_meta=None):
        from .tasks import publish_request

        parsed = parse_source_url(validated_data["source_url"])
        url = parsed._replace(fragment="").geturl()
        software_request = SoftwareRequest.objects.create(
            user=user,
            source_url=url,
            description=validated_data["description"],
            business_reason=validated_data["business_reason"],
            external_system=validated_data.get("external_system", ""),
            external_request_id=validated_data.get("external_request_id", ""),
            request_status=SoftwareRequest.RequestStatus.UNDER_SECURITY_REVIEW,
            processing_due_at=timezone.now(),
        )
        source = FileSource.objects.create(
            request=software_request, original_url=url, domain=parsed.hostname[:255],
            source_type=SoftwareRequestService.detect_source_type(url),
        )
        AuditService.log(
            action="REQUEST_CREATED", actor=user, actor_type=AuditLog.ActorType.USER,
            object_type="SoftwareRequest", object_id=software_request.pk,
            ip_address=(request_meta or {}).get("ip_address"),
            user_agent=(request_meta or {}).get("user_agent", ""),
            details={"source_domain": source.domain, "file_source_id": source.pk},
        )
        transaction.on_commit(lambda: publish_request(software_request.pk), robust=True)
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