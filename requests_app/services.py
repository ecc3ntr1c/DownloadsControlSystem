from datetime import timedelta

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.utils import timezone

from accounts.roles import APPROVE_SOFTWARE_REQUEST_PERMISSION, REJECT_SOFTWARE_REQUEST_PERMISSION
from audit.models import AuditLog
from audit.services import AuditService
from files_app.models import FileSource, StoredFile
from files_app.services.storage import FileStorageError, FileStorageService
from notifications.models import Notification
from notifications.services import notify_request_owner

from .models import SoftwareRequest
from .review import approval_blockers, can_reprocess, decision_ready, latest_scan
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
    @staticmethod
    def approve_request(*, software_request, security_user, security_comment="", request_meta=None):
        return ApprovalService._decide(
            software_request.pk, security_user, security_comment, request_meta, approve=True,
        )

    @staticmethod
    def reject_request(*, software_request, security_user, security_comment, request_meta=None):
        return ApprovalService._decide(
            software_request.pk, security_user, security_comment, request_meta, approve=False,
        )

    @staticmethod
    def _decide(request_id, security_user, comment, request_meta, *, approve):
        permission = APPROVE_SOFTWARE_REQUEST_PERMISSION if approve else REJECT_SOFTWARE_REQUEST_PERMISSION
        if not security_user.has_perm(permission):
            raise PermissionDenied
        comment = comment.strip()
        if len(comment) > 2000 or (not approve and not comment):
            raise ValueError("Укажите причину отказа. Максимальная длина комментария — 2000 символов.")

        storage = FileStorageService()
        copied_path = None
        try:
            with transaction.atomic(durable=True):
                request = SoftwareRequest.objects.select_for_update().get(pk=request_id)
                if not decision_ready(request):
                    raise ValueError("Решение доступно после автоматической обработки и принимается один раз.")

                stored_file = request.files.select_for_update().filter(pk=request.review_file_id).first()
                matches = list(request.prohibited_matches.select_related("rule"))
                now = timezone.now()
                if approve:
                    blockers = approval_blockers(request, stored_file, latest_scan(request), matches)
                    if blockers:
                        raise ValueError(" ".join(blockers))
                    if matches and not comment:
                        raise ValueError("Для исключения из реестра запрещённого ПО нужно указать обоснование.")

                if stored_file is not None and stored_file.storage_zone == StoredFile.StorageZone.QUARANTINE:
                    zone = StoredFile.StorageZone.APPROVED if approve else StoredFile.StorageZone.REJECTED
                    try:
                        copied_path = storage.copy_for_decision(stored_file, zone)
                    except FileStorageError:
                        if approve:
                            raise
                    if copied_path is not None:
                        source_path = storage.path_for(stored_file)
                        stored_file.storage_zone = zone
                        stored_file.storage_path = storage.relative_path(copied_path)
                        transaction.on_commit(lambda: storage.remove_quietly(source_path), robust=True)
                    stored_file.is_available = approve
                    retention = settings.APPROVED_RETENTION_DAYS if approve else settings.REJECTED_RETENTION_DAYS
                    stored_file.delete_after = now + timedelta(days=retention)
                    stored_file.save(update_fields=["storage_path", "storage_zone", "is_available", "delete_after"])

                if approve and matches:
                    request.prohibited_matches.update(
                        is_overridden=True, overridden_by=security_user, override_comment=comment, overridden_at=now,
                    )

                request.request_status = (
                    SoftwareRequest.RequestStatus.AVAILABLE_FOR_DOWNLOAD if approve
                    else SoftwareRequest.RequestStatus.REJECTED
                )
                request.decided_at = now
                request.decided_by = security_user
                request.security_comment = comment
                request.closed_at = None if approve else now
                request.save(update_fields=[
                    "request_status", "decided_at", "decided_by", "security_comment", "closed_at", "updated_at",
                ])
                _log_security_action(
                    request, security_user, request_meta, "REQUEST_APPROVED" if approve else "REQUEST_REJECTED",
                    stored_file_id=stored_file.pk if stored_file else None,
                    moved=copied_path is not None, overridden_rule_ids=[match.rule_id for match in matches] if approve else [],
                )
                notify_request_owner(request, Notification.Event.APPROVED if approve else Notification.Event.REJECTED)
        except BaseException:
            if copied_path is not None:
                storage.remove_quietly(copied_path)
            raise
        return request

    @staticmethod
    @transaction.atomic
    def reprocess_request(*, software_request, security_user, request_meta=None):
        from .tasks import publish_request

        if not security_user.has_perm(APPROVE_SOFTWARE_REQUEST_PERMISSION):
            raise PermissionDenied
        request = SoftwareRequest.objects.select_for_update().get(pk=software_request.pk)
        if not can_reprocess(request):
            raise ValueError("Повторная обработка доступна для заявок с ошибкой или без подтверждённой проверки.")
        request.review_file = None
        request.request_status = SoftwareRequest.RequestStatus.UNDER_SECURITY_REVIEW
        request.scan_status = SoftwareRequest.ScanStatus.PENDING
        request.risk_level = SoftwareRequest.RiskLevel.UNKNOWN
        request.processing_attempts = 0
        request.processing_error = ""
        request.processing_due_at = timezone.now()
        request.processing_token = None
        request.last_queued_at = None
        request.save(update_fields=[
            "review_file", "request_status", "scan_status", "risk_level", "processing_attempts",
            "processing_error", "processing_due_at", "processing_token", "last_queued_at", "updated_at",
        ])
        _log_security_action(request, security_user, request_meta, "REQUEST_REPROCESSING")
        transaction.on_commit(lambda: publish_request(request.pk), robust=True)
        return request


def _log_security_action(request, user, request_meta, action, **details):
    request_meta = request_meta or {}
    AuditService.log(
        action=action, actor=user, actor_type=AuditLog.ActorType.SECURITY,
        object_type="SoftwareRequest", object_id=request.pk, details=details,
        ip_address=request_meta.get("ip_address"), user_agent=request_meta.get("user_agent", ""),
    )
