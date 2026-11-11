from django.db import transaction
from django.http import Http404
from django.urls import reverse
from django.utils import timezone

from audit.models import AuditLog
from audit.services import AuditService
from files_app.models import StoredFile
from files_app.services.storage import FileStorageError, FileStorageService
from requests_app.models import SoftwareRequest

ISSUED_STATES = (SoftwareRequest.RequestStatus.AVAILABLE_FOR_DOWNLOAD, SoftwareRequest.RequestStatus.DOWNLOADED)


def can_download(request, stored_file):
    return (
        request.request_status in ISSUED_STATES and request.decided_at is not None
        and stored_file is not None and stored_file.request_id == request.pk
        and request.review_file_id == stored_file.pk
        and stored_file.is_available and stored_file.storage_zone == StoredFile.StorageZone.APPROVED
        and stored_file.deleted_at is None and stored_file.delete_after is not None
        and stored_file.delete_after > timezone.now()
    )


def download_link(request, user):
    if user is not None and user.pk == request.user_id and can_download(request, request.review_file):
        return reverse("approved-file-download", args=[request.review_file_id])
    return None


def authorize_download(file_id, user, *, record, request_meta):
    """Проверить владельца и доступность перед каждым скачиванием."""
    content = None
    try:
        with transaction.atomic():
            request = SoftwareRequest.objects.select_for_update().filter(
                review_file_id=file_id, user=user,
            ).first()
            if request is None:
                raise Http404
            stored_file = request.files.select_for_update().filter(pk=file_id).first()
            if not can_download(request, stored_file):
                raise Http404
            content = FileStorageService().open_file(stored_file)
            if record:
                stored_file.download_count += 1
                stored_file.save(update_fields=["download_count"])
                if request.request_status != SoftwareRequest.RequestStatus.DOWNLOADED:
                    request.request_status = SoftwareRequest.RequestStatus.DOWNLOADED
                    request.save(update_fields=["request_status", "updated_at"])
                AuditService.log(
                    action="FILE_DOWNLOAD_AUTHORIZED", actor=user, actor_type=AuditLog.ActorType.USER,
                    object_type="SoftwareRequest", object_id=request.pk,
                    details={"stored_file_id": stored_file.pk},
                    ip_address=request_meta.get("ip_address"), user_agent=request_meta.get("user_agent", ""),
                )
    except BaseException as exc:
        if content is not None:
            content.close()
        if isinstance(exc, FileStorageError):
            raise Http404 from exc
        raise
    return stored_file, content
