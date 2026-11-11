import logging
import shutil
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from audit.services import AuditService
from files_app.models import StoredFile
from files_app.services.delivery import ISSUED_STATES
from files_app.services.storage import FileStorageError, FileStorageService
from notifications.models import Notification
from notifications.services import notify_request_owner
from requests_app.models import SoftwareRequest

logger = logging.getLogger(__name__)
ACTIVE_ZONES = (StoredFile.StorageZone.QUARANTINE, StoredFile.StorageZone.APPROVED, StoredFile.StorageZone.REJECTED)


def cleanup_expired_files():
    now = timezone.now()
    expired = (
        StoredFile.objects.filter(delete_after__lte=now, storage_zone__in=ACTIVE_ZONES)
        .order_by("delete_after", "pk").values_list("request_id", "pk")
    )
    removed = 0
    for request_id, file_id in expired.iterator(chunk_size=100):
        try:
            removed += _expire_file(request_id, file_id, now)
        except (FileStorageError, OSError):
            logger.warning("Не удалось удалить просроченный файл %s", file_id)
        if removed >= 100:
            break
    return removed


@transaction.atomic
def _expire_file(request_id, file_id, now):
    request = SoftwareRequest.objects.select_for_update().filter(pk=request_id).first()
    if request is None:
        return 0
    if (
        request.review_file_id == file_id and request.processing_token is not None
        and request.processing_due_at is not None and request.processing_due_at > now
    ):
        return 0
    stored_file = (
        request.files.select_for_update().filter(pk=file_id, delete_after__lte=now, storage_zone__in=ACTIVE_ZONES).first()
    )
    if stored_file is None:
        return 0

    storage = FileStorageService()
    storage.path_for(stored_file).unlink(missing_ok=True)
    # После сбоя процесса может остаться копия, записанная до фиксации решения в БД.
    if not StoredFile.objects.filter(stored_filename=stored_file.stored_filename).exclude(pk=file_id).exists():
        for zone in ACTIVE_ZONES:
            if zone != stored_file.storage_zone:
                storage.zone_path(zone, stored_file.stored_filename).unlink(missing_ok=True)

    stored_file.storage_zone = StoredFile.StorageZone.DELETED
    stored_file.is_available = False
    stored_file.deleted_at = now
    stored_file.save(update_fields=["storage_zone", "is_available", "deleted_at"])
    if request.review_file_id == file_id and request.request_status in ISSUED_STATES:
        request.request_status = SoftwareRequest.RequestStatus.CLOSED
        request.closed_at = now
        request.save(update_fields=["request_status", "closed_at", "updated_at"])
        notify_request_owner(request, Notification.Event.EXPIRED)
    AuditService.log(
        action="FILE_EXPIRED", object_type="SoftwareRequest", object_id=request.pk,
        details={"stored_file_id": stored_file.pk},
    )
    return 1


def cleanup_stale_workspaces():
    storage = FileStorageService()
    storage.ensure_structure()
    cutoff = (timezone.now() - timedelta(days=1)).timestamp()
    for path in storage.staging_dir.glob("job-*"):
        try:
            if not path.is_symlink() and path.is_dir() and path.stat().st_mtime < cutoff:
                shutil.rmtree(path)
        except FileNotFoundError:
            continue
        except OSError:
            logger.warning("Не удалось удалить устаревший временный каталог.")
    for zone in ACTIVE_ZONES:
        for path in storage.stale_unregistered_files(zone, cutoff):
            if not StoredFile.objects.filter(stored_filename=path.name).exists():
                storage.remove_quietly(path)
        for path in storage.get_zone_dir(zone).glob(".storage-*.part"):
            try:
                if path.lstat().st_mtime < cutoff:
                    path.unlink(missing_ok=True)
            except FileNotFoundError:
                continue
            except OSError:
                logger.warning("Не удалось удалить незавершённую копию файла.")
