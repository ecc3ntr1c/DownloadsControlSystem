from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from django.db import transaction

from audit.models import AuditLog
from audit.services import AuditService
from files_app.downloaders import build_download_manager
from files_app.models import FileSource, StoredFile
from files_app.services.download_failures import DownloadFailureClassifier
from files_app.services.storage import FileStorageService
from files_app.services.stored_files import StoredFileService


class DownloadService:
    """Загрузка во временный каталог и регистрация файла в карантине."""

    @staticmethod
    @contextmanager
    def fetch(source):
        with FileStorageService().download_workspace() as directory:
            yield build_download_manager().download(source=source, destination_dir=Path(directory))

    @staticmethod
    @contextmanager
    def quarantine(result):
        storage = FileStorageService()
        path = storage.save_file(
            source_path=result.file_path,
            zone=StoredFile.StorageZone.QUARANTINE,
            extension=result.extension,
        )
        try:
            yield replace(result, file_path=path)
        except BaseException:
            storage.remove_quietly(path)
            raise

    @staticmethod
    def register(source, result):
        stored_file = StoredFileService.create_from_download_result(source=source, result=result)
        source.status = FileSource.SourceStatus.DOWNLOADED
        source.error_message = ""
        source.metadata.pop("download_error", None)
        source.save(update_fields=["status", "error_message", "metadata", "updated_at"])
        AuditService.log(
            actor_type=AuditLog.ActorType.WORKER,
            action="FILE_DOWNLOAD_COMPLETED",
            object_type="SoftwareRequest",
            object_id=source.request_id,
            details={
                "file_source_id": source.pk,
                "stored_file_id": stored_file.pk,
                "size": stored_file.size_bytes,
                "sha256": stored_file.file_hash_sha256,
                "mime_type": stored_file.mime_type,
            },
        )
        return stored_file

    @staticmethod
    def record_failure(source, exception):
        failure = DownloadFailureClassifier.classify(exception)
        source.status = FileSource.SourceStatus.FAILED
        source.error_message = failure.message
        source.metadata = {
            **source.metadata,
            "download_error": {"code": failure.code, "retryable": failure.retryable},
        }
        source.save(update_fields=["status", "error_message", "metadata", "updated_at"])
        AuditService.log(
            actor_type=AuditLog.ActorType.WORKER,
            action="FILE_DOWNLOAD_FAILED",
            object_type="SoftwareRequest",
            object_id=source.request_id,
            details={"file_source_id": source.pk, "error_code": failure.code},
        )
        return failure

    @staticmethod
    def download_source(*, source):
        try:
            with DownloadService.fetch(source) as result, DownloadService.quarantine(result) as quarantined:
                with transaction.atomic():
                    return DownloadService.register(source, quarantined)
        except Exception as exc:
            with transaction.atomic():
                DownloadService.record_failure(source, exc)
            raise
