from pathlib import Path

from django.db import transaction

from audit.models import AuditLog
from audit.services import AuditService

from files_app.downloaders import (
    build_download_manager,
)
from files_app.models import FileSource, StoredFile
from files_app.services.download_failures import (
    DownloadFailure,
    DownloadFailureClassifier,
)
from files_app.services.stored_files import (
    StoredFileService,
)


class DownloadService:
    """
    Высокоуровневый сервис скачивания файла.
    """

    @staticmethod
    def download_source(
        *,
        source: FileSource,
        destination_dir: Path,
    ) -> StoredFile:

        manager = build_download_manager()

        try:
            # Сетевую операцию выполняем
            # вне DB-транзакции.
            result = manager.download(
                source=source,
                destination_dir=destination_dir,
            )

        except Exception as exc:
            DownloadService._handle_failure(
                source=source,
                exception=exc,
            )

            raise

        try:
            with transaction.atomic():

                stored_file = (
                    StoredFileService
                    .create_from_download_result(
                        source=source,
                        result=result,
                    )
                )

                AuditService.log(
                    actor=None,
                    actor_type=(
                        AuditLog.ActorType.WORKER
                    ),
                    action=(
                        "FILE_DOWNLOAD_COMPLETED"
                    ),
                    object_type=(
                        "SoftwareRequest"
                    ),
                    object_id=str(
                        source.request_id
                    ),
                    details={
                        "file_source_id": source.id,
                        "stored_file_id": stored_file.id,
                        "source_type": source.source_type,
                        "original_filename": stored_file.original_filename,
                        "stored_filename": stored_file.stored_filename,
                        "final_url": result.final_url,
                        "size": stored_file.size_bytes,
                        "sha256": stored_file.file_hash_sha256,
                        "mime_type": stored_file.mime_type,
                        "declared_content_type": (
                            result.declared_content_type
                        ),
                        "extension": stored_file.extension,
                    },
                )

        except Exception as exc:
            # Файл уже физически скачан,
            # но не удалось зарегистрировать его
            # в системе.
            DownloadService._cleanup_file(
                result.file_path
            )

            DownloadService._handle_failure(
                source=source,
                exception=exc,
            )

            raise

        return stored_file

    @staticmethod
    def _handle_failure(
        *,
        source: FileSource,
        exception: Exception,
    ) -> None:

        failure = (
            DownloadFailureClassifier
            .classify(
                exception
            )
        )

        with transaction.atomic():

            DownloadService._mark_source_failed(
                source=source,
                failure=failure,
            )

            DownloadService._write_failure_audit(
                source=source,
                failure=failure,
                exception=exception,
            )

    @staticmethod
    def _mark_source_failed(
            *,
            source: FileSource,
            failure: DownloadFailure,
    ) -> None:

        source.status = FileSource.SourceStatus.FAILED
        source.error_message = failure.message

        metadata = dict(
            source.metadata or {}
        )

        metadata["download_error"] = {
            "code": failure.code,
            "message": failure.message,
            "retryable": failure.retryable,
        }

        source.metadata = metadata

        source.save(
            update_fields=[
                "status",
                "error_message",
                "metadata",
                "updated_at",
            ]
        )

    @staticmethod
    def _write_failure_audit(
        *,
        source: FileSource,
        failure: DownloadFailure,
        exception: Exception,
    ) -> None:

        details = {
            "file_source_id": source.id,
            "source_type": source.source_type,
            "error_code": failure.code,
            "message": failure.message,
            "retryable": failure.retryable,
            "exception_type": (
                exception.__class__.__name__
            ),
        }

        AuditService.log(
            actor=None,
            actor_type=(
                AuditLog.ActorType.WORKER
            ),
            action="FILE_DOWNLOAD_FAILED",
            object_type="SoftwareRequest",
            object_id=str(
                source.request_id
            ),
            details=details,
        )

    @staticmethod
    def _cleanup_file(
        file_path: Path,
    ) -> None:

        try:
            Path(file_path).unlink(
                missing_ok=True
            )
        except OSError:
            pass