from pathlib import Path

from celery import shared_task
from django.conf import settings

from audit.models import AuditLog
from audit.services import AuditService
from requests_app.models import SoftwareRequest

from .models import FileSource
from .services.download_failures import (
    DownloadFailureClassifier,
)
from .services.downloads import DownloadService


@shared_task(
    bind=True,
    name="files.download_file_source",
    queue="downloads",
    max_retries=3,
    acks_late=True,
    reject_on_worker_lost=True,
)
def download_file_source(
    self,
    source_id: int,
) -> dict[str, object]:
    """
    Скачать один FileSource.

    Задача:
    - работает по ID, а не по сериализованной Django-модели;
    - не скачивает файл повторно, если StoredFile уже существует;
    - запускает реальный DownloadService;
    - фиксирует статусы FileSource и SoftwareRequest;
    - повторяет только временные ошибки;
    - пишет события retry в аудит.
    """

    try:
        source = (
            FileSource.objects
            .select_related("request")
            .get(pk=source_id)
        )
    except FileSource.DoesNotExist:
        # Источник мог быть удалён до того,
        # как Celery дошёл до задачи.
        return {
            "status": "source_not_found",
            "file_source_id": source_id,
        }

    # --------------------------------------------------
    # 1. Идемпотентность
    # --------------------------------------------------

    existing_file = (
        source.stored_files
        .order_by("-created_at")
        .first()
    )

    if existing_file is not None:
        _mark_download_completed(
            source=source,
        )

        return {
            "status": "already_downloaded",
            "file_source_id": source.id,
            "stored_file_id": existing_file.id,
            "sha256": (
                existing_file.file_hash_sha256
            ),
            "size": (
                existing_file.size_bytes
            ),
        }

    # Celery считает retries начиная с 0.
    # Поэтому первый запуск задачи = attempt 1.
    attempt = self.request.retries + 1

    # --------------------------------------------------
    # 2. Начало попытки скачивания
    # --------------------------------------------------

    _mark_download_started(
        source=source,
    )

    AuditService.log(
        actor=None,
        actor_type=AuditLog.ActorType.WORKER,
        action="FILE_DOWNLOAD_STARTED",
        object_type="SoftwareRequest",
        object_id=str(source.request_id),
        details={
            "file_source_id": source.id,
            "source_type": source.source_type,
            "attempt": attempt,
        },
    )

    # --------------------------------------------------
    # 3. Реальное скачивание
    # --------------------------------------------------

    try:
        stored_file = (
            DownloadService.download_source(
                source=source,
                destination_dir=Path(
                    settings.DOWNLOAD_QUARANTINE_DIR
                ),
            )
        )

    except Exception as exc:
        failure = (
            DownloadFailureClassifier
            .classify(exc)
        )

        # Любая неуспешная попытка скачивания:
        #
        # FileSource -> FAILED
        # SoftwareRequest.scan_status -> SCAN_FAILED
        #
        # Если ошибка временная и будет retry,
        # следующая попытка снова переведёт их
        # в DOWNLOAD_STARTED / DOWNLOADING.
        _mark_download_failed(
            source=source,
        )

        # --------------------------------------------------
        # 4. Повтор временной ошибки
        # --------------------------------------------------

        if (
            failure.retryable
            and self.request.retries
            < self.max_retries
        ):
            countdown = _get_retry_delay(
                retries=self.request.retries,
            )

            AuditService.log(
                actor=None,
                actor_type=(
                    AuditLog.ActorType.WORKER
                ),
                action=(
                    "FILE_DOWNLOAD_RETRY_SCHEDULED"
                ),
                object_type="SoftwareRequest",
                object_id=str(
                    source.request_id
                ),
                details={
                    "file_source_id": source.id,
                    "error_code": failure.code,
                    "attempt": attempt,
                    "retry_in_seconds": countdown,
                },
            )

            raise self.retry(
                exc=exc,
                countdown=countdown,
            )

        # Ошибка окончательная.
        #
        # DownloadService уже записал
        # FILE_DOWNLOAD_FAILED и error_message.
        raise

    # --------------------------------------------------
    # 5. Успешное завершение
    # --------------------------------------------------

    _mark_download_completed(
        source=source,
    )

    return {
        "status": "downloaded",
        "file_source_id": source.id,
        "stored_file_id": stored_file.id,
        "sha256": (
            stored_file.file_hash_sha256
        ),
        "size": stored_file.size_bytes,
    }


def _mark_download_started(
    *,
    source: FileSource,
) -> None:
    """
    Начать новую попытку скачивания.

    При retry предыдущая ошибка FileSource
    очищается, потому что начинается новая попытка.
    """

    source.status = (
        FileSource.SourceStatus.DOWNLOAD_STARTED
    )

    source.error_message = ""

    source.save(
        update_fields=[
            "status",
            "error_message",
            "updated_at",
        ]
    )

    SoftwareRequest.objects.filter(
        pk=source.request_id,
    ).update(
        scan_status=(
            SoftwareRequest.ScanStatus.DOWNLOADING
        )
    )


def _mark_download_completed(
    *,
    source: FileSource,
) -> None:
    """
    Зафиксировать успешное скачивание.
    """

    FileSource.objects.filter(
        pk=source.pk,
    ).update(
        status=(
            FileSource.SourceStatus.DOWNLOADED
        ),
        error_message="",
    )

    SoftwareRequest.objects.filter(
        pk=source.request_id,
    ).update(
        scan_status=(
            SoftwareRequest.ScanStatus.DOWNLOADED
        )
    )


def _mark_download_failed(
    *,
    source: FileSource,
) -> None:
    """
    Зафиксировать неуспешную попытку скачивания.

    Подробная причина ошибки и metadata
    записываются DownloadService.

    Здесь фиксируем состояния бизнес-pipeline.
    """

    FileSource.objects.filter(
        pk=source.pk,
    ).update(
        status=(
            FileSource.SourceStatus.FAILED
        )
    )

    SoftwareRequest.objects.filter(
        pk=source.request_id,
    ).update(
        scan_status=(
            SoftwareRequest.ScanStatus.SCAN_FAILED
        )
    )


def _get_retry_delay(
    *,
    retries: int,
) -> int:
    """
    Exponential backoff.

    После первой ошибки:
        60 секунд

    После второй:
        120 секунд

    После третьей:
        240 секунд

    Максимум:
        15 минут
    """

    return min(
        60 * (2 ** retries),
        15 * 60,
    )