from pathlib import Path

from django.db import transaction

from files_app.downloaders.base import DownloadResult
from files_app.models import FileSource, StoredFile
from files_app.services.storage import FileStorageService


class StoredFileService:
    """
    Создание StoredFile на основании результата
    успешного скачивания.
    """

    @staticmethod
    @transaction.atomic
    def create_from_download_result(
        *,
        source: FileSource,
        result: DownloadResult,
    ) -> StoredFile:
        """
        Зарегистрировать успешно скачанный файл в БД.

        Файл на этом этапе находится в карантинной зоне
        и ещё не доступен пользователю.
        """

        StoredFileService._validate_result(
            result=result,
        )

        stored_file = StoredFile.objects.create(
            request=source.request,
            source=source,

            original_filename=result.filename,
            stored_filename=result.file_path.name,

            file_hash_sha256=result.sha256,

            mime_type=result.mime_type or "",
            extension=result.extension,

            size_bytes=result.size,

            storage_path=FileStorageService().relative_path(result.file_path),
            storage_zone=StoredFile.StorageZone.QUARANTINE,

            is_available=False,
        )

        StoredFileService._update_source(
            source=source,
            result=result,
        )

        return stored_file

    @staticmethod
    def _validate_result(
        *,
        result: DownloadResult,
    ) -> None:
        """
        Проверить, что DownloadResult соответствует
        реально существующему скачанному файлу.
        """

        file_path = Path(
            result.file_path
        )

        if not file_path.exists():
            raise ValueError(
                "Скачанный файл не существует"
            )

        if not file_path.is_file():
            raise ValueError(
                "Путь скачанного объекта "
                "не является файлом"
            )

        actual_size = file_path.stat().st_size

        if actual_size != result.size:
            raise ValueError(
                "Размер файла на диске "
                "не совпадает с DownloadResult"
            )

        if not result.sha256:
            raise ValueError(
                "DownloadResult не содержит SHA-256"
            )

        if len(result.sha256) != 64:
            raise ValueError(
                "Некорректная длина SHA-256"
            )

    @staticmethod
    def _update_source(
        *,
        source: FileSource,
        result: DownloadResult,
    ) -> None:
        """
        Сохранить фактические данные об источнике
        после успешного скачивания.
        """

        source.final_url = result.final_url

        metadata = dict(
            source.metadata or {}
        )

        metadata["download"] = {
            "declared_content_type": (
                result.declared_content_type
            ),
            "detected_mime_type": (
                result.mime_type
            ),
            "extension": result.extension,
            "size": result.size,
            "sha256": result.sha256,
        }

        source.metadata = metadata

        source.save(
            update_fields=[
                "final_url",
                "metadata",
                "updated_at",
            ]
        )
