from pathlib import Path

from ..models import FileSource
from ..services.policies import DownloadPolicyService
from .base import BaseDownloader, DownloadResult
from .exceptions import UnsupportedSourceError


class DownloadManager:
    """
    Выбирает подходящий downloader по типу FileSource
    и запускает скачивание с текущей активной политикой.
    """

    def __init__(self) -> None:
        self._downloaders: dict[str, BaseDownloader] = {}

    def register_downloader(
        self,
        source_type: str,
        downloader: BaseDownloader,
    ) -> None:
        """
        Зарегистрировать downloader для типа источника.
        """

        if not source_type:
            raise ValueError(
                "source_type не может быть пустым"
            )

        self._downloaders[source_type] = downloader

    def download(
        self,
        *,
        source: FileSource,
        destination_dir: Path,
    ) -> DownloadResult:
        """
        Скачать файл из FileSource.

        Менеджер:
        1. получает активную глобальную политику;
        2. выбирает downloader;
        3. передаёт ему конкретный URL;
        4. возвращает DownloadResult.
        """

        policy = (
            DownloadPolicyService
            .get_active_policy()
        )

        downloader = self._get_downloader(
            source_type=source.source_type,
        )

        return downloader.download(
            url=source.original_url,
            destination_dir=destination_dir,
            policy=policy,
        )

    def _get_downloader(
        self,
        *,
        source_type: str,
    ) -> BaseDownloader:
        """
        Получить зарегистрированный downloader.
        """

        downloader = self._downloaders.get(
            source_type
        )

        if downloader is None:
            raise UnsupportedSourceError(
                "Downloader для типа источника "
                f"{source_type!r} не зарегистрирован"
            )

        return downloader