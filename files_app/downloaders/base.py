from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DownloadResult:
    """
    Результат скачивания файла.
    """

    file_path: Path
    original_url: str
    final_url: str
    filename: str
    size: int
    sha256: str
    content_type: str | None


class BaseDownloader(ABC):
    """
    Базовый интерфейс загрузчика файлов.
    """

    @abstractmethod
    def download(
        self,
        url: str,
        destination_dir: Path,
    ) -> DownloadResult:
        """
        Скачать файл и вернуть информацию о нём.
        """
        raise NotImplementedError