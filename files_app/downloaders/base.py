from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from ..services.policies import DownloadPolicyConfig


@dataclass(frozen=True)
class DownloadResult:
    """
    Результат успешного скачивания файла.
    """

    file_path: Path

    original_url: str
    final_url: str

    filename: str
    extension: str

    size: int
    sha256: str

    mime_type: str | None
    declared_content_type: str | None


class BaseDownloader(ABC):
    """
    Базовый интерфейс всех downloader'ов.
    """

    @abstractmethod
    def download(
        self,
        *,
        url: str,
        destination_dir: Path,
        policy: DownloadPolicyConfig,
    ) -> DownloadResult:
        raise NotImplementedError