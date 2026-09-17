from ..models import FileSource
from ..validators.url_validator import (
    DownloadUrlValidator,
)
from .http import HttpDownloader
from .manager import DownloadManager
from .protected_rules import (
    ProtectedDownloadRuleService,
)


def build_download_manager() -> DownloadManager:
    """
    Собрать полностью настроенный DownloadManager
    со всеми поддерживаемыми downloader'ами.
    """

    protected_rule_service = (
        ProtectedDownloadRuleService()
    )

    url_validator = DownloadUrlValidator(
        protected_rule_service=(
            protected_rule_service
        ),
    )

    http_downloader = HttpDownloader(
        url_validator=url_validator,
    )

    manager = DownloadManager()

    manager.register_downloader(
        source_type=FileSource.SourceType.HTTP,
        downloader=http_downloader,
    )

    return manager