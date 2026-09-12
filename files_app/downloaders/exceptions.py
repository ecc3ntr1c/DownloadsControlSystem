class DownloadError(Exception):
    """Базовая ошибка скачивания файла."""


class UnsupportedSourceError(DownloadError):
    """Источник не поддерживается."""


class InvalidSourceURLError(DownloadError):
    """Некорректный или небезопасный URL."""


class FileTooLargeError(DownloadError):
    """Размер файла превышает установленный лимит."""


class DownloadTimeoutError(DownloadError):
    """Истекло время ожидания скачивания."""