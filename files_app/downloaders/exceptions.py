class DownloadError(Exception):
    """
    Базовая ошибка механизма скачивания.
    """


class DownloadPolicyError(DownloadError):
    """
    Операция запрещена политикой скачивания.
    """


class UnsupportedSourceError(DownloadError):
    """
    Для типа источника не зарегистрирован downloader.
    """


class InvalidDownloadUrlError(DownloadPolicyError):
    """
    URL некорректен или запрещён политикой.
    """


class ProtectedDownloadError(DownloadPolicyError):
    """
    URL запрещён ProtectedDownloadRule.
    """


class DownloadSizeExceededError(DownloadError):
    """
    Размер файла превышает установленный лимит.
    """


class DownloadRedirectError(DownloadError):
    """
    Ошибка обработки HTTP redirect.
    """


class DownloadNetworkError(DownloadError):
    """
    Ошибка сетевого взаимодействия.
    """


class AuthenticationRequiredError(DownloadError):
    """
    Источник требует аутентификацию.
    """


class AccessDeniedError(DownloadError):
    """
    Удалённый сервер запретил доступ.
    """


class DownloadHttpStatusError(DownloadError):
    """
    Удалённый сервер вернул неподходящий HTTP status.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code


class DownloadContentRejectedError(DownloadPolicyError):
    """
    Полученный контент запрещён политикой.
    """


class DownloadStorageError(DownloadError):
    """
    Ошибка локального сохранения файла.
    """