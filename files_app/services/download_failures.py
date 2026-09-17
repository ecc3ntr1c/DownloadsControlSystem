from dataclasses import dataclass

from files_app.downloaders.exceptions import (
    AccessDeniedError,
    AuthenticationRequiredError,
    DownloadContentRejectedError,
    DownloadError,
    DownloadHttpStatusError,
    DownloadNetworkError,
    DownloadPolicyError,
    DownloadRedirectError,
    DownloadSizeExceededError,
    DownloadStorageError,
    InvalidDownloadUrlError,
    ProtectedDownloadError,
)


@dataclass(frozen=True)
class DownloadFailure:
    """
    Нормализованное описание ошибки скачивания.
    """

    code: str
    message: str
    retryable: bool


class DownloadFailureClassifier:
    """
    Преобразует технические исключения downloader'ов
    в стабильные коды ошибок системы.
    """

    @staticmethod
    def classify(
        exception: Exception,
    ) -> DownloadFailure:

        if isinstance(
            exception,
            ProtectedDownloadError,
        ):
            return DownloadFailure(
                code="PROTECTED_RULE_BLOCKED",
                message=(
                    "Источник запрещён "
                    "защищённым правилом"
                ),
                retryable=False,
            )

        if isinstance(
            exception,
            InvalidDownloadUrlError,
        ):
            return DownloadFailure(
                code="URL_REJECTED",
                message=str(exception),
                retryable=False,
            )

        if isinstance(
            exception,
            DownloadSizeExceededError,
        ):
            return DownloadFailure(
                code="FILE_TOO_LARGE",
                message=(
                    "Размер файла превышает "
                    "разрешённый лимит"
                ),
                retryable=False,
            )

        if isinstance(
            exception,
            DownloadContentRejectedError,
        ):
            return DownloadFailure(
                code="CONTENT_REJECTED",
                message=str(exception),
                retryable=False,
            )

        if isinstance(
            exception,
            AuthenticationRequiredError,
        ):
            return DownloadFailure(
                code="AUTHENTICATION_FAILED",
                message=str(exception),
                retryable=False,
            )

        if isinstance(
            exception,
            AccessDeniedError,
        ):
            return DownloadFailure(
                code="ACCESS_DENIED",
                message=(
                    "Удалённый сервер запретил доступ"
                ),
                retryable=False,
            )

        if isinstance(
            exception,
            DownloadRedirectError,
        ):
            return DownloadFailure(
                code="REDIRECT_ERROR",
                message=str(exception),
                retryable=False,
            )

        if isinstance(
            exception,
            DownloadHttpStatusError,
        ):
            return (
                DownloadFailureClassifier
                ._classify_http_status(
                    exception
                )
            )

        if isinstance(
            exception,
            DownloadNetworkError,
        ):
            return DownloadFailure(
                code="NETWORK_ERROR",
                message=(
                    "Сетевая ошибка при скачивании"
                ),
                retryable=True,
            )

        if isinstance(
            exception,
            DownloadStorageError,
        ):
            return DownloadFailure(
                code="STORAGE_ERROR",
                message=(
                    "Ошибка сохранения файла "
                    "в локальное хранилище"
                ),
                retryable=True,
            )

        if isinstance(
            exception,
            DownloadPolicyError,
        ):
            return DownloadFailure(
                code="POLICY_REJECTED",
                message=str(exception),
                retryable=False,
            )

        if isinstance(
            exception,
            DownloadError,
        ):
            return DownloadFailure(
                code="DOWNLOAD_ERROR",
                message="Ошибка скачивания файла",
                retryable=False,
            )

        # Неизвестная ошибка.
        #
        # Наружу не отдаём str(exception):
        # там потенциально могут оказаться URL,
        # credentials или внутренние данные.
        return DownloadFailure(
            code="INTERNAL_DOWNLOAD_ERROR",
            message=(
                "Внутренняя ошибка "
                "механизма скачивания"
            ),
            retryable=False,
        )

    @staticmethod
    def _classify_http_status(
        exception: DownloadHttpStatusError,
    ) -> DownloadFailure:

        status_code = exception.status_code

        if status_code == 429:
            return DownloadFailure(
                code="HTTP_RATE_LIMIT",
                message=(
                    "Удалённый сервер временно "
                    "ограничил количество запросов"
                ),
                retryable=True,
            )

        if 500 <= status_code <= 599:
            return DownloadFailure(
                code="HTTP_SERVER_ERROR",
                message=(
                    "Удалённый сервер временно "
                    "не может обработать запрос"
                ),
                retryable=True,
            )

        return DownloadFailure(
            code="HTTP_ERROR",
            message=(
                "Удалённый сервер вернул "
                f"HTTP {status_code}"
            ),
            retryable=False,
        )