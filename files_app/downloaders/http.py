import hashlib
import ipaddress
import os
import re
import tempfile
import time
import unicodedata
import uuid
import magic
from email.message import Message
from pathlib import Path
from urllib.parse import unquote, urljoin, urlparse, urlunparse

import httpx

from ..services.policies import DownloadPolicyConfig
from ..validators.url_validator import (
    DownloadUrlValidator,
    ValidatedUrl,
)
from .base import BaseDownloader, DownloadResult
from .exceptions import (
    AccessDeniedError,
    AuthenticationRequiredError,
    DownloadContentRejectedError,
    DownloadError,
    DownloadHttpStatusError,
    DownloadNetworkError,
    DownloadRedirectError,
    DownloadSizeExceededError,
    DownloadStorageError,
)


class _PinnedHostResolver:
    """
    Хранит соответствие hostname -> IP для текущего скачивания.

    Нужен для того, чтобы HTTP-клиент подключался именно
    к тому IP, который уже был проверен DownloadUrlValidator.
    """

    def __init__(self) -> None:
        self._mapping: dict[str, str] = {}

    @staticmethod
    def _normalize_host(host: str) -> str:
        return host.lower().rstrip(".")

    def pin(
        self,
        *,
        host: str,
        address: str,
    ) -> None:
        self._mapping[
            self._normalize_host(host)
        ] = address

    def resolve(
        self,
        host: str,
    ) -> str | None:
        return self._mapping.get(
            self._normalize_host(host)
        )


class _PinnedDnsTransport(httpx.HTTPTransport):
    """
    HTTPTransport, который подменяет DNS resolution
    на заранее проверенный IP.

    При HTTPS сохраняется исходный hostname для TLS SNI
    и проверки сертификата.
    """

    def __init__(
        self,
        *,
        resolver: _PinnedHostResolver,
    ) -> None:
        self._resolver = resolver

        super().__init__(
            retries=0,
            trust_env=False,
            limits=httpx.Limits(max_keepalive_connections=0),
        )

    def handle_request(
        self,
        request: httpx.Request,
    ) -> httpx.Response:

        original_host = request.url.host

        address = self._resolver.resolve(
            original_host
        )

        if address is None:
            raise DownloadNetworkError(
                "Попытка подключения к непроверенному hostname"
            )

        if request.url.scheme == "https":
            request.extensions["sni_hostname"] = (
                original_host
            )

        request.url = request.url.copy_with(
            host=address
        )

        return super().handle_request(
            request
        )


class HttpDownloader(BaseDownloader):
    """
    Downloader для HTTP/HTTPS ресурсов.

    Выполняет:
    - проверку каждого URL;
    - ручную обработку redirects;
    - подключение только к проверенным IP;
    - streaming;
    - контроль размера;
    - SHA-256;
    - безопасное сохранение файла.
    """

    REDIRECT_STATUSES = frozenset(
        {
            301,
            302,
            303,
            307,
            308,
        }
    )

    HTML_CONTENT_TYPES = frozenset(
        {
            "text/html",
            "application/xhtml+xml",
        }
    )

    CHUNK_SIZE = 1024 * 1024

    MAX_FILENAME_LENGTH = 180
    MAX_DOWNLOAD_SECONDS = 480

    USER_AGENT = "DownloadsControl/1.0"

    DEFAULT_TIMEOUT = httpx.Timeout(
        connect=10.0,
        read=60.0,
        write=30.0,
        pool=10.0,
    )

    WINDOWS_RESERVED_NAMES = frozenset(
        {
            "CON",
            "PRN",
            "AUX",
            "NUL",
            "COM1",
            "COM2",
            "COM3",
            "COM4",
            "COM5",
            "COM6",
            "COM7",
            "COM8",
            "COM9",
            "LPT1",
            "LPT2",
            "LPT3",
            "LPT4",
            "LPT5",
            "LPT6",
            "LPT7",
            "LPT8",
            "LPT9",
        }
    )

    def __init__(
        self,
        url_validator: DownloadUrlValidator,
        *,
        timeout: httpx.Timeout | None = None,
        chunk_size: int = CHUNK_SIZE,
    ) -> None:

        if chunk_size <= 0:
            raise ValueError(
                "chunk_size должен быть больше нуля"
            )

        self.url_validator = url_validator
        self.timeout = (
            timeout
            if timeout is not None
            else self.DEFAULT_TIMEOUT
        )
        self.chunk_size = chunk_size

    def download(
        self,
        *,
        url: str,
        destination_dir: Path,
        policy: DownloadPolicyConfig,
    ) -> DownloadResult:
        """
        Скачать HTTP/HTTPS ресурс.

        Каждый URL, включая redirect Location,
        заново проходит DownloadUrlValidator.
        """

        self._validate_runtime_policy(
            policy=policy
        )

        destination_dir = (
            self._prepare_destination_dir(
                destination_dir
            )
        )

        resolver = _PinnedHostResolver()

        transport = _PinnedDnsTransport(
            resolver=resolver
        )

        try:
            with httpx.Client(
                transport=transport,
                timeout=self.timeout,
                follow_redirects=False,
                trust_env=False,
                headers={
                    "User-Agent": self.USER_AGENT,
                    "Accept": "*/*",
                    "Accept-Encoding": "identity",
                },
            ) as client:

                return self._download_with_client(
                    client=client,
                    resolver=resolver,
                    url=url,
                    destination_dir=destination_dir,
                    policy=policy,
                )

        except DownloadError:
            raise

        except httpx.TimeoutException as exc:
            raise DownloadNetworkError(
                "Превышено время ожидания при скачивании"
            ) from exc

        except httpx.TransportError as exc:
            raise DownloadNetworkError(
                "Сетевая ошибка при скачивании файла"
            ) from exc

    def _download_with_client(
            self,
            *,
            client: httpx.Client,
            resolver: _PinnedHostResolver,
            url: str,
            destination_dir: Path,
            policy: DownloadPolicyConfig,
    ) -> DownloadResult:

        original_url = url
        current_url = url

        redirect_count = 0
        deadline = time.monotonic() + self.MAX_DOWNLOAD_SECONDS

        while True:
            self._check_deadline(deadline)
            validated_url = (
                self.url_validator.validate(
                    url=current_url,
                    policy=policy,
                )
            )

            response = self._send_request(
                client=client,
                resolver=resolver,
                validated_url=validated_url,
            )

            try:
                if (
                        response.status_code
                        in self.REDIRECT_STATUSES
                ):
                    if (
                            redirect_count
                            >= policy.max_redirects
                    ):
                        raise DownloadRedirectError(
                            "Превышено максимально "
                            "разрешённое количество redirects"
                        )

                    location = response.headers.get(
                        "location"
                    )

                    if not location:
                        raise DownloadRedirectError(
                            "Сервер вернул redirect "
                            "без заголовка Location"
                        )

                    current_url = urljoin(
                        current_url,
                        location.strip(),
                    )
                    try:
                        parsed_location = urlparse(current_url)
                    except ValueError as exc:
                        raise DownloadRedirectError("Некорректный адрес перенаправления.") from exc
                    if parsed_location.username is not None or parsed_location.password is not None:
                        raise DownloadRedirectError("Перенаправление содержит учётные данные.")

                    redirect_count += 1

                    continue

                self._validate_http_status(
                    response=response,
                    validated_url=validated_url,
                    policy=policy,
                )

                (
                    file_path,
                    filename,
                    extension,
                    size,
                    sha256,
                    mime_type,
                    declared_content_type,
                ) = self._save_response(
                    response=response,
                    validated_url=validated_url,
                    destination_dir=destination_dir,
                    policy=policy,
                    deadline=deadline,
                )

                return DownloadResult(
                    file_path=file_path,
                    original_url=self._redact_url(
                        original_url
                    ),
                    final_url=self._redact_url(
                        current_url
                    ),
                    filename=filename,
                    extension=extension,
                    size=size,
                    sha256=sha256,
                    mime_type=mime_type,
                    declared_content_type=(
                        declared_content_type
                    ),
                )

            finally:
                response.close()

    def _send_request(
        self,
        *,
        client: httpx.Client,
        resolver: _PinnedHostResolver,
        validated_url: ValidatedUrl,
    ) -> httpx.Response:
        """
        Выполняет запрос только к одному из IP,
        которые уже прошли проверку validator'ом.

        Если один IP недоступен, пробует следующий.
        """

        request_url = self._build_request_url(
            validated_url
        )

        auth = self._build_auth(
            validated_url
        )

        last_error: httpx.TransportError | None = (
            None
        )

        for address in (
            validated_url.resolved_addresses
        ):
            resolver.pin(
                host=validated_url.hostname,
                address=address,
            )

            request = client.build_request(
                method="GET",
                url=request_url,
            )

            try:
                if auth is None:
                    return client.send(
                        request,
                        stream=True,
                        follow_redirects=False,
                    )

                return client.send(
                    request,
                    stream=True,
                    follow_redirects=False,
                    auth=auth,
                )

            except httpx.TransportError as exc:
                last_error = exc

        raise DownloadNetworkError(
            "Не удалось установить соединение "
            "ни с одним разрешённым IP-адресом"
        ) from last_error

    @staticmethod
    def _build_auth(
        validated_url: ValidatedUrl,
    ) -> httpx.BasicAuth | None:

        if not validated_url.has_credentials:
            return None

        username = unquote(
            validated_url.parsed.username or ""
        )

        password = unquote(
            validated_url.parsed.password or ""
        )

        return httpx.BasicAuth(
            username=username,
            password=password,
        )

    @staticmethod
    def _build_request_url(
        validated_url: ValidatedUrl,
    ) -> str:
        """
        Удаляет username/password из URL перед
        передачей URL в HTTPX.

        Credentials передаются отдельно через BasicAuth,
        поэтому они не попадают в сетевые исключения
        и внутренние URL HTTPX.
        """

        parsed = validated_url.parsed

        hostname = validated_url.hostname

        try:
            address = ipaddress.ip_address(
                hostname
            )
        except ValueError:
            address = None

        if (
            address is not None
            and address.version == 6
        ):
            host_part = f"[{hostname}]"
        else:
            host_part = hostname

        explicit_port = parsed.port

        if explicit_port is not None:
            netloc = (
                f"{host_part}:{explicit_port}"
            )
        else:
            netloc = host_part

        clean_parsed = parsed._replace(
            scheme=parsed.scheme.lower(),
            netloc=netloc,
            fragment="",
        )

        return urlunparse(
            clean_parsed
        )

    @staticmethod
    def _validate_http_status(
        *,
        response: httpx.Response,
        validated_url: ValidatedUrl,
        policy: DownloadPolicyConfig,
    ) -> None:

        status_code = response.status_code

        if status_code == 401:
            if validated_url.has_credentials:
                raise AuthenticationRequiredError(
                    "Удалённый сервер отклонил "
                    "переданные учётные данные"
                )

            if policy.reject_auth_required:
                raise AuthenticationRequiredError(
                    "Источник требует аутентификацию, "
                    "что запрещено политикой"
                )

            raise AuthenticationRequiredError(
                "Источник требует аутентификацию"
            )

        if status_code == 403:
            raise AccessDeniedError(
                "Удалённый сервер запретил доступ"
            )

        if status_code == 206:
            raise DownloadHttpStatusError(
                "Сервер вернул частичный ответ 206 "
                "без запроса Range",
                status_code=status_code,
            )

        if status_code in {204, 205}:
            raise DownloadHttpStatusError(
                f"Сервер вернул HTTP {status_code} "
                "без содержимого файла",
                status_code=status_code,
            )

        if not 200 <= status_code < 300:
            raise DownloadHttpStatusError(
                "Сервер вернул неподходящий "
                f"HTTP status: {status_code}",
                status_code=status_code,
            )


    def _save_response(
            self,
            *,
            response: httpx.Response,
            validated_url: ValidatedUrl,
            destination_dir: Path,
            policy: DownloadPolicyConfig,
            deadline: float,
    ) -> tuple[
        Path,
        str,
        str,
        int,
        str,
        str | None,
        str | None,
    ]:
        """
        Потоково сохранить HTTP response.

        Возвращает:
        - file_path;
        - filename;
        - extension;
        - size;
        - sha256;
        - фактический mime_type;
        - declared_content_type от HTTP-сервера.
        """

        expected_size = self._validate_content_length(
            response=response,
            policy=policy,
        )
        if response.headers.get("content-encoding", "identity").strip().lower() != "identity":
            raise DownloadContentRejectedError("Сервер прислал файл с кодированием HTTP.")

        # Тип, заявленный HTTP-сервером.
        declared_content_type = (
            self._get_content_type(
                response=response,
            )
        )

        self._validate_content_type(
            content_type=declared_content_type,
            policy=policy,
        )

        filename = self._extract_filename(
            response=response,
            validated_url=validated_url,
        )

        # Шаг 140:
        # расширение определяем из исходного имени.
        extension = self._detect_extension(
            filename=filename,
        )

        final_path = self._build_final_path(
            destination_dir=destination_dir,
            filename=filename,
        )

        sha256 = hashlib.sha256()

        total_size = 0
        first_payload_checked = False

        temp_path: Path | None = None

        try:
            with tempfile.NamedTemporaryFile(
                    mode="wb",
                    prefix=".download-",
                    suffix=".part",
                    dir=destination_dir,
                    delete=False,
            ) as output_file:

                temp_path = Path(
                    output_file.name
                )

                try:
                    for chunk in response.iter_bytes(
                            chunk_size=self.chunk_size
                    ):
                        self._check_deadline(deadline)
                        if not chunk:
                            continue

                        if (
                                policy.reject_html_pages
                                and not first_payload_checked
                        ):
                            first_payload_checked = True

                            if self._looks_like_html(
                                    chunk
                            ):
                                raise (
                                    DownloadContentRejectedError(
                                        "Полученный ресурс "
                                        "похож на HTML-страницу"
                                    )
                                )

                        next_size = (
                                total_size
                                + len(chunk)
                        )

                        if (
                                next_size
                                > policy.max_file_size_bytes
                        ):
                            raise (
                                DownloadSizeExceededError(
                                    "Размер файла превышает "
                                    "разрешённый лимит"
                                )
                            )

                        output_file.write(
                            chunk
                        )

                        sha256.update(
                            chunk
                        )

                        total_size = next_size

                    if not total_size or (expected_size is not None and total_size != expected_size):
                        raise DownloadContentRejectedError("Файл пуст или получен не полностью.")
                    output_file.flush()

                    os.fsync(
                        output_file.fileno()
                    )

                except httpx.TransportError as exc:
                    raise DownloadNetworkError(
                        "Соединение было прервано "
                        "во время скачивания файла"
                    ) from exc

            # К этому моменту временный файл полностью
            # записан и уже закрыт.

            # Шаг 139:
            # определяем реальный MIME по содержимому.
            mime_type = self._detect_mime_type(
                file_path=temp_path,
            )
            self._validate_content_type(content_type=mime_type, policy=policy)

            try:
                os.replace(
                    temp_path,
                    final_path,
                )
            except OSError as exc:
                raise DownloadStorageError(
                    "Не удалось переместить "
                    "загруженный файл в хранилище"
                ) from exc

            temp_path = None

            return (
                final_path,
                filename,
                extension,
                total_size,
                sha256.hexdigest(),
                mime_type,
                declared_content_type,
            )

        except DownloadError:
            raise

        except OSError as exc:
            raise DownloadStorageError(
                "Ошибка записи файла в хранилище"
            ) from exc

        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink(
                        missing_ok=True
                    )
                except OSError:
                    pass


    @staticmethod
    def _check_deadline(deadline: float) -> None:
        if time.monotonic() >= deadline:
            raise DownloadNetworkError("Превышено общее время скачивания.")

    @staticmethod
    def _validate_content_length(
        *,
        response: httpx.Response,
        policy: DownloadPolicyConfig,
    ) -> int | None:

        raw_content_length = (
            response.headers.get(
                "content-length"
            )
        )

        if raw_content_length is None:
            return None

        try:
            content_length = int(
                raw_content_length
            )
        except ValueError as exc:
            raise DownloadHttpStatusError(
                "Сервер вернул некорректный Content-Length",
                status_code=response.status_code,
            ) from exc

        if content_length < 0:
            raise DownloadHttpStatusError(
                "Сервер вернул отрицательный Content-Length",
                status_code=response.status_code,
            )

        if (
            content_length
            > policy.max_file_size_bytes
        ):
            raise DownloadSizeExceededError(
                "Размер файла согласно Content-Length превышает разрешённый лимит"
            )
        return content_length

    @classmethod
    def _validate_content_type(
        cls,
        *,
        content_type: str | None,
        policy: DownloadPolicyConfig,
    ) -> None:

        if not policy.reject_html_pages:
            return

        if (
            content_type
            in cls.HTML_CONTENT_TYPES
        ):
            raise DownloadContentRejectedError(
                "Политика запрещает скачивание HTML-страниц"
            )

    @staticmethod
    def _get_content_type(
        *,
        response: httpx.Response,
    ) -> str | None:

        raw_content_type = (
            response.headers.get(
                "content-type"
            )
        )

        if not raw_content_type:
            return None

        content_type = (
            raw_content_type
            .split(";", 1)[0]
            .strip()
            .lower()
        )

        return (
            content_type
            if content_type
            else None
        )

    @staticmethod
    def _looks_like_html(
        chunk: bytes,
    ) -> bool:

        sample = chunk[:4096].lstrip()

        if sample.startswith(
            b"\xef\xbb\xbf"
        ):
            sample = sample[3:].lstrip()

        sample = sample.lower()

        return (
            sample.startswith(
                b"<!doctype html"
            )
            or sample.startswith(
                b"<html"
            )
            or sample.startswith(
                b"<head"
            )
            or sample.startswith(
                b"<body"
            )
        )

    def _extract_filename(
        self,
        *,
        response: httpx.Response,
        validated_url: ValidatedUrl,
    ) -> str:

        filename: str | None = None

        content_disposition = (
            response.headers.get(
                "content-disposition"
            )
        )

        if content_disposition:
            try:
                message = Message()

                message[
                    "Content-Disposition"
                ] = content_disposition

                filename = (
                    message.get_filename()
                )
            except (ValueError, TypeError):
                filename = None

        if not filename:
            path = unquote(
                validated_url.parsed.path
            )

            filename = Path(
                path.replace("\\", "/")
            ).name

        if not filename:
            filename = "download.bin"

        return self._sanitize_filename(
            filename
        )

    def _sanitize_filename(
        self,
        filename: str,
    ) -> str:
        """
        Удаляет path traversal и символы,
        опасные для файловой системы.
        """

        filename = unicodedata.normalize(
            "NFKC",
            filename,
        )

        filename = filename.replace(
            "\\",
            "/",
        )

        filename = Path(
            filename
        ).name

        filename = re.sub(
            r'[\x00-\x1f\x7f<>:"/\\|?*]',
            "_",
            filename,
        )

        filename = filename.strip(
            " ."
        )

        if not filename:
            filename = "download.bin"

        stem = Path(filename).stem

        if (
            stem.upper()
            in self.WINDOWS_RESERVED_NAMES
        ):
            filename = f"_{filename}"

        if (
            len(filename)
            > self.MAX_FILENAME_LENGTH
        ):
            suffix = Path(
                filename
            ).suffix

            max_stem_length = (
                self.MAX_FILENAME_LENGTH
                - len(suffix)
            )

            stem = Path(
                filename
            ).stem[:max_stem_length]

            filename = (
                f"{stem}{suffix}"
            )

        return filename

    @staticmethod
    def _build_final_path(
        *,
        destination_dir: Path,
        filename: str,
    ) -> Path:
        """
        Генерирует внутреннее уникальное имя файла.

        Пользовательское имя никогда напрямую
        не используется как storage path.
        """

        suffix = Path(
            filename
        ).suffix.lower()

        if not re.fullmatch(
            r"\.[a-z0-9]{1,12}",
            suffix,
        ):
            suffix = ""

        for _ in range(10):
            stored_filename = (
                f"{uuid.uuid4().hex}"
                f"{suffix}"
            )

            candidate = (
                destination_dir
                / stored_filename
            )

            if not candidate.exists():
                return candidate

        raise DownloadStorageError(
            "Не удалось создать уникальное "
            "имя файла в хранилище"
        )

    @staticmethod
    def _prepare_destination_dir(
        destination_dir: Path,
    ) -> Path:

        try:
            destination_dir = (
                Path(destination_dir)
                .expanduser()
            )

            destination_dir.mkdir(
                parents=True,
                exist_ok=True,
            )

            destination_dir = (
                destination_dir.resolve(
                    strict=True
                )
            )

        except OSError as exc:
            raise DownloadStorageError(
                "Не удалось подготовить "
                "директорию для скачивания"
            ) from exc

        if not destination_dir.is_dir():
            raise DownloadStorageError(
                "Путь назначения не является "
                "директорией"
            )

        return destination_dir

    @staticmethod
    def _validate_runtime_policy(
        *,
        policy: DownloadPolicyConfig,
    ) -> None:

        if (
            policy.max_file_size_bytes
            <= 0
        ):
            raise DownloadStorageError(
                "В политике указан некорректный "
                "максимальный размер файла"
            )

        if policy.max_redirects < 0:
            raise DownloadRedirectError(
                "В политике указано некорректное "
                "максимальное количество redirects"
            )

    @staticmethod
    def _redact_url(
        url: str,
    ) -> str:
        """
        Удаляет реальные username/password
        из URL перед передачей результата дальше.
        """

        try:
            parsed = urlparse(
                url
            )

            hostname = (
                parsed.hostname or ""
            )

            try:
                address = (
                    ipaddress.ip_address(
                        hostname
                    )
                )
            except ValueError:
                address = None

            if (
                address is not None
                and address.version == 6
            ):
                host_part = (
                    f"[{hostname}]"
                )
            else:
                host_part = hostname

            try:
                port = parsed.port
            except ValueError:
                port = None

            if port is not None:
                host_part = (
                    f"{host_part}:{port}"
                )

            if (
                parsed.username is not None
                or parsed.password is not None
            ):
                netloc = (
                    f"***:***@{host_part}"
                )
            else:
                netloc = host_part

            redacted = parsed._replace(
                netloc=netloc,
                fragment="",
                query="",
            )

            return urlunparse(
                redacted
            )

        except (TypeError, ValueError):
            return "<invalid-url>"

    @staticmethod
    def _detect_mime_type(
            *,
            file_path: Path,
    ) -> str | None:
        """
        Определить фактический MIME-type файла
        по его содержимому через libmagic.
        """

        try:
            mime_type = magic.from_file(
                str(file_path),
                mime=True,
            )
        except (OSError, magic.MagicException):
            return None

        if not mime_type:
            return None

        mime_type = mime_type.strip().lower()

        return mime_type or None

    @staticmethod
    def _detect_extension(
            *,
            filename: str,
    ) -> str:
        """
        Получить расширение из исходного имени файла.

        Расширение возвращается без точки:
        setup.exe -> exe
        file.PDF -> pdf
        README -> ""
        """

        suffix = Path(
            filename
        ).suffix.lower()

        if not suffix:
            return ""

        extension = suffix.lstrip(".")

        if not re.fullmatch(
                r"[a-z0-9]{1,12}",
                extension,
        ):
            return ""

        return extension
