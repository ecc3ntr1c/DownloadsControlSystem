import hashlib
import ipaddress
import re
import socket
import uuid
from pathlib import Path
from urllib.parse import unquote, urljoin, urlparse

import httpx

from .base import BaseDownloader, DownloadResult
from .exceptions import (
    DownloadError,
    DownloadTimeoutError,
    FileTooLargeError,
    InvalidSourceURLError,
)


class HttpDownloader(BaseDownloader):
    """
    Загрузка файлов по HTTP/HTTPS.
    """

    CHUNK_SIZE = 1024 * 1024
    MAX_REDIRECTS = 5
    MAX_FILE_SIZE = 500 * 1024 * 1024

    def download(
        self,
        url: str,
        destination_dir: Path,
    ) -> DownloadResult:
        self._validate_url(url)

        destination_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        current_url = url

        for _ in range(self.MAX_REDIRECTS + 1):
            self._validate_url(current_url)

            try:
                with httpx.Client(
                    follow_redirects=False,
                    timeout=httpx.Timeout(
                        connect=10.0,
                        read=60.0,
                        write=30.0,
                        pool=10.0,
                    ),
                    trust_env=False,
                ) as client:
                    response = client.get(
                        current_url,
                        follow_redirects=False,
                    )

            except httpx.TimeoutException as exc:
                raise DownloadTimeoutError(
                    f"Таймаут при скачивании {current_url}"
                ) from exc

            except httpx.HTTPError as exc:
                raise DownloadError(
                    f"Ошибка HTTP при скачивании {current_url}: {exc}"
                ) from exc

            if response.is_redirect:
                location = response.headers.get("Location")

                if not location:
                    raise DownloadError(
                        "Сервер вернул redirect без Location."
                    )

                current_url = urljoin(
                    current_url,
                    location,
                )

                continue

            response.raise_for_status()

            return self._save_response(
                response=response,
                original_url=url,
                final_url=current_url,
                destination_dir=destination_dir,
            )

        raise DownloadError(
            f"Превышено максимальное количество redirect: "
            f"{self.MAX_REDIRECTS}"
        )

    def _save_response(
        self,
        *,
        response: httpx.Response,
        original_url: str,
        final_url: str,
        destination_dir: Path,
    ) -> DownloadResult:
        content_length = response.headers.get("Content-Length")

        if content_length:
            try:
                content_length = int(content_length)
            except ValueError:
                content_length = None

        if (
            content_length is not None
            and content_length > self.MAX_FILE_SIZE
        ):
            raise FileTooLargeError(
                f"Файл слишком большой: {content_length} bytes"
            )

        filename = self._get_filename(
            final_url,
            response.headers.get("Content-Disposition"),
        )

        temp_filename = f"{uuid.uuid4().hex}.part"
        file_path = destination_dir / temp_filename

        sha256 = hashlib.sha256()
        total_size = 0

        try:
            with file_path.open("wb") as file:
                for chunk in response.iter_bytes(
                    chunk_size=self.CHUNK_SIZE
                ):
                    total_size += len(chunk)

                    if total_size > self.MAX_FILE_SIZE:
                        raise FileTooLargeError(
                            f"Файл превышает лимит "
                            f"{self.MAX_FILE_SIZE} bytes"
                        )

                    sha256.update(chunk)
                    file.write(chunk)

        except Exception:
            file_path.unlink(missing_ok=True)
            raise

        return DownloadResult(
            file_path=file_path,
            original_url=original_url,
            final_url=final_url,
            filename=filename,
            size=total_size,
            sha256=sha256.hexdigest(),
            content_type=response.headers.get("Content-Type"),
        )

    @staticmethod
    def _get_filename(
        url: str,
        content_disposition: str | None,
    ) -> str:
        if content_disposition:
            match = re.search(
                r'filename="?([^";]+)"?',
                content_disposition,
                flags=re.IGNORECASE,
            )

            if match:
                filename = match.group(1).strip()

                if filename:
                    return Path(filename).name

        parsed = urlparse(url)
        filename = Path(
            unquote(parsed.path)
        ).name

        if filename:
            return filename

        return "download.bin"

    @staticmethod
    def _validate_url(url: str) -> None:
        parsed = urlparse(url)

        if parsed.scheme not in {"http", "https"}:
            raise InvalidSourceURLError(
                "Разрешены только HTTP и HTTPS URL."
            )

        if not parsed.hostname:
            raise InvalidSourceURLError(
                "URL не содержит hostname."
            )

        if parsed.username or parsed.password:
            raise InvalidSourceURLError(
                "URL с username/password запрещён."
            )

        try:
            addresses = {
                info[4][0]
                for info in socket.getaddrinfo(
                    parsed.hostname,
                    parsed.port or (
                        443 if parsed.scheme == "https" else 80
                    ),
                    type=socket.SOCK_STREAM,
                )
            }
        except socket.gaierror as exc:
            raise InvalidSourceURLError(
                f"Не удалось разрешить hostname: {parsed.hostname}"
            ) from exc

        for address in addresses:
            ip = ipaddress.ip_address(address)

            if not ip.is_global:
                raise InvalidSourceURLError(
                    f"Доступ к адресу {address} запрещён."
                )