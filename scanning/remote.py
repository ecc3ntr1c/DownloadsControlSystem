import hashlib
import json
import re
from contextlib import contextmanager
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from urllib.parse import quote, urlsplit

import httpx
from django.conf import settings

from files_app.services.storage import FileStorageError, FileStorageService

from .contracts import ScanOutcome, ScannerError
from .credentials import decrypt_api_key
from .models import AntivirusProvider, ScanResult

MAX_REPORT_BYTES = 1024 * 1024
REMOTE_ID = re.compile(r"[A-Za-z0-9_+=.-]{1,255}")
VERDICT = ScanResult.Verdict


def gateway_endpoint(value):
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment or parsed.port == 0
            or any(char.isspace() or char == "\\" for char in value)
        ):
            raise ValueError
    except ValueError as exc:
        raise ScannerError("Укажи HTTPS-адрес шлюза без логина, пароля и параметров.") from exc
    return value.rstrip("/")


def _object(value):
    if not isinstance(value, dict):
        raise ScannerError("Антивирус вернул ответ в неожиданном формате.")
    return value


def _id(value):
    if not isinstance(value, str) or not REMOTE_ID.fullmatch(value) or value in {".", ".."}:
        raise ScannerError("Антивирус не вернул корректный идентификатор проверки.")
    return value


def _retry_delay(value):
    if value:
        try:
            seconds = int(value)
        except ValueError:
            try:
                date = parsedate_to_datetime(value)
                seconds = int((date - datetime.now(UTC)).total_seconds())
            except (ValueError, TypeError, OverflowError):
                return 60
        return max(15, min(seconds, settings.ANTIVIRUS_MAX_WAIT_SECONDS))
    return 60


def _client():
    return httpx.Client(
        timeout=httpx.Timeout(60, connect=5, read=40),
        follow_redirects=False, trust_env=False,
    )


def _request(method, url, headers, **kwargs):
    try:
        with _client() as client, client.stream(
            method, url, headers={**headers, "Accept": "application/json", "Accept-Encoding": "identity"}, **kwargs,
        ) as response:
            status = response.status_code
            if status == 429:
                raise ScannerError(
                    "Антивирус временно ограничил частоту запросов.",
                    retryable=True, retry_after=_retry_delay(response.headers.get("Retry-After")),
                )
            if status in {401, 403}:
                raise ScannerError("Антивирус отказал в доступе. Проверь ключ API и его права.")
            if not 200 <= status < 300:
                raise ScannerError(
                    f"Сервис проверки вернул HTTP {status}.",
                    retryable=method == "GET" and (status == 404 or status >= 500),
                )
            if response.headers.get("content-encoding", "identity").lower() != "identity":
                raise ScannerError("Сервис проверки вернул отчёт в неподдерживаемом кодировании.")
            body = bytearray()
            for chunk in response.iter_raw():
                if len(body) + len(chunk) > MAX_REPORT_BYTES:
                    raise ScannerError("Ответ антивируса слишком большой.")
                body.extend(chunk)
    except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
        raise ScannerError("Не удалось подключиться к антивирусу.", retryable=True) from exc
    except (httpx.RequestError, httpx.InvalidURL) as exc:
        message = (
            "Загрузка не подтверждена. Проверь историю у провайдера перед повторной отправкой."
            if method == "POST" else "Не удалось получить ответ антивируса."
        )
        raise ScannerError(message, retryable=method == "GET") from exc
    try:
        return _object(json.loads(body))
    except (ValueError, RecursionError) as exc:
        raise ScannerError("Антивирус вернул некорректный JSON.") from exc


@contextmanager
def _verified_file(stored_file):
    """Сверить хеш и отправлять байты через тот же открытый дескриптор."""
    try:
        with FileStorageService().open_file(stored_file) as content:
            digest = hashlib.file_digest(content, "sha256").hexdigest()
            if digest != stored_file.file_hash_sha256:
                raise ScannerError("Содержимое файла изменилось после загрузки.")
            content.seek(0)
            # Не передаём исходное имя или данные заявки.
            extension = stored_file.extension
            suffix = f".{extension}" if re.fullmatch(r"[a-z0-9]{1,12}", extension) else ".bin"
            yield (digest + suffix, content, "application/octet-stream")
    except (OSError, FileStorageError) as exc:
        raise ScannerError("Не удалось прочитать файл из карантина.") from exc


class VirusTotalScanner:
    API = "https://www.virustotal.com/api/v3"
    UPLOAD_HOSTS = {"www.virustotal.com", "virustotal.com", "upload.virustotal.com"}
    DIRECT_UPLOAD_LIMIT = 32_000_000

    def __init__(self, provider):
        if not provider.allow_public_uploads:
            raise ScannerError("Отправка файлов в общий набор данных VirusTotal не разрешена.")
        key = decrypt_api_key(provider.encrypted_api_key)
        if not key:
            raise ScannerError("В админке не задан API-ключ VirusTotal.")
        self.headers = {"x-apikey": key}

    def submit(self, stored_file):
        with _verified_file(stored_file) as payload:
            url = f"{self.API}/files"
            if stored_file.size_bytes > self.DIRECT_UPLOAD_LIMIT:
                response = _request("GET", f"{self.API}/files/upload_url", self.headers)
                url = self._upload_url(response.get("data"))
            response = _request("POST", url, self.headers, files={"file": payload})
        return _id(_object(response.get("data")).get("id"))

    @classmethod
    def _upload_url(cls, value):
        if not isinstance(value, str):
            raise ScannerError("VirusTotal не вернул адрес для загрузки большого файла.")
        try:
            parsed = urlsplit(value)
            if (
                parsed.scheme not in {"http", "https"} or parsed.hostname not in cls.UPLOAD_HOSTS
                or parsed.username is not None or parsed.password is not None
                or parsed.fragment or parsed.port not in {None, 80 if parsed.scheme == "http" else 443}
                or not parsed.path
            ):
                raise ValueError
        except ValueError as exc:
            raise ScannerError("VirusTotal вернул неподдерживаемый адрес загрузки.") from exc
        # В документации встречается HTTP-адрес. Данные и ключ передаются только через TLS.
        return parsed._replace(scheme="https", netloc=parsed.hostname).geturl()

    def poll(self, remote_id, expected_sha256):
        payload = _request("GET", f"{self.API}/analyses/{quote(_id(remote_id), safe='')}", self.headers)
        data = _object(payload.get("data"))
        attributes = _object(data.get("attributes"))
        status = attributes.get("status")
        if status in ("queued", "in-progress"):
            return None
        if status != "completed":
            raise ScannerError("VirusTotal не подтвердил завершение анализа.")
        file_info = _object(_object(payload.get("meta")).get("file_info"))
        if file_info.get("sha256") != expected_sha256:
            raise ScannerError("SHA-256 в отчёте VirusTotal не совпадает с файлом заявки.")
        stats = _object(attributes.get("stats"))
        for category in ("malicious", "suspicious", "undetected", "harmless"):
            if type(stats.get(category)) is not int or stats[category] < 0:
                raise ScannerError("В отчёте VirusTotal отсутствуют счётчики вердиктов.")

        if stats["malicious"]:
            verdict = VERDICT.MALICIOUS
        elif stats["suspicious"]:
            verdict = VERDICT.SUSPICIOUS
        elif stats["undetected"] + stats["harmless"]:
            verdict = VERDICT.CLEAN
        else:
            verdict = VERDICT.UNKNOWN
        engines = _object(attributes.get("results", {}))
        return ScanOutcome(
            verdict,
            summary={"stats": stats},
            report={
                "analysis_id": remote_id, "sha256": expected_sha256,
                "date": attributes.get("date"), "stats": stats, "results": engines,
            },
        )


class HttpGatewayScanner:
    def __init__(self, provider):
        self.endpoint = gateway_endpoint(provider.endpoint)
        key = decrypt_api_key(provider.encrypted_api_key)
        self.headers = {"Authorization": f"Bearer {key}"} if key else {}

    def submit(self, stored_file):
        with _verified_file(stored_file) as payload:
            result = _request(
                "POST", f"{self.endpoint}/v1/scans", self.headers,
                data={"sha256": stored_file.file_hash_sha256}, files={"file": payload},
            )
        return _id(result.get("id"))

    def poll(self, remote_id, expected_sha256):
        report = _request("GET", f"{self.endpoint}/v1/scans/{quote(_id(remote_id), safe='')}", self.headers)
        status = report.get("status")
        if status in ("queued", "in-progress"):
            return None
        if status != "completed":
            raise ScannerError("Локальный антивирус не завершил проверку.")
        if report.get("sha256") != expected_sha256:
            raise ScannerError("SHA-256 в отчёте шлюза не совпадает с файлом заявки.")
        verdict = report.get("verdict")
        if verdict not in (VERDICT.CLEAN, VERDICT.SUSPICIOUS, VERDICT.MALICIOUS, VERDICT.UNKNOWN):
            raise ScannerError("Шлюз вернул неизвестный вердикт.")
        summary = report.get("summary", "")
        if not isinstance(summary, str):
            raise ScannerError("Шлюз вернул некорректное резюме.")
        return ScanOutcome(
            verdict, summary={"message": summary[:500]} if summary else {},
            report={"sha256": expected_sha256, "details": _object(report.get("details", {}))},
        )


def remote_scanner(provider):
    if provider.kind == AntivirusProvider.Kind.VIRUSTOTAL:
        return VirusTotalScanner(provider)
    if provider.kind == AntivirusProvider.Kind.HTTP_GATEWAY:
        return HttpGatewayScanner(provider)
    raise ScannerError("Неподдерживаемый тип подключения антивируса.")
