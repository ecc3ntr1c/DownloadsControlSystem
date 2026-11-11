import hashlib
import socket
import struct
import time

from django.conf import settings

from files_app.services.storage import FileStorageError, FileStorageService

from .contracts import ScanOutcome, ScannerError
from .models import ScanResult


class ClamAVScanner:
    """Передаёт ClamAV только байты файла из закрытого хранилища."""

    CHUNK_SIZE = 64 * 1024
    MAX_REPLY_BYTES = 4096

    def scan(self, stored_file):
        if not 0 < stored_file.size_bytes <= settings.CLAMD_MAX_FILE_BYTES:
            raise ScannerError("Размер файла не подходит для проверки ClamAV.")
        deadline = time.monotonic() + settings.CLAMD_TIMEOUT_SECONDS
        try:
            with FileStorageService().open_file(stored_file) as content, self._connect() as connection:
                self._send(connection, b"zINSTREAM\0", deadline)
                digest = hashlib.sha256()
                size = 0
                for chunk in iter(lambda: content.read(self.CHUNK_SIZE), b""):
                    size += len(chunk)
                    if size > stored_file.size_bytes:
                        raise ScannerError("Размер файла изменился после загрузки.")
                    digest.update(chunk)
                    self._send(connection, struct.pack("!I", len(chunk)) + chunk, deadline)
                if size != stored_file.size_bytes or digest.hexdigest() != stored_file.file_hash_sha256:
                    raise ScannerError("Содержимое файла изменилось после загрузки.")
                self._send(connection, struct.pack("!I", 0), deadline)
                reply = self._read_reply(connection, deadline)
        except FileStorageError as exc:
            raise ScannerError(str(exc)) from exc
        except OSError as exc:
            raise ScannerError("Не удалось завершить проверку в ClamAV.", retryable=True) from exc

        if reply == "stream: OK":
            return ScanOutcome(ScanResult.Verdict.CLEAN, report={"response": reply})
        if reply.startswith("stream: ") and reply.endswith(" FOUND"):
            signature = reply.removeprefix("stream: ").removesuffix(" FOUND").strip()
            if signature:
                verdict = (
                    ScanResult.Verdict.SUSPICIOUS if signature.startswith("Heuristics.")
                    else ScanResult.Verdict.MALICIOUS
                )
                return ScanOutcome(verdict, signature, report={"response": reply})
        raise ScannerError("ClamAV не подтвердил завершение проверки.")

    def ping(self):
        try:
            with self._connect() as connection:
                deadline = time.monotonic() + 5
                self._send(connection, b"zPING\0", deadline)
                return self._read_reply(connection, deadline) == "PONG"
        except (OSError, ScannerError):
            return False

    @staticmethod
    def _connect():
        return socket.create_connection((settings.CLAMD_HOST, settings.CLAMD_PORT), timeout=5)

    @staticmethod
    def _set_timeout(connection, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("ClamAV timed out")
        connection.settimeout(remaining)

    def _send(self, connection, data, deadline):
        self._set_timeout(connection, deadline)
        connection.sendall(data)

    def _read_reply(self, connection, deadline):
        reply = bytearray()
        while len(reply) < self.MAX_REPLY_BYTES:
            self._set_timeout(connection, deadline)
            chunk = connection.recv(min(1024, self.MAX_REPLY_BYTES - len(reply)))
            if not chunk:
                raise ScannerError("ClamAV оборвал ответ.", retryable=True)
            reply.extend(chunk)
            if b"\0" in chunk:
                return bytes(reply).split(b"\0", 1)[0].decode("utf-8", errors="replace")
        raise ScannerError("Ответ ClamAV превышает допустимый размер.")
