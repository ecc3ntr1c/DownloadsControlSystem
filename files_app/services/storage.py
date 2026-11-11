import errno
import hashlib
import logging
import os
import re
import shutil
import stat
import tempfile
import uuid
from pathlib import Path

from django.conf import settings

from files_app.downloaders.exceptions import DownloadStorageError
from files_app.models import StoredFile

logger = logging.getLogger(__name__)


class FileStorageError(DownloadStorageError):
    """Хранилище не может выполнить операцию с файлом."""


class FileStorageService:
    """Закрытое локальное хранилище с отдельной зоной выдачи."""

    _ZONE_NAMES = {
        StoredFile.StorageZone.QUARANTINE: "quarantine",
        StoredFile.StorageZone.APPROVED: "approved",
        StoredFile.StorageZone.REJECTED: "rejected",
        StoredFile.StorageZone.DELETED: "deleted",
    }
    _FILE_NAME = re.compile(r"[0-9a-f]{32}(?:\.[a-z0-9]{1,12})?")

    def __init__(self):
        self.root_dir = Path(settings.FILE_STORAGE_ROOT).expanduser().resolve()

    def _directory(self, name):
        path = self.root_dir / name
        if path.resolve() != path:
            raise FileStorageError("Каталог хранилища не должен быть символической ссылкой.")
        return path

    @property
    def staging_dir(self):
        return self._directory("staging")

    def get_zone_dir(self, zone):
        return self._directory(self._ZONE_NAMES[StoredFile.StorageZone(zone)])

    def ensure_structure(self):
        try:
            self.root_dir.mkdir(parents=True, exist_ok=True)
            self.staging_dir.mkdir(mode=0o700, exist_ok=True)
            for zone in self._ZONE_NAMES:
                mode = 0o755 if zone == StoredFile.StorageZone.APPROVED else 0o700
                self.get_zone_dir(zone).mkdir(mode=mode, exist_ok=True)
            self.validate_structure()
        except OSError as exc:
            raise FileStorageError("Не удалось подготовить файловое хранилище.") from exc

    def validate_structure(self):
        directories = [self.staging_dir, *(self.get_zone_dir(zone) for zone in self._ZONE_NAMES)]
        if not all(path.is_dir() for path in directories):
            raise FileStorageError("Не созданы каталоги файлового хранилища.")

    def download_workspace(self):
        self.ensure_structure()
        return tempfile.TemporaryDirectory(prefix="job-", dir=self.staging_dir)

    def zone_path(self, zone, filename):
        if not self._FILE_NAME.fullmatch(filename):
            raise FileStorageError("Некорректное внутреннее имя файла.")
        path = self.get_zone_dir(zone) / filename
        if path.is_symlink():
            raise FileStorageError("Файл хранилища не должен быть символической ссылкой.")
        return path

    def relative_path(self, path):
        return str(Path(path).relative_to(self.root_dir))

    def path_for(self, stored_file):
        if stored_file.storage_zone == StoredFile.StorageZone.DELETED:
            raise FileStorageError("Файл удалён.")
        path = self.zone_path(stored_file.storage_zone, stored_file.stored_filename)
        recorded = Path(stored_file.storage_path)
        # Старые версии сохраняли абсолютный путь.
        if recorded not in (path, path.relative_to(self.root_dir)):
            raise FileStorageError("Путь файла не соответствует зоне хранилища.")
        return path

    def open_file(self, stored_file):
        try:
            path = self.path_for(stored_file)
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            with_fd = os.open(path, flags)
            try:
                info = os.fstat(with_fd)
                if not stat.S_ISREG(info.st_mode) or info.st_size != stored_file.size_bytes:
                    raise FileStorageError("Размер или тип файла не соответствует записи.")
                return os.fdopen(with_fd, "rb")
            except BaseException:
                os.close(with_fd)
                raise
        except OSError as exc:
            raise FileStorageError("Файл отсутствует или недоступен.") from exc

    def save_file(self, *, source_path, zone, extension=""):
        """Перенести временный файл из staging в закрытую зону."""
        source = Path(source_path)
        if source.is_symlink() or not source.resolve().is_relative_to(self.staging_dir):
            raise FileStorageError("Ожидался временный файл хранилища.")
        if not source.is_file() or zone == StoredFile.StorageZone.APPROVED:
            raise FileStorageError("Файл можно опубликовать только после проверки.")
        suffix = extension.strip().lower().lstrip(".")
        suffix = f".{suffix}" if re.fullmatch(r"[a-z0-9]{1,12}", suffix) else ""
        destination = self.zone_path(zone, f"{uuid.uuid4().hex}{suffix}")
        try:
            try:
                os.replace(source, destination)
            except OSError as exc:
                if exc.errno != errno.EXDEV:
                    raise
                with source.open("rb") as content:
                    self._write_copy(content, destination)
                self.remove_quietly(source)
        except OSError as exc:
            raise FileStorageError("Не удалось сохранить временный файл.") from exc
        return destination

    def copy_for_decision(self, stored_file, zone):
        """Сохранить исходник до коммита БД и проверить SHA-256 публикуемой копии."""
        if zone not in (StoredFile.StorageZone.APPROVED, StoredFile.StorageZone.REJECTED):
            raise FileStorageError("Некорректная зона для решения ИБ.")
        if stored_file.storage_zone != StoredFile.StorageZone.QUARANTINE:
            raise FileStorageError("Решение можно применить к файлу из карантина.")
        destination = self.zone_path(zone, stored_file.stored_filename)
        try:
            with self.open_file(stored_file) as content:
                self._write_copy(
                    content,
                    destination,
                    expected_hash=stored_file.file_hash_sha256,
                    public_read=zone == StoredFile.StorageZone.APPROVED,
                )
        except OSError as exc:
            raise FileStorageError("Не удалось сохранить результат решения ИБ.") from exc
        return destination

    @staticmethod
    def _write_copy(content, destination, *, expected_hash=None, public_read=False):
        digest = hashlib.sha256()
        temporary_path = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=destination.parent, prefix=".storage-", suffix=".part", delete=False
            ) as output:
                temporary_path = Path(output.name)
                for chunk in iter(lambda: content.read(1024 * 1024), b""):
                    output.write(chunk)
                    digest.update(chunk)
                if expected_hash is not None and digest.hexdigest() != expected_hash:
                    raise FileStorageError("Содержимое файла изменилось после загрузки.")
                if public_read:
                    os.fchmod(output.fileno(), 0o644)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary_path, destination)
        finally:
            if temporary_path is not None:
                FileStorageService.remove_quietly(temporary_path)

    @staticmethod
    def remove_quietly(path):
        try:
            Path(path).unlink(missing_ok=True)
        except OSError:
            logger.warning("Не удалось убрать временную или заменённую копию файла.")
