from base64 import urlsafe_b64encode

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.utils.crypto import salted_hmac

from .contracts import ScannerError


def _cipher():
    key = settings.ANTIVIRUS_ENCRYPTION_KEY
    if not key:
        if settings.SECRET_KEY == "unsafe-dev-key":
            raise ScannerError("Задай ANTIVIRUS_ENCRYPTION_KEY или собственный SECRET_KEY в окружении приложения.")
        digest = salted_hmac(
            "downloadscontrol.antivirus.credentials", "v1", algorithm="sha256",
        ).digest()
        key = urlsafe_b64encode(digest)
    try:
        return Fernet(key)
    except ValueError as exc:
        raise ScannerError("Некорректный ключ шифрования учётных данных антивирусов.") from exc


def encrypt_api_key(value):
    return _cipher().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_api_key(value):
    if not value:
        return ""
    try:
        return _cipher().decrypt(value).decode("utf-8")
    except (InvalidToken, UnicodeError) as exc:
        raise ScannerError("Не удалось расшифровать ключ API. Сохрани его заново в админке.") from exc
