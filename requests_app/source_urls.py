from urllib.parse import urlsplit


def parse_source_url(value):
    """Проверка формы ссылки без DNS или сетевых обращений."""
    if (
        not value or len(value) > 2048 or "\\" in value
        or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError("Введите прямую ссылку HTTP или HTTPS.")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Некорректный адрес или порт источника.") from exc
    if parsed.scheme not in {"http", "https"} or not hostname or port == 0:
        raise ValueError("Введите прямую ссылку HTTP или HTTPS.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Ссылки с именем пользователя или паролем не принимаются.")
    return parsed


def display_source_url(value):
    """Ссылка для экрана ИБ и аудита без параметров доступа."""
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ""
        return parsed._replace(netloc=parsed.netloc.rsplit("@", 1)[-1], query="", fragment="").geturl()
    except ValueError:
        return ""
