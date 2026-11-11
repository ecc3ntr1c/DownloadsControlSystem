"""Создать отдельное окружение Compose с уникальными локальными секретами."""

import argparse
import os
import secrets
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, nargs="?", default=Path(".env.compose"))
    parser.add_argument("--smoke", action="store_true", help="Настроить отдельную БД для сквозного теста.")
    options = parser.parse_args()
    example = Path(__file__).resolve().parents[1] / ".env.example"
    content = example.read_text(encoding="utf-8")
    content = content.replace(
        "DOWNLOADSCONTROL_SECRET_KEY=\n", f"DOWNLOADSCONTROL_SECRET_KEY={secrets.token_urlsafe(64)}\n",
    ).replace("POSTGRES_PASSWORD=\n", f"POSTGRES_PASSWORD={secrets.token_urlsafe(32)}\n")
    if options.smoke:
        content = content.replace("POSTGRES_DB=software_control", "POSTGRES_DB=downloadscontrol_smoke")
        content = content.replace("PORTAL_PORT=8080", "PORTAL_PORT=18080")
        content = content.replace("ALLOWED_HOSTS=localhost,127.0.0.1", "ALLOWED_HOSTS=localhost,127.0.0.1,portal.test")
        content += "DOWNLOADSCONTROL_IMAGE_TAG=smoke\n"
    try:
        fd = os.open(options.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        parser.exit(1, f"Файл {options.path} уже существует. Выбери другой путь.\n")
    with os.fdopen(fd, "w", encoding="utf-8") as environment:
        environment.write(content)
    print(f"Создано окружение {options.path}")


if __name__ == "__main__":
    main()
