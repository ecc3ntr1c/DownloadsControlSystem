"""Проверка сквозного сценария в изолированном тестовом Compose."""

import hashlib
import os
import secrets
import time
from pathlib import Path

import django
import httpx

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
django.setup()

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.utils import timezone

from accounts.roles import SOFTWARE_CONTROL_SECURITY_GROUP
from audit.models import AuditLog
from files_app.models import DownloadsPolicy, StoredFile
from files_app.services.retention import cleanup_expired_files
from requests_app.models import SoftwareRequest

BASE_URL = "http://portal.test:8080"


def login(client, user, password):
    response = client.get("/login/")
    response.raise_for_status()
    token = client.cookies["csrftoken"]
    response = client.post(
        "/login/", data={"username": user.username, "password": password, "csrfmiddlewaretoken": token},
    )
    assert response.status_code == 302, response.status_code


def enter_portal(client, name):
    response = client.get("/welcome/")
    response.raise_for_status()
    response = client.post("/welcome/", data={
        "name": name, "csrfmiddlewaretoken": client.cookies["csrftoken"],
    })
    assert response.status_code == 302 and response.headers["Location"] == "/", response.status_code


def post_json(client, path, body, expected):
    response = client.post(path, json=body, headers={"X-CSRFToken": client.cookies["csrftoken"]})
    assert response.status_code == expected, f"{path}: {response.status_code} != {expected}"
    return response.json()


def check():
    if (
        os.environ.get("DOWNLOADSCONTROL_SMOKE") != "1"
        or settings.DATABASES["default"]["NAME"] != "downloadscontrol_smoke"
    ):
        raise SystemExit("Используй отдельную тестовую БД и deploy/compose.smoke.yml.")

    password = secrets.token_urlsafe(32)
    suffix = secrets.token_hex(4)
    users = get_user_model().objects
    officer = users.create_user(f"smoke-officer-{suffix}", password=password)
    officer.groups.add(Group.objects.get(name=SOFTWARE_CONTROL_SECURITY_GROUP))

    policy = DownloadsPolicy.objects.get(is_active=True)
    policy.allow_private_networks = True
    policy.allowed_domains = ["fixture.test"]
    policy.allowed_ports = [8000]
    policy.save(update_fields=["allow_private_networks", "allowed_domains", "allowed_ports"])

    fixture = Path(__file__).resolve().parents[1] / "deploy" / "fixtures" / "package.txt"
    expected_bytes = fixture.read_bytes()
    with (
        httpx.Client(base_url=BASE_URL, timeout=8) as employee,
        httpx.Client(base_url=BASE_URL, timeout=8) as security,
        httpx.Client(base_url=BASE_URL, timeout=8) as another,
    ):
        assert employee.get("/readyz/").json() == {"status": "ready"}
        assert employee.get("/static/downloadscontrol/portal.css").status_code == 200
        name = f"Участник проверки {suffix}"
        enter_portal(employee, name)
        enter_portal(another, name)
        login(security, officer, password)
        assert employee.get("/security/").status_code == 403
        payload = post_json(employee, "/api/v1/requests/create/", {
            "source_url": "http://fixture.test:8000/package.txt", "description": "Контрольный пакет",
            "business_reason": "Локальная проверка",
        }, 201)
        request_id = payload["id"]
        owner = SoftwareRequest.objects.get(pk=request_id).user
        assert owner.get_full_name() == name and not owner.has_usable_password()
        assert another.get(f"/requests/{request_id}/").status_code == 404
        assert payload["download_url"] is None
        print(f"Заявка {request_id} принята через Nginx, ожидание Celery и ClamAV", flush=True)

        deadline = time.monotonic() + 60
        while True:
            response = security.get(f"/api/v1/security/requests/{request_id}/")
            response.raise_for_status()
            review = response.json()
            if review["request_status"] == "WAITING_SECURITY_DECISION":
                break
            if time.monotonic() >= deadline:
                raise AssertionError(f"Заявка не обработана: {review['scan_status']}, {review['processing_error']}")
            time.sleep(1)
        assert review["scan_status"] == "SCAN_COMPLETED", review["processing_error"]
        assert name in security.get(f"/security/{request_id}/").text
        assert review["scan"]["provider"] == "CLAMAV" and review["scan"]["verdict"] == "CLEAN", review["scan"]
        assert review["scan"]["file_sha256"] == hashlib.sha256(expected_bytes).hexdigest()
        file_id = review["file"]["id"]
        link = f"/downloads/{file_id}/"
        assert employee.get(link).status_code == 404

        post_json(security, f"/api/v1/security/requests/{request_id}/approve/", {"security_comment": "Проверено"}, 200)
        portal = employee.get(f"/requests/{request_id}/")
        assert portal.status_code == 200 and link in portal.text
        assert another.get(link).status_code == 404
        stored_file = StoredFile.objects.get(pk=file_id)
        assert employee.get(f"/_approved/{stored_file.stored_filename}").status_code == 404
        received = employee.get(link)
        assert received.status_code == 200 and received.content == expected_bytes
        assert "attachment" in received.headers["Content-Disposition"]
        assert "no-store" in received.headers["Cache-Control"]
        assert received.headers["Content-Type"] == "application/octet-stream"
        assert AuditLog.objects.filter(actor=owner, action="FILE_DOWNLOAD_AUTHORIZED", object_id=str(request_id)).exists()
        print("Решение ИБ применено, Nginx выдал правильные байты только владельцу", flush=True)

        StoredFile.objects.filter(pk=file_id).update(delete_after=timezone.now())
        assert employee.get(link).status_code == 404
        assert cleanup_expired_files() >= 1
        stored_file.refresh_from_db()
        assert stored_file.storage_zone == StoredFile.StorageZone.DELETED
        assert SoftwareRequest.objects.get(pk=request_id).request_status == SoftwareRequest.RequestStatus.CLOSED
        print("Просроченный файл недоступен и удалён, история заявки сохранена", flush=True)


if __name__ == "__main__":
    check()
