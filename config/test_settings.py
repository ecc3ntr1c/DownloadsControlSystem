import os
from tempfile import TemporaryDirectory
from pathlib import Path

os.environ["LOAD_PROJECT_DOTENV"] = "0"
from .settings import *  # noqa: E402, F403

SECRET_KEY = "test-key-only-used-for-tests"
if os.getenv("TEST_POSTGRES") != "1":
    DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
CELERY_BROKER_URL = "memory://"
CELERY_RESULT_BACKEND = "cache+memory://"
_storage = TemporaryDirectory(prefix="downloadscontrol-tests-")
FILE_STORAGE_ROOT = Path(_storage.name)
FILE_DELIVERY_ACCEL = False
TRUST_EDGE_IP = False
