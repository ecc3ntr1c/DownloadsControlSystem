import logging

import redis
from django.conf import settings
from django.db import DatabaseError, connection
from django.http import JsonResponse
from django.views.decorators.http import require_safe

from files_app.services.storage import FileStorageError, FileStorageService

logger = logging.getLogger(__name__)


@require_safe
def health(request):
    return JsonResponse({"status": "ok"})


@require_safe
def readiness(request):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        with redis.Redis.from_url(settings.CELERY_BROKER_URL, socket_connect_timeout=2, socket_timeout=2) as broker:
            broker.ping()
        FileStorageService().validate_structure()
    except (DatabaseError, redis.RedisError, FileStorageError, OSError, ValueError) as exc:
        logger.warning("Сервис временно не готов (%s)", type(exc).__name__)
        return JsonResponse({"status": "unavailable"}, status=503)
    return JsonResponse({"status": "ready"})
