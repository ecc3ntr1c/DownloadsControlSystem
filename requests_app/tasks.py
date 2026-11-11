import logging
from datetime import timedelta

from celery import shared_task
from django.db.models import Q
from django.utils import timezone
from kombu.exceptions import OperationalError

from .models import SoftwareRequest
from .processing import process_request

logger = logging.getLogger(__name__)
TASK_LIMITS = {"acks_late": True, "reject_on_worker_lost": True, "soft_time_limit": 810, "time_limit": 840}


@shared_task(**TASK_LIMITS)
def process_software_request_task(request_id):
    return process_request(request_id)


def _pending_requests(now):
    return SoftwareRequest.objects.filter(
        Q(last_queued_at__isnull=True) | Q(last_queued_at__lte=now - timedelta(minutes=2)),
        request_status=SoftwareRequest.RequestStatus.UNDER_SECURITY_REVIEW,
        processing_due_at__lte=now,
    )


def publish_request(request_id):
    """Поставить задачу в очередь. Строка в БД остаётся источником повторной постановки."""
    now = timezone.now()
    reserved = _pending_requests(now).filter(pk=request_id).update(last_queued_at=now)
    if not reserved:
        return False
    try:
        process_software_request_task.apply_async(args=(request_id,), retry=False, expires=120)
        return True
    except (OperationalError, OSError):
        logger.warning("Очередь недоступна, заявка %s сохранена для повторной постановки", request_id)
        SoftwareRequest.objects.filter(pk=request_id, last_queued_at=now).update(last_queued_at=None)
        return False


@shared_task
def dispatch_pending_requests():
    due = list(
        _pending_requests(timezone.now()).order_by("processing_due_at", "pk").values_list("pk", flat=True)[:50]
    )
    for request_id in due:
        if not publish_request(request_id):
            break
