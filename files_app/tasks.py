from celery import shared_task

from requests_app.processing import process_request
from requests_app.tasks import TASK_LIMITS

from .models import FileSource


@shared_task(name="files.download_file_source", queue="downloads", **TASK_LIMITS)
def download_file_source(source_id):
    """Совместимость с ранее отправленными задачами загрузки."""
    request_id = FileSource.objects.filter(pk=source_id).values_list("request_id", flat=True).first()
    if request_id is None:
        return "source_not_found"
    return process_request(request_id)


@shared_task(soft_time_limit=60, time_limit=90)
def enforce_file_retention():
    from .services.retention import cleanup_expired_files, cleanup_stale_workspaces

    removed = cleanup_expired_files()
    cleanup_stale_workspaces()
    return removed
