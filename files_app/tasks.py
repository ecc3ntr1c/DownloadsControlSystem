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
