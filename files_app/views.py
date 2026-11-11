from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, HttpResponse
from django.utils.http import content_disposition_header
from django.views.decorators.http import require_safe

from files_app.services.delivery import authorize_download
from requests_app.request_metadata import request_metadata


@login_required
@require_safe
def download_approved_file(request, pk):
    stored_file, content = authorize_download(
        pk, request.user, record=request.method == "GET", request_meta=request_metadata(request),
    )
    if settings.FILE_DELIVERY_ACCEL:
        content.close()
        response = HttpResponse(content_type="application/octet-stream")
        response["X-Accel-Redirect"] = f"/_approved/{stored_file.stored_filename}"
        response["Content-Disposition"] = content_disposition_header(True, stored_file.original_filename)
    else:
        response = FileResponse(
            content, content_type="application/octet-stream", as_attachment=True,
            filename=stored_file.original_filename,
        )
    response["Cache-Control"] = "private, no-store"
    response["X-Content-Type-Options"] = "nosniff"
    return response
