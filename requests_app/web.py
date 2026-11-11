import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_http_methods, require_POST, require_safe

from accounts.roles import (
    APPROVE_SOFTWARE_REQUEST_PERMISSION,
    REJECT_SOFTWARE_REQUEST_PERMISSION,
    VIEW_SECURITY_REQUESTS_PERMISSION,
)
from files_app.services.delivery import download_link
from files_app.services.storage import FileStorageError

from .forms import DecisionForm, RequestForm
from .models import SoftwareRequest
from .request_metadata import request_metadata
from .review import approval_blockers, can_reprocess, decision_ready, latest_scan, scan_reports
from .security_views import filter_request_status
from .services import ApprovalService, SoftwareRequestService
from .source_urls import display_source_url


def _render_list(request, queryset, *, security=False):
    status_value = request.GET.get("status", "")
    queryset = filter_request_status(queryset, status_value).order_by("-created_at", "-pk")
    page = Paginator(queryset, 25).get_page(request.GET.get("page"))
    return render(request, "requests_app/list.html", {
        "page_obj": page, "security": security, "status_value": status_value,
        "status_choices": SoftwareRequest.RequestStatus.choices,
    })


@login_required
@require_safe
def my_requests(request):
    return _render_list(request, SoftwareRequest.objects.filter(user=request.user))


@login_required
@permission_required(VIEW_SECURITY_REQUESTS_PERMISSION, raise_exception=True)
@require_safe
def security_requests(request):
    return _render_list(request, SoftwareRequest.objects.select_related("user"), security=True)


@login_required
@require_http_methods(["GET", "HEAD", "POST"])
def create_request(request):
    form = RequestForm(request.POST if request.method == "POST" else None)
    if form.is_valid():
        item = SoftwareRequestService.create_request(
            user=request.user, validated_data=form.cleaned_data, request_meta=request_metadata(request),
        )
        messages.success(request, "Заявка принята и поставлена на автоматическую обработку.")
        return redirect("portal-request", pk=item.pk)
    return render(request, "requests_app/create.html", {"form": form})


@login_required
@require_safe
def request_detail(request, pk):
    item = get_object_or_404(
        SoftwareRequest.objects.select_related("review_file", "decided_by"), pk=pk, user=request.user,
    )
    return _render_detail(request, item)


@login_required
@permission_required(VIEW_SECURITY_REQUESTS_PERMISSION, raise_exception=True)
@require_safe
def security_detail(request, pk):
    item = get_object_or_404(
        SoftwareRequest.objects.select_related("review_file", "user", "decided_by"), pk=pk,
    )
    return _render_detail(request, item, security=True)


def _render_detail(request, item, *, security=False, form=None, status=200):
    context = {
        "item": item, "security": security, "source_display": display_source_url(item.source_url),
        "download_url": download_link(item, request.user), "file": item.review_file,
        "pending": item.processing_due_at is not None,
    }
    if security:
        scan = latest_scan(item)
        matches = list(item.prohibited_matches.select_related("rule"))
        context.update(
            reports=_portal_scan_reports(item), matches=matches, blockers=approval_blockers(item, item.review_file, scan, matches),
            can_decide=decision_ready(item), can_retry=can_reprocess(item),
            form=form if form is not None else DecisionForm(),
        )
    return render(request, "requests_app/detail.html", context, status=status)


def _portal_scan_reports(item):
    reports = scan_reports(item)
    for report in reports:
        if report["result"] is None:
            continue
        raw = report["result"].raw_result
        if not isinstance(raw, dict):
            continue
        engines = raw.get("results")
        if isinstance(engines, dict):
            report["engines"] = [
                {"name": engine.get("engine_name") or name, "category": engine.get("category"),
                 "result": engine.get("result"), "version": engine.get("engine_version")}
                for name, engine in engines.items() if isinstance(engine, dict)
            ]
        if raw.get("details"):
            report["details_json"] = json.dumps(raw["details"], indent=2, ensure_ascii=True)
    return reports


@login_required
@permission_required(VIEW_SECURITY_REQUESTS_PERMISSION, raise_exception=True)
@require_POST
def security_action(request, pk, action):
    actions = {
        "approve": (APPROVE_SOFTWARE_REQUEST_PERMISSION, ApprovalService.approve_request, "Выдача разрешена."),
        "reject": (REJECT_SOFTWARE_REQUEST_PERMISSION, ApprovalService.reject_request, "В выдаче отказано."),
        "reprocess": (APPROVE_SOFTWARE_REQUEST_PERMISSION, ApprovalService.reprocess_request, "Заявка возвращена в очередь."),
    }
    if action not in actions:
        raise Http404
    permission, service, confirmation = actions[action]
    if not request.user.has_perm(permission):
        raise PermissionDenied
    item = get_object_or_404(SoftwareRequest, pk=pk)
    form = DecisionForm(request.POST)
    if not form.is_valid():
        return _render_detail(request, item, security=True, form=form, status=400)
    params = {"security_comment": form.cleaned_data["security_comment"]} if action != "reprocess" else {}
    try:
        service(software_request=item, security_user=request.user, request_meta=request_metadata(request), **params)
    except ValueError as exc:
        form.add_error(None, str(exc))
        return _render_detail(request, item, security=True, form=form, status=409)
    except FileStorageError:
        form.add_error(None, "Не удалось опубликовать файл на внутреннем сервере.")
        return _render_detail(request, item, security=True, form=form, status=503)
    messages.success(request, confirmation)
    return redirect("portal-security-request", pk=item.pk)
