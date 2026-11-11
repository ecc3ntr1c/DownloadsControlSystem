from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST, require_safe

from .models import Notification


@login_required
@require_safe
def inbox(request):
    queryset = Notification.objects.filter(recipient=request.user)
    return render(request, "notifications/inbox.html", {
        "page_obj": Paginator(queryset, 25).get_page(request.GET.get("page")),
        "unread": queryset.filter(read_at__isnull=True).exists(),
    })


@login_required
@require_POST
def mark_all_read(request):
    Notification.objects.filter(recipient=request.user, read_at__isnull=True).update(read_at=timezone.now())
    return redirect("notification-inbox")
