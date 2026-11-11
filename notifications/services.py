from .models import Notification


def notify_request_owner(request, event):
    Notification.objects.create(recipient_id=request.user_id, request=request, event=event)
