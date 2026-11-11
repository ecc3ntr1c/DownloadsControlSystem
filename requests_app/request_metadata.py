from ipaddress import ip_address

from django.conf import settings


def request_metadata(request):
    address = request.META.get("REMOTE_ADDR")
    if settings.TRUST_EDGE_IP:
        address = request.META.get("HTTP_X_REAL_IP", address)
    try:
        address = str(ip_address(address))
    except ValueError:
        address = None
    return {"ip_address": address, "user_agent": request.META.get("HTTP_USER_AGENT", "")[:512]}
