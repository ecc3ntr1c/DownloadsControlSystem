from django.urls import path

from .views import (
    SoftwareRequestCreateAPIView,
    SoftwareRequestDetailAPIView,
    SoftwareRequestListAPIView,
    SoftwareRequestStatusAPIView,
)

from .security_views import (
    SecurityRequestListAPIView,
    SecurityRequestDetailAPIView,
    SecurityRequestApproveAPIView,
    SecurityRequestRejectAPIView
)

urlpatterns = [
    path("", SoftwareRequestListAPIView.as_view(), name="software-request-list"),
    path("create/", SoftwareRequestCreateAPIView.as_view(), name="software-request-create"),
    path("<int:pk>/", SoftwareRequestDetailAPIView.as_view(), name="software-request-detail"),
    path("<int:pk>/status/", SoftwareRequestStatusAPIView.as_view(), name="software-request-status"),

    path("security/", SecurityRequestListAPIView.as_view(), name="legacy-security-request-list"),
    path("security/<int:pk>/", SecurityRequestDetailAPIView.as_view(), name="legacy-security-request-detail"),
    path("security/<int:pk>/approve", SecurityRequestApproveAPIView.as_view(), name="legacy-security-request-approve"),
    path("security/<int:pk>/reject", SecurityRequestRejectAPIView.as_view(), name="legacy-security-request-reject"),
]
