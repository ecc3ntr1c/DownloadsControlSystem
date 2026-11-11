from django.urls import path

from .security_views import (
    SecurityRequestListAPIView,
    SecurityRequestDetailAPIView,
    SecurityRequestApproveAPIView,
    SecurityRequestRejectAPIView,
    SecurityRequestReprocessAPIView,
    SecurityScanReportAPIView,
)

urlpatterns = [
    path("", SecurityRequestListAPIView.as_view(), name="security-request-list"),
    path("<int:pk>/", SecurityRequestDetailAPIView.as_view(), name="security-request-detail"),
    path("<int:pk>/approve/", SecurityRequestApproveAPIView.as_view(), name="security-request-approve"),
    path("<int:pk>/reject/", SecurityRequestRejectAPIView.as_view(), name="security-request-reject"),
    path("<int:pk>/reprocess/", SecurityRequestReprocessAPIView.as_view(), name="security-request-reprocess"),
    path("<int:pk>/scans/<int:scan_id>/", SecurityScanReportAPIView.as_view(), name="security-scan-report"),
]
