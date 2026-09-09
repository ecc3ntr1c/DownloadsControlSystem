from django.urls import path

from .views import (
    SoftwareRequestCreateAPIView,
    SoftwareRequestDetailAPIView,
    SoftwareRequestListAPIView,
    SoftwareRequestStatusAPIView,
)

urlpatterns = [
    path("", SoftwareRequestListAPIView.as_view(), name="software-request-list"),
    path("create/", SoftwareRequestCreateAPIView.as_view(), name="software-request-create"),
    path("<int:pk>/", SoftwareRequestDetailAPIView.as_view(), name="software-request-detail"),
    path("<int:pk>/status/", SoftwareRequestStatusAPIView.as_view(), name="software-request-status"),
]