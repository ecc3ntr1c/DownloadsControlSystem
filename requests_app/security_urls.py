from django.urls import path

from .security_views import (
    SecurityRequestListAPIView,
    SecurityRequestDetailAPIView,
    SecurityRequestApproveAPIView,
    SecurityRequestRejectAPIView
)

urlpatterns = [
    path("", SecurityRequestListAPIView.as_view(), name="security-request-list"),
    path("<int:pk>/", SecurityRequestDetailAPIView.as_view(), name="security-request-detail"),
    path("<int:pk>/approve/", SecurityRequestApproveAPIView.as_view(), name="security-request-approve"),
    path("<int:pk>/reject/", SecurityRequestRejectAPIView.as_view(), name="security-request-reject"),
]