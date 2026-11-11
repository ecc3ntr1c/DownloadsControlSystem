from django.shortcuts import get_object_or_404
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.generics import GenericAPIView, ListAPIView, RetrieveAPIView
from rest_framework.response import Response

from accounts.permissions import CanApproveSoftwareRequest, CanRejectSoftwareRequest, CanViewSecurityRequests
from files_app.services.storage import FileStorageError
from scanning.models import ScanResult

from .models import SoftwareRequest
from .request_metadata import request_metadata
from .serializers import (
    RequestReprocessSerializer,
    ScanDetailSerializer,
    SecurityRequestApproveSerializer,
    SecurityRequestDetailSerializer,
    SecurityRequestRejectSerializer,
    SoftwareRequestDetailSerializer,
)
from .services import ApprovalService


def filter_request_status(queryset, status_value):
    if status_value in SoftwareRequest.RequestStatus.values:
        return queryset.filter(request_status=status_value)
    return queryset


class SecurityRequestListAPIView(ListAPIView):
    serializer_class = SoftwareRequestDetailSerializer
    permission_classes = [CanViewSecurityRequests]

    def get_queryset(self):
        return filter_request_status(
            SoftwareRequest.objects.select_related("user", "review_file"),
            self.request.query_params.get("status"),
        )


class SecurityRequestDetailAPIView(RetrieveAPIView):
    serializer_class = SecurityRequestDetailSerializer
    permission_classes = [CanViewSecurityRequests]
    queryset = SoftwareRequest.objects.select_related("user", "review_file", "decided_by")


class SecurityScanReportAPIView(RetrieveAPIView):
    serializer_class = ScanDetailSerializer
    permission_classes = [CanViewSecurityRequests]
    queryset = ScanResult.objects.all()
    lookup_url_kwarg = "scan_id"

    def get_queryset(self):
        return self.queryset.filter(request_id=self.kwargs.get("pk"))


class SecurityRequestActionAPIView(GenericAPIView):
    @extend_schema(responses={200: SoftwareRequestDetailSerializer})
    def post(self, request, pk):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        software_request = get_object_or_404(SoftwareRequest, pk=pk)
        try:
            software_request = self.decision_service(
                software_request=software_request, security_user=request.user,
                request_meta=request_metadata(request), **serializer.validated_data,
            )
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_409_CONFLICT)
        except FileStorageError:
            return Response(
                {"detail": "Не удалось разместить проверенный файл на внутреннем сервере."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        return Response(SoftwareRequestDetailSerializer(
            software_request, context=self.get_serializer_context(),
        ).data)


class SecurityRequestApproveAPIView(SecurityRequestActionAPIView):
    permission_classes = [CanApproveSoftwareRequest]
    serializer_class = SecurityRequestApproveSerializer
    decision_service = staticmethod(ApprovalService.approve_request)


class SecurityRequestRejectAPIView(SecurityRequestActionAPIView):
    permission_classes = [CanRejectSoftwareRequest]
    serializer_class = SecurityRequestRejectSerializer
    decision_service = staticmethod(ApprovalService.reject_request)


class SecurityRequestReprocessAPIView(SecurityRequestActionAPIView):
    permission_classes = [CanApproveSoftwareRequest]
    serializer_class = RequestReprocessSerializer
    decision_service = staticmethod(ApprovalService.reprocess_request)
