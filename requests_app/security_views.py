from rest_framework import status
from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.permissions import (
    CanApproveSoftwareRequest,
    CanRejectSoftwareRequest,
    CanViewSecurityRequests,
)
from .models import SoftwareRequest
from .serializers import (
    SecurityRequestApproveSerializer,
    SecurityRequestRejectSerializer,
    SoftwareRequestDetailSerializer,
)
from .services import ApprovalService
from .views import get_client_ip


class SecurityRequestListAPIView(ListAPIView):
    """
    Список всех заявок для сотрудника ИБ.
    """

    serializer_class = SoftwareRequestDetailSerializer
    permission_classes = [CanViewSecurityRequests]

    def get_queryset(self):
        return SoftwareRequest.objects.all().order_by("-created_at")


class SecurityRequestDetailAPIView(RetrieveAPIView):
    """
    Карточка любой заявки для сотрудника ИБ.
    """

    serializer_class = SoftwareRequestDetailSerializer
    permission_classes = [CanViewSecurityRequests]

    def get_queryset(self):
        return SoftwareRequest.objects.all()


class SecurityRequestApproveAPIView(APIView):
    """
    Согласование заявки сотрудником ИБ.
    """

    permission_classes = [CanApproveSoftwareRequest]

    def post(self, request, pk):
        serializer = SecurityRequestApproveSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            software_request = SoftwareRequest.objects.get(id=pk)
        except SoftwareRequest.DoesNotExist:
            return Response(
                {"detail": "Заявка не найдена."},
                status=status.HTTP_404_NOT_FOUND,
            )

        try:
            software_request = ApprovalService.approve_request(
                software_request=software_request,
                security_user=request.user,
                security_comment=serializer.validated_data.get(
                    "security_comment",
                    "",
                ),
                request_meta={
                    "ip_address": get_client_ip(request),
                    "user_agent": request.META.get("HTTP_USER_AGENT", ""),
                },
            )
        except ValueError as error:
            return Response(
                {"detail": str(error)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        response_serializer = SoftwareRequestDetailSerializer(software_request)
        return Response(response_serializer.data, status=status.HTTP_200_OK)


class SecurityRequestRejectAPIView(APIView):
    """
    Отказ по заявке сотрудником ИБ.
    """

    permission_classes = [CanRejectSoftwareRequest]

    def post(self, request, pk):
        serializer = SecurityRequestRejectSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            software_request = SoftwareRequest.objects.get(id=pk)
        except SoftwareRequest.DoesNotExist:
            return Response(
                {"detail": "Заявка не найдена."},
                status=status.HTTP_404_NOT_FOUND,
            )

        try:
            software_request = ApprovalService.reject_request(
                software_request=software_request,
                security_user=request.user,
                security_comment=serializer.validated_data["security_comment"],
                request_meta={
                    "ip_address": get_client_ip(request),
                    "user_agent": request.META.get("HTTP_USER_AGENT", ""),
                },
            )
        except ValueError as error:
            return Response(
                {"detail": str(error)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        response_serializer = SoftwareRequestDetailSerializer(software_request)
        return Response(response_serializer.data, status=status.HTTP_200_OK)