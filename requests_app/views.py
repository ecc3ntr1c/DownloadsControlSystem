from rest_framework import permissions, status
from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import SoftwareRequest
from .serializers import (
    SoftwareRequestCreateSerializer,
    SoftwareRequestDetailSerializer,
)
from .services import SoftwareRequestService


def get_client_ip(request):
    """
    Получение IP клиента.

    Пока простая версия.
    Позже можно доработать под reverse proxy / nginx.
    """
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")

    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()

    return request.META.get("REMOTE_ADDR")


class SoftwareRequestCreateAPIView(APIView):
    """
    Создание заявки на проверку ПО.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = SoftwareRequestCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        software_request = SoftwareRequestService.create_request(
            user=request.user,
            validated_data=serializer.validated_data,
            request_meta={
                "ip_address": get_client_ip(request),
                "user_agent": request.META.get("HTTP_USER_AGENT", ""),
            },
        )

        response_serializer = SoftwareRequestDetailSerializer(software_request)

        return Response(
            response_serializer.data,
            status=status.HTTP_201_CREATED,
        )


class SoftwareRequestListAPIView(ListAPIView):
    """
    Список заявок текущего пользователя.

    Сотруднику ИБ позже сделаем отдельный endpoint,
    где будут видны все заявки.
    """

    serializer_class = SoftwareRequestDetailSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return SoftwareRequest.objects.filter(
            user=self.request.user
        ).order_by("-created_at")


class SoftwareRequestDetailAPIView(RetrieveAPIView):
    """
    Карточка заявки.
    """

    serializer_class = SoftwareRequestDetailSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return SoftwareRequest.objects.filter(user=self.request.user)


class SoftwareRequestStatusAPIView(RetrieveAPIView):
    """
    Краткий статус заявки.

    Пока используем тот же serializer, потом можно сделать отдельный короткий.
    """

    serializer_class = SoftwareRequestDetailSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return SoftwareRequest.objects.filter(user=self.request.user)