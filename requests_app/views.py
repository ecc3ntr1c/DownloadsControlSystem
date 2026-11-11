from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.generics import GenericAPIView, ListAPIView, RetrieveAPIView
from rest_framework.response import Response

from .models import SoftwareRequest
from .request_metadata import request_metadata
from .serializers import SoftwareRequestCreateSerializer, SoftwareRequestDetailSerializer
from .services import SoftwareRequestService


class SoftwareRequestCreateAPIView(GenericAPIView):
    serializer_class = SoftwareRequestCreateSerializer

    @extend_schema(responses={201: SoftwareRequestDetailSerializer})
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        software_request = SoftwareRequestService.create_request(
            user=request.user, validated_data=serializer.validated_data, request_meta=request_metadata(request),
        )
        data = SoftwareRequestDetailSerializer(software_request, context=self.get_serializer_context()).data
        return Response(data, status=status.HTTP_201_CREATED)


class OwnedRequestsMixin:
    serializer_class = SoftwareRequestDetailSerializer

    def get_queryset(self):
        if not self.request.user.is_authenticated:
            return SoftwareRequest.objects.none()
        return SoftwareRequest.objects.filter(user=self.request.user).select_related("review_file", "user")


class SoftwareRequestListAPIView(OwnedRequestsMixin, ListAPIView):
    pass


class SoftwareRequestDetailAPIView(OwnedRequestsMixin, RetrieveAPIView):
    pass


class SoftwareRequestStatusAPIView(SoftwareRequestDetailAPIView):
    pass
