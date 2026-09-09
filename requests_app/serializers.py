from rest_framework import serializers

from .models import SoftwareRequest


class SoftwareRequestCreateSerializer(serializers.ModelSerializer):
    """
    Serializer для создания заявки пользователем.

    Пользователь передаёт:
    - ссылку на ПО;
    - описание;
    - обоснование;
    """

    class Meta:
        model = SoftwareRequest
        fields = (
            "source_url",
            "description",
            "business_reason",
        )


class ExternalSoftwareRequestCreateSerializer(serializers.ModelSerializer):
    """
    Serializer для создания заявки внешней системой.

    Система передаёт:
    - ссылку на ПО;
    - описание;
    - обоснование;
    - ID внешней системы;
    - ID заявки во внешней системы.
    """

    class Meta:
        model = SoftwareRequest
        fields = (
            "id",
            "source_url",
            "description",
            "business_reason",
            "external_system",
            "external_request_id",
        )
        read_only_fields = ("id",)

    def validate_external_system(self, value):
        if not value:
            raise serializers.ValidationError("external_system обязателен для внешней системы.")
        return value

    def validate_external_request_id(self, value):
        if not value:
            raise serializers.ValidationError("external_request_id обязателен для внешней системы.")
        return value


class SoftwareRequestDetailSerializer(serializers.ModelSerializer):
    """
    Serializer для просмотра карточки заявки.
    """

    user = serializers.StringRelatedField()

    class Meta:
        model = SoftwareRequest
        fields = (
            "id",
            "user",
            "source_url",
            "description",
            "business_reason",
            "request_status",
            "scan_status",
            "risk_level",
            "security_comment",
            "external_system",
            "external_request_id",
            "created_at",
            "updated_at",
            "closed_at",
        )
        read_only_fields = fields