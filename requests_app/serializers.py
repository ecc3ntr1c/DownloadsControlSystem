from rest_framework import serializers
from drf_spectacular.utils import extend_schema_field

from files_app.models import ProhibitedSoftwareMatch, StoredFile
from files_app.services.delivery import download_link
from scanning.models import ScanResult

from .models import SoftwareRequest
from .review import approval_blockers, latest_scan, scan_reports
from .source_urls import display_source_url, parse_source_url


class RequestInputSerializer(serializers.ModelSerializer):
    description = serializers.CharField(max_length=4000)
    business_reason = serializers.CharField(max_length=4000)

    def validate_source_url(self, value):
        try:
            return parse_source_url(value).geturl()
        except ValueError as exc:
            raise serializers.ValidationError(str(exc)) from exc


class SoftwareRequestCreateSerializer(RequestInputSerializer):
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


class ExternalSoftwareRequestCreateSerializer(RequestInputSerializer):
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
    source_url = serializers.SerializerMethodField()
    download_url = serializers.SerializerMethodField()

    @extend_schema_field(str)
    def get_source_url(self, obj):
        return display_source_url(obj.source_url)

    @extend_schema_field(serializers.URLField(allow_null=True))
    def get_download_url(self, obj):
        request = self.context.get("request")
        if request is None:
            return None
        link = download_link(obj, request.user)
        return request.build_absolute_uri(link) if link else None

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
            "processing_error",
            "decided_at",
            "download_url",
        )
        read_only_fields = fields


class SecurityRequestApproveSerializer(serializers.Serializer):
    security_comment = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=2000,
    )


class SecurityRequestRejectSerializer(serializers.Serializer):
    security_comment = serializers.CharField(
        required=True,
        allow_blank=False,
        max_length=2000,
    )


class FileSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = StoredFile
        fields = ("id", "original_filename", "file_hash_sha256", "size_bytes", "mime_type", "storage_zone", "delete_after")


class ScanSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanResult
        fields = ("id", "provider", "verdict", "risk_level", "file_sha256", "normalized_result", "created_at")


class ScanDetailSerializer(ScanSummarySerializer):
    class Meta(ScanSummarySerializer.Meta):
        fields = ScanSummarySerializer.Meta.fields + ("raw_result",)


class ProviderReportSerializer(serializers.Serializer):
    name = serializers.CharField()
    provider = serializers.CharField()
    status = serializers.ChoiceField(choices=("pending", "waiting_report", "finished"))
    last_error = serializers.CharField(allow_blank=True)
    result = ScanSummarySerializer(allow_null=True)


class ProhibitedMatchSerializer(serializers.ModelSerializer):
    rule_name = serializers.CharField(source="rule.name")
    reason = serializers.CharField(source="rule.reason")

    class Meta:
        model = ProhibitedSoftwareMatch
        fields = ("rule_name", "reason", "matched_field", "is_overridden")


class SecurityRequestDetailSerializer(SoftwareRequestDetailSerializer):
    file = FileSummarySerializer(source="review_file", allow_null=True)
    scan = serializers.SerializerMethodField()
    reports = serializers.SerializerMethodField()
    prohibited_matches = ProhibitedMatchSerializer(many=True)
    approval_blockers = serializers.SerializerMethodField()
    decided_by = serializers.StringRelatedField()

    @extend_schema_field(ScanSummarySerializer(allow_null=True))
    def get_scan(self, obj):
        severity = {"CLEAN": 0, "UNKNOWN": 1, "FAILED": 2, "SUSPICIOUS": 3, "MALICIOUS": 4}
        results = (report["result"] for report in scan_reports(obj) if report["result"] is not None)
        result = max(results, key=lambda item: severity.get(item.verdict, 1), default=None)
        return ScanSummarySerializer(result).data if result else None

    @extend_schema_field(ProviderReportSerializer(many=True))
    def get_reports(self, obj):
        return ProviderReportSerializer(scan_reports(obj), many=True).data

    @extend_schema_field(serializers.ListField(child=serializers.CharField()))
    def get_approval_blockers(self, obj):
        return approval_blockers(obj, obj.review_file, latest_scan(obj), obj.prohibited_matches.select_related("rule"))

    class Meta(SoftwareRequestDetailSerializer.Meta):
        fields = SoftwareRequestDetailSerializer.Meta.fields + (
            "file", "scan", "reports", "prohibited_matches", "approval_blockers", "decided_by",
        )


class RequestReprocessSerializer(serializers.Serializer):
    pass
