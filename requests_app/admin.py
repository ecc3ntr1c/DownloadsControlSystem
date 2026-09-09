from django.contrib import admin

from .models import SoftwareRequest


@admin.register(SoftwareRequest)
class SoftwareRequestAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "request_status",
        "scan_status",
        "risk_level",
        "created_at",
    )

    list_filter = (
        "request_status",
        "scan_status",
        "risk_level",
        "created_at",
    )

    search_fields = (
        "source_url",
        "description",
        "business_reason",
        "external_system",
        "external_request_id",
    )

    readonly_fields = (
        "created_at",
        "updated_at",
        "closed_at",
    )