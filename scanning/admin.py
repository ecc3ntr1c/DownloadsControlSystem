from django.contrib import admin

from .models import ScanResult


@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "request",
        "file",
        "provider",
        "verdict",
        "risk_score",
        "risk_level",
        "created_at",
    )

    list_filter = (
        "provider",
        "verdict",
        "risk_level",
        "created_at",
    )

    search_fields = (
        "request__source_url",
        "file__original_filename",
        "file__file_hash_sha256",
    )

    readonly_fields = (
        "created_at",
    )