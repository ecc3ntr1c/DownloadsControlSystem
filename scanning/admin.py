from django.contrib import admin

from accounts.admin_base import ReadOnlyModelAdmin

from .forms import AntivirusProviderForm
from .models import AntivirusProvider, ScanResult


@admin.register(ScanResult)
class ScanResultAdmin(ReadOnlyModelAdmin):
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


@admin.register(AntivirusProvider)
class AntivirusProviderAdmin(admin.ModelAdmin):
    form = AntivirusProviderForm
    list_display = ("name", "kind", "enabled", "key_configured")
    list_filter = ("enabled", "kind")
    fields = (
        "name", "kind", "enabled", "endpoint", "allow_public_uploads",
        "key_configured", "api_key", "clear_api_key",
    )
    readonly_fields = ("key_configured",)

    @admin.display(boolean=True, description="Ключ сохранён")
    def key_configured(self, obj):
        return bool(obj and obj.encrypted_api_key)

    def get_readonly_fields(self, request, obj=None):
        if obj:
            return (*self.readonly_fields, "kind", "endpoint")
        return self.readonly_fields

    def has_module_permission(self, request):
        return request.user.is_superuser

    def has_view_permission(self, request, obj=None):
        return request.user.is_superuser

    def has_add_permission(self, request):
        return request.user.is_superuser

    def has_change_permission(self, request, obj=None):
        return request.user.is_superuser

    def has_delete_permission(self, request, obj=None):
        return False
