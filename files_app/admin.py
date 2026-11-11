import re

from django import forms
from django.contrib import admin

from accounts.admin_base import ReadOnlyModelAdmin

from .models import (
    FileSource,
    FileTypePolicy,
    StoredFile,
    DownloadsPolicy,
    ProtectedDownloadRule,
    ProhibitedSoftwareRule,
    ProhibitedSoftwareMatch,
)


@admin.register(FileSource)
class FileSourceAdmin(ReadOnlyModelAdmin):
    list_display = (
        "id",
        "request",
        "source_type",
        "status",
        "domain",
        "created_at",
    )

    list_filter = (
        "source_type",
        "status",
        "created_at",
    )

    search_fields = (
        "original_url",
        "final_url",
        "domain",
    )

    readonly_fields = (
        "created_at",
        "updated_at",
    )


@admin.register(StoredFile)
class StoredFileAdmin(ReadOnlyModelAdmin):
    list_display = (
        "id",
        "request",
        "original_filename",
        "storage_zone",
        "is_available",
        "size_bytes",
        "created_at",
    )

    list_filter = (
        "storage_zone",
        "is_available",
        "created_at",
    )

    search_fields = (
        "original_filename",
        "stored_filename",
        "file_hash_sha256",
        "extension",
        "mime_type",
    )

    readonly_fields = (
        "created_at",
        "deleted_at",
    )


@admin.register(FileTypePolicy)
class FileTypePolicyAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "extension",
        "mime_type",
        "is_allowed",
        "requires_unpacking",
        "requires_sandbox",
        "requires_manual_review",
        "max_size_mb",
    )

    list_filter = (
        "is_allowed",
        "requires_unpacking",
        "requires_sandbox",
        "requires_manual_review",
    )

    search_fields = (
        "extension",
        "mime_type",
        "description",
    )


@admin.register(DownloadsPolicy)
class DownloadPolicyAdmin(admin.ModelAdmin):
    exclude = ("allow_file_scheme", "allow_url_credentials", "allowed_file_hosts", "blocked_file_hosts", "allowed_file_base_paths")
    list_display = (
        "id",
        "name",
        "is_active",
        "allow_http",
        "allow_https",
        "allow_private_networks",
        "max_file_size_mb",
        "max_redirects",
    )

    list_filter = (
        "is_active",
        "allow_http",
        "allow_https",
        "allow_private_networks",
    )

    search_fields = (
        "name",
    )

    readonly_fields = (
        "created_at",
        "updated_at",
    )


@admin.register(ProtectedDownloadRule)
class ProtectedDownloadRuleAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "name",
        "is_active",
        "scheme",
        "host_pattern",
        "credentials_mode",
        "created_at",
    )

    list_filter = (
        "is_active",
        "scheme",
        "credentials_mode",
    )

    search_fields = (
        "name",
        "host_pattern",
        "reason",
    )

    readonly_fields = (
        "created_at",
        "updated_at",
    )

    def has_view_permission(self, request, obj=None):
        return request.user.is_superuser

    def has_add_permission(self, request):
        return request.user.is_superuser

    def has_change_permission(self, request, obj=None):
        return request.user.is_superuser

    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser


class ProhibitedRuleForm(forms.ModelForm):
    def clean(self):
        data = super().clean()
        pattern = data.get("pattern", "")
        if pattern and data.get("match_type") == ProhibitedSoftwareRule.MatchType.REGEX:
            try:
                re.compile(pattern)
            except re.error:
                self.add_error("pattern", "Проверьте синтаксис регулярного выражения.")
        return data


@admin.register(ProhibitedSoftwareRule)
class ProhibitedSoftwareRuleAdmin(admin.ModelAdmin):
    form = ProhibitedRuleForm
    list_display = (
        "id",
        "name",
        "is_active",
        "match_type",
        "target_field",
        "pattern",
        "requires_security_confirmation",
        "allow_security_override",
    )

    list_filter = (
        "is_active",
        "match_type",
        "target_field",
        "requires_security_confirmation",
        "allow_security_override",
    )

    search_fields = (
        "name",
        "pattern",
        "reason",
    )

    readonly_fields = (
        "created_at",
        "updated_at",
    )


@admin.register(ProhibitedSoftwareMatch)
class ProhibitedSoftwareMatchAdmin(ReadOnlyModelAdmin):
    list_display = (
        "id",
        "request",
        "rule",
        "matched_field",
        "is_overridden",
        "overridden_by",
        "created_at",
    )

    list_filter = (
        "is_overridden",
        "matched_field",
        "created_at",
    )

    search_fields = (
        "request__source_url",
        "rule__name",
        "matched_value",
    )

    readonly_fields = (
        "created_at",
        "overridden_at",
    )
