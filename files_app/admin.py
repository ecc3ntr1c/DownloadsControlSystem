from django.contrib import admin

from .models import FileSource, FileTypePolicy, StoredFile


@admin.register(FileSource)
class FileSourceAdmin(admin.ModelAdmin):
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
class StoredFileAdmin(admin.ModelAdmin):
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