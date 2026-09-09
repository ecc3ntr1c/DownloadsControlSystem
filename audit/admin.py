from django.contrib import admin

from .models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "actor",
        "actor_type",
        "action",
        "object_type",
        "object_id",
        "created_at",
    )

    list_filter = (
        "actor_type",
        "action",
        "created_at",
    )

    search_fields = (
        "action",
        "object_type",
        "object_id",
    )

    readonly_fields = (
        "created_at",
    )