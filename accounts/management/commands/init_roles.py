from django.contrib.auth.models import Group, Permission
from django.core.management.base import BaseCommand

from accounts.roles import (
    SOFTWARE_CONTROL_ADMINS_GROUP,
    SOFTWARE_CONTROL_SECURITY_GROUP,
    SOFTWARE_CONTROL_USERS_GROUP,
)


class Command(BaseCommand):
    help = "Create default Software Control groups and permissions"

    def handle(self, *args, **options):
        users_group, _ = Group.objects.get_or_create(
            name=SOFTWARE_CONTROL_USERS_GROUP
        )
        security_group, _ = Group.objects.get_or_create(
            name=SOFTWARE_CONTROL_SECURITY_GROUP
        )
        admins_group, _ = Group.objects.get_or_create(
            name=SOFTWARE_CONTROL_ADMINS_GROUP
        )

        security_permissions = Permission.objects.filter(
            content_type__app_label="requests_app",
            codename__in=[
                "view_security_requests",
                "approve_software_request",
                "reject_software_request",
            ],
        )

        security_group.permissions.add(*security_permissions)
        admins_group.permissions.add(*security_permissions)

        self.stdout.write(
            self.style.SUCCESS("Software Control groups initialized")
        )