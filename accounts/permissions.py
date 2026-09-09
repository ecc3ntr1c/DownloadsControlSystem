from rest_framework.permissions import BasePermission

from accounts.roles import (
    APPROVE_SOFTWARE_REQUEST_PERMISSION,
    REJECT_SOFTWARE_REQUEST_PERMISSION,
    VIEW_SECURITY_REQUESTS_PERMISSION,
)


def user_has_permission(user, permission_name: str) -> bool:
    """
    Безопасная проверка Django permission.

    user.has_perm(...) сам учитывает:
    - права пользователя;
    - права через группы;
    - superuser;
    - backend авторизации.
    """

    if not user or not user.is_authenticated:
        return False

    return user.has_perm(permission_name)


class CanViewSecurityRequests(BasePermission):
    """
    Доступ к списку/карточкам заявок со стороны ИБ.
    """

    message = "You do not have permission to view security requests."

    def has_permission(self, request, view):
        return user_has_permission(
            request.user,
            VIEW_SECURITY_REQUESTS_PERMISSION,
        )


class CanApproveSoftwareRequest(BasePermission):
    """
    Право согласовывать заявки.
    """

    message = "You do not have permission to approve software requests."

    def has_permission(self, request, view):
        return user_has_permission(
            request.user,
            APPROVE_SOFTWARE_REQUEST_PERMISSION,
        )


class CanRejectSoftwareRequest(BasePermission):
    """
    Право отклонять заявки.
    """

    message = "You do not have permission to reject software requests."

    def has_permission(self, request, view):
        return user_has_permission(
            request.user,
            REJECT_SOFTWARE_REQUEST_PERMISSION,
        )


class IsRequestOwner(BasePermission):
    """
    Доступ только владельцу заявки.
    """

    message = "Only request owner can access this object."

    def has_object_permission(self, request, view, obj):
        return obj.user_id == request.user.id


class IsRequestOwnerOrCanViewSecurityRequests(BasePermission):
    """
    Доступ владельцу заявки или пользователю с правом ИБ на просмотр заявок.
    """

    message = "Only request owner or security officer can access this object."

    def has_object_permission(self, request, view, obj):
        if obj.user_id == request.user.id:
            return True

        return user_has_permission(
            request.user,
            VIEW_SECURITY_REQUESTS_PERMISSION,
        )