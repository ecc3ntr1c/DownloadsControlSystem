from typing import Any

from .models import AuditLog


class AuditService:
    """
    Сервис для записи событий аудита.

    Через него будут писать события:
    - пользователи;
    - сотрудники ИБ;
    - worker-процессы;
    - внешние системы;
    - сама система.
    """

    @staticmethod
    def log(
        *,
        action: str,
        actor=None,
        actor_type: str = AuditLog.ActorType.SYSTEM,
        object_type: str = "",
        object_id: str = "",
        ip_address: str | None = None,
        user_agent: str = "",
        details: dict[str, Any] | None = None,
    ) -> AuditLog:
        return AuditLog.objects.create(
            actor=actor,
            actor_type=actor_type,
            action=action,
            object_type=object_type,
            object_id=str(object_id) if object_id else "",
            ip_address=ip_address,
            user_agent=user_agent,
            details=details or {},
        )