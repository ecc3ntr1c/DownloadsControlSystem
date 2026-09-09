from django.conf import settings
from django.db import models


class AuditLog(models.Model):
    """
    Журнал действий пользователей, внешних систем и worker-процессов.
    """

    class ActorType(models.TextChoices):
        USER = "USER", "Пользователь"
        SECURITY = "SECURITY", "Сотрудник ИБ"
        ADMIN = "ADMIN", "Администратор"
        WORKER = "WORKER", "Worker"
        EXTERNAL_SYSTEM = "EXTERNAL_SYSTEM", "Внешняя система"
        SYSTEM = "SYSTEM", "Система"

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs",
        verbose_name="Пользователь",
    )

    actor_type = models.CharField(
        max_length=32,
        choices=ActorType.choices,
        default=ActorType.USER,
        verbose_name="Тип субъекта",
    )

    action = models.CharField(
        max_length=128,
        verbose_name="Действие",
    )

    object_type = models.CharField(
        max_length=128,
        blank=True,
        verbose_name="Тип объекта",
    )

    object_id = models.CharField(
        max_length=128,
        blank=True,
        verbose_name="ID объекта",
    )

    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name="IP-адрес",
    )

    user_agent = models.TextField(
        blank=True,
        verbose_name="User-Agent",
    )

    details = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Детали",
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Дата события",
    )

    class Meta:
        verbose_name = "Событие аудита"
        verbose_name_plural = "Журнал аудита"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.created_at} | {self.action}"