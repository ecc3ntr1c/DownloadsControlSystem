from django.conf import settings
from django.db import models


class Notification(models.Model):
    class Event(models.TextChoices):
        REVIEW_READY = "REVIEW_READY", "Автоматическая обработка завершена. Заявка передана в ИБ."
        APPROVED = "APPROVED", "ИБ разрешила выдачу. Ссылка доступна в заявке."
        REJECTED = "REJECTED", "ИБ отказала в выдаче. Причина указана в заявке."
        EXPIRED = "EXPIRED", "Срок доступа к файлу истёк."

    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    request = models.ForeignKey("requests_app.SoftwareRequest", on_delete=models.CASCADE)
    event = models.CharField(max_length=16, choices=Event.choices)
    created_at = models.DateTimeField(auto_now_add=True)
    read_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at", "-pk")
        indexes = [models.Index(fields=["recipient", "read_at"])]
