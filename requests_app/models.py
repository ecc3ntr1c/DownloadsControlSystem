from django.conf import settings
from django.db import models


class SoftwareRequest(models.Model):
    """
    Основная модель заявки на загрузку и проверку стороннего ПО.
    """

    class RequestStatus(models.TextChoices):
        CREATED = "CREATED", "Создана"
        UNDER_SECURITY_REVIEW = "UNDER_SECURITY_REVIEW", "На рассмотрении ИБ"
        WAITING_SECURITY_DECISION = "WAITING_SECURITY_DECISION", "Ожидает решения ИБ"
        APPROVED = "APPROVED", "Согласована ИБ"
        REJECTED = "REJECTED", "Отказана ИБ"
        AVAILABLE_FOR_DOWNLOAD = "AVAILABLE_FOR_DOWNLOAD", "Доступна для скачивания"
        DOWNLOADED = "DOWNLOADED", "Файл выдан пользователю"
        CLOSED = "CLOSED", "Закрыта"

    class ScanStatus(models.TextChoices):
        PENDING = "PENDING", "Ожидает обработки"
        URL_VALIDATION = "URL_VALIDATION", "Проверка URL"
        DOWNLOADING = "DOWNLOADING", "Скачивание файла"
        DOWNLOADED = "DOWNLOADED", "Файл скачан"
        SCANNING = "SCANNING", "Антивирусная проверка"
        SCAN_COMPLETED = "SCAN_COMPLETED", "Проверка завершена"
        SCAN_FAILED = "SCAN_FAILED", "Проверка не выполнена"
        CANCELLED = "CANCELLED", "Отменена"
        COMPLETED_AFTER_REJECTION = "COMPLETED_AFTER_REJECTION", "Завершена после отказа"

    class RiskLevel(models.TextChoices):
        UNKNOWN = "UNKNOWN", "Неизвестно"
        LOW = "LOW", "Низкий"
        MEDIUM = "MEDIUM", "Средний"
        HIGH = "HIGH", "Высокий"
        CRITICAL = "CRITICAL", "Критический"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="software_requests",
        verbose_name="Пользователь",
    )

    source_url = models.URLField(
        max_length=2048,
        verbose_name="Ссылка на ПО",
    )

    description = models.TextField(
        verbose_name="Описание ПО",
    )

    business_reason = models.TextField(
        verbose_name="Обоснование необходимости",
    )

    request_status = models.CharField(
        max_length=64,
        choices=RequestStatus.choices,
        default=RequestStatus.CREATED,
        verbose_name="Статус заявки",
    )

    scan_status = models.CharField(
        max_length=64,
        choices=ScanStatus.choices,
        default=ScanStatus.PENDING,
        verbose_name="Статус автоматической проверки",
    )

    risk_level = models.CharField(
        max_length=32,
        choices=RiskLevel.choices,
        default=RiskLevel.UNKNOWN,
        verbose_name="Уровень риска",
    )

    security_comment = models.TextField(
        blank=True,
        verbose_name="Комментарий ИБ",
    )

    external_system = models.CharField(
        max_length=64,
        blank=True,
        verbose_name="Внешняя система",
    )

    external_request_id = models.CharField(
        max_length=128,
        blank=True,
        verbose_name="ID заявки во внешней системе",
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Дата создания",
    )

    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name="Дата обновления",
    )

    closed_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Дата закрытия",
    )

    class Meta:
        verbose_name = "Заявка на ПО"
        verbose_name_plural = "Заявки на ПО"
        ordering = ["-created_at"]
        permissions = [
            (
                "view_security_requests",
                "Can view requests as security officer",
            ),
            (
                "approve_software_request",
                "Can approve software request",
            ),
            (
                "reject_software_request",
                "Can reject software request",
            ),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["external_system", "external_request_id"],
                name="unique_external_request",
                condition=~models.Q(external_system="")
                          & ~models.Q(external_request_id=""),
            )
        ]

    def __str__(self):
        return f"Заявка #{self.id} от {self.user}"