from django.db import models

from files_app.models import StoredFile
from requests_app.models import SoftwareRequest


class ScanResult(models.Model):
    """
    Результат антивирусной проверки.
    """

    class Provider(models.TextChoices):
        CLAMAV = "CLAMAV", "ClamAV"
        MOCK = "MOCK", "Mock-провайдер"
        VIRUSTOTAL = "VIRUSTOTAL", "VirusTotal"
        KASPERSKY = "KASPERSKY", "Kaspersky"
        OTHER = "OTHER", "Другой"

    class Verdict(models.TextChoices):
        CLEAN = "CLEAN", "Чистый"
        SUSPICIOUS = "SUSPICIOUS", "Подозрительный"
        MALICIOUS = "MALICIOUS", "Вредоносный"
        UNKNOWN = "UNKNOWN", "Неизвестно"
        FAILED = "FAILED", "Ошибка проверки"

    request = models.ForeignKey(
        SoftwareRequest,
        on_delete=models.CASCADE,
        related_name="scan_results",
        verbose_name="Заявка",
    )

    file = models.ForeignKey(
        StoredFile,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scan_results",
        verbose_name="Файл",
    )

    provider = models.CharField(
        max_length=32,
        choices=Provider.choices,
        default=Provider.CLAMAV,
        verbose_name="Провайдер проверки",
    )

    file_sha256 = models.CharField(max_length=64, blank=True)

    verdict = models.CharField(
        max_length=32,
        choices=Verdict.choices,
        default=Verdict.UNKNOWN,
        verbose_name="Вердикт",
    )

    risk_score = models.PositiveIntegerField(
        default=0,
        verbose_name="Оценка риска",
    )

    risk_level = models.CharField(
        max_length=32,
        default="UNKNOWN",
        verbose_name="Уровень риска",
    )

    raw_result = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Сырой результат",
    )

    normalized_result = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Нормализованный результат",
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Дата проверки",
    )

    class Meta:
        verbose_name = "Результат проверки"
        verbose_name_plural = "Результаты проверок"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.provider}: {self.verdict}"
