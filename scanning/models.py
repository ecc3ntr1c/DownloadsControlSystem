from django.db import models
from django.utils import timezone

from files_app.models import StoredFile
from requests_app.models import SoftwareRequest


class ScanResult(models.Model):
    """
    Результат антивирусной проверки.
    """

    class Provider(models.TextChoices):
        CLAMAV = "CLAMAV", "ClamAV"
        HTTP_GATEWAY = "HTTP_GATEWAY", "HTTP-шлюз"
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


class AntivirusProvider(models.Model):
    class Kind(models.TextChoices):
        CLAMAV = "CLAMAV", "ClamAV"
        VIRUSTOTAL = "VIRUSTOTAL", "VirusTotal"
        HTTP_GATEWAY = "HTTP_GATEWAY", "HTTP-шлюз локального антивируса"

    name = models.CharField("Название", max_length=100, unique=True)
    kind = models.CharField("Тип подключения", max_length=32, choices=Kind.choices)
    enabled = models.BooleanField("Включён", default=False)
    endpoint = models.URLField("Базовый URL шлюза", max_length=512, blank=True)
    allow_public_uploads = models.BooleanField("Разрешить отправку файлов в общий набор данных VirusTotal", default=False)
    encrypted_api_key = models.TextField(blank=True, editable=False)

    class Meta:
        verbose_name = "Подключение антивируса"
        verbose_name_plural = "Подключения антивирусов"
        ordering = ("pk",)
        constraints = [models.UniqueConstraint(
            fields=("kind",), condition=models.Q(enabled=True, kind__in=("CLAMAV", "VIRUSTOTAL")),
            name="unique_active_builtin_antivirus",
        )]

    def __str__(self):
        return self.name


class ProviderScan(models.Model):
    file = models.ForeignKey(StoredFile, on_delete=models.CASCADE, related_name="antivirus_checks")
    provider = models.ForeignKey(AntivirusProvider, on_delete=models.PROTECT, related_name="checks")
    provider_name = models.CharField(max_length=100)
    result = models.OneToOneField(ScanResult, on_delete=models.SET_NULL, null=True, blank=True)
    remote_id = models.CharField(max_length=255, blank=True)
    submitting = models.BooleanField(default=False)
    failures = models.PositiveSmallIntegerField(default=0)
    last_error = models.CharField(max_length=512, blank=True)
    next_check_at = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("pk",)
        constraints = [models.UniqueConstraint(fields=("file", "provider"), name="unique_antivirus_per_file")]
