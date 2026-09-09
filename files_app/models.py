from django.db import models

from requests_app.models import SoftwareRequest


class FileSource(models.Model):
    """
    Источник файла: обычная HTTP-ссылка, Яндекс.Диск,
    ручная загрузка или другой будущий источник.
    """

    class SourceType(models.TextChoices):
        HTTP = "HTTP", "HTTP/HTTPS"
        YANDEX_DISK = "YANDEX_DISK", "Яндекс Диск"
        MANUAL_UPLOAD = "MANUAL_UPLOAD", "Ручная загрузка"
        UNKNOWN = "UNKNOWN", "Неизвестно"

    class SourceStatus(models.TextChoices):
        CREATED = "CREATED", "Создан"
        VALIDATING = "VALIDATING", "Проверяется"
        VALID = "VALID", "Валиден"
        INVALID = "INVALID", "Невалиден"
        DOWNLOAD_STARTED = "DOWNLOAD_STARTED", "Скачивание начато"
        DOWNLOADED = "DOWNLOADED", "Скачан"
        FAILED = "FAILED", "Ошибка"

    request = models.ForeignKey(
        SoftwareRequest,
        on_delete=models.CASCADE,
        related_name="file_sources",
        verbose_name="Заявка",
    )

    original_url = models.URLField(
        max_length=2048,
        verbose_name="Исходная ссылка",
    )

    final_url = models.URLField(
        max_length=4096,
        blank=True,
        verbose_name="Финальная ссылка после редиректов",
    )

    source_type = models.CharField(
        max_length=32,
        choices=SourceType.choices,
        default=SourceType.UNKNOWN,
        verbose_name="Тип источника",
    )

    status = models.CharField(
        max_length=32,
        choices=SourceStatus.choices,
        default=SourceStatus.CREATED,
        verbose_name="Статус источника",
    )

    domain = models.CharField(
        max_length=255,
        blank=True,
        verbose_name="Домен",
    )

    error_message = models.TextField(
        blank=True,
        verbose_name="Ошибка",
    )

    metadata = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Метаданные источника",
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Дата создания",
    )

    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name="Дата обновления",
    )

    class Meta:
        verbose_name = "Источник файла"
        verbose_name_plural = "Источники файлов"

    def __str__(self):
        return f"{self.source_type}: {self.original_url}"


class StoredFile(models.Model):
    """
    Физически скачанный и сохранённый файл.
    """

    class StorageZone(models.TextChoices):
        PENDING = "PENDING", "Ожидает проверки"
        QUARANTINE = "QUARANTINE", "Карантин"
        APPROVED = "APPROVED", "Разрешён"
        REJECTED = "REJECTED", "Отклонён"
        DELETED = "DELETED", "Удалён"

    request = models.ForeignKey(
        SoftwareRequest,
        on_delete=models.CASCADE,
        related_name="files",
        verbose_name="Заявка",
    )

    source = models.ForeignKey(
        FileSource,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="stored_files",
        verbose_name="Источник файла",
    )

    original_filename = models.CharField(
        max_length=255,
        verbose_name="Исходное имя файла",
    )

    stored_filename = models.CharField(
        max_length=255,
        verbose_name="Внутреннее имя файла",
    )

    file_hash_sha256 = models.CharField(
        max_length=64,
        blank=True,
        db_index=True,
        verbose_name="SHA-256",
    )

    mime_type = models.CharField(
        max_length=128,
        blank=True,
        verbose_name="MIME-тип",
    )

    extension = models.CharField(
        max_length=32,
        blank=True,
        verbose_name="Расширение файла",
    )

    size_bytes = models.BigIntegerField(
        default=0,
        verbose_name="Размер в байтах",
    )

    storage_path = models.TextField(
        verbose_name="Путь хранения",
    )

    storage_zone = models.CharField(
        max_length=32,
        choices=StorageZone.choices,
        default=StorageZone.PENDING,
        verbose_name="Зона хранения",
    )

    is_available = models.BooleanField(
        default=False,
        verbose_name="Доступен для скачивания",
    )

    download_count = models.PositiveIntegerField(
        default=0,
        verbose_name="Количество скачиваний",
    )

    delete_after = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Удалить после",
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Дата создания",
    )

    deleted_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Дата удаления",
    )

    class Meta:
        verbose_name = "Файл"
        verbose_name_plural = "Файлы"

    def __str__(self):
        return self.original_filename


class FileTypePolicy(models.Model):
    """
    Политика обработки разных типов файлов.

    Например:
    .exe — разрешён, требует песочницы;
    .zip — разрешён, требует распаковки;
    .iso — запрещён или требует ручной проверки.
    """

    extension = models.CharField(
        max_length=32,
        db_index=True,
        verbose_name="Расширение",
    )

    mime_type = models.CharField(
        max_length=128,
        blank=True,
        verbose_name="MIME-тип",
    )

    is_allowed = models.BooleanField(
        default=True,
        verbose_name="Разрешён",
    )

    requires_unpacking = models.BooleanField(
        default=False,
        verbose_name="Требует распаковки",
    )

    requires_sandbox = models.BooleanField(
        default=False,
        verbose_name="Требует песочницы",
    )

    requires_manual_review = models.BooleanField(
        default=True,
        verbose_name="Требует ручного решения ИБ",
    )

    max_size_mb = models.PositiveIntegerField(
        default=500,
        verbose_name="Максимальный размер, МБ",
    )

    description = models.CharField(
        max_length=255,
        blank=True,
        verbose_name="Описание",
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Дата создания",
    )

    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name="Дата обновления",
    )

    class Meta:
        verbose_name = "Политика типа файла"
        verbose_name_plural = "Политики типов файлов"
        unique_together = ("extension", "mime_type")

    def __str__(self):
        return f"{self.extension} / {self.mime_type or 'любой MIME'}"