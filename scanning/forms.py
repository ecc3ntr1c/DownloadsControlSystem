import re

from django import forms

from .contracts import ScannerError
from .credentials import encrypt_api_key
from .models import AntivirusProvider
from .remote import gateway_endpoint


class AntivirusProviderForm(forms.ModelForm):
    api_key = forms.CharField(
        label="Ключ API или Bearer-токен", max_length=512, required=False,
        widget=forms.PasswordInput, help_text="Пустое поле сохраняет текущий ключ. Ключ хранится в зашифрованном виде.",
    )
    clear_api_key = forms.BooleanField(label="Удалить сохранённый ключ", required=False)

    class Meta:
        model = AntivirusProvider
        fields = ("name", "kind", "enabled", "endpoint", "allow_public_uploads")
        help_texts = {
            "endpoint": "Для локального антивируса укажи базовый HTTPS-адрес его шлюза.",
            "allow_public_uploads": (
                "Обычная отправка в VirusTotal добавляет файл в общий набор данных. "
                "Бесплатный Public API предназначен для некоммерческого использования. "
                "Для рабочего процесса компании нужен подходящий договор."
            ),
        }

    def clean(self):
        data = super().clean()
        kind = data.get("kind", self.instance.kind)
        endpoint = data.get("endpoint", self.instance.endpoint)
        key = data.get("api_key", "")
        clear = data.get("clear_api_key", False)
        encrypted = self.instance.encrypted_api_key
        if key and clear:
            self.add_error("api_key", "Выбери замену или удаление ключа.")
        if clear:
            encrypted = ""
        if key:
            if not re.fullmatch(r"[!-~]+", key):
                self.add_error("api_key", "Ключ должен состоять из печатных ASCII-символов без пробелов.")
            else:
                try:
                    encrypted = encrypt_api_key(key)
                except ScannerError as exc:
                    self.add_error("api_key", str(exc))
        if self.instance.pk and encrypted and not key and (kind, endpoint) != (self.instance.kind, self.instance.endpoint):
            self.add_error("api_key", "При смене адреса или типа введи новый ключ либо удали прежний.")
        if kind == AntivirusProvider.Kind.HTTP_GATEWAY:
            try:
                data["endpoint"] = gateway_endpoint(endpoint)
            except ScannerError as exc:
                self.add_error("endpoint", str(exc))
        elif endpoint:
            self.add_error("endpoint", "Свой адрес можно указать для HTTP-шлюза.")
        if kind == AntivirusProvider.Kind.VIRUSTOTAL and data.get("enabled"):
            if not encrypted:
                self.add_error("api_key", "Введи ключ VirusTotal.")
            if not data.get("allow_public_uploads"):
                self.add_error("allow_public_uploads", "Подтверди разрешение на отправку публичных файлов.")
        self.encrypted_key = encrypted
        return data

    def save(self, commit=True):
        provider = super().save(commit=False)
        provider.encrypted_api_key = self.encrypted_key
        if commit:
            provider.save()
        return provider
