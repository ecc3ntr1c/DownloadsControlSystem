from django import forms

from .source_urls import parse_source_url


class RequestForm(forms.Form):
    source_url = forms.CharField(label="Прямая ссылка на файл", max_length=2048, widget=forms.URLInput)
    description = forms.CharField(label="Название и описание ПО", max_length=4000, widget=forms.Textarea(attrs={"rows": 3}))
    business_reason = forms.CharField(label="Для какой задачи нужно ПО", max_length=4000, widget=forms.Textarea(attrs={"rows": 3}))

    def clean_source_url(self):
        try:
            return parse_source_url(self.cleaned_data["source_url"]).geturl()
        except ValueError as exc:
            raise forms.ValidationError(str(exc)) from exc


class DecisionForm(forms.Form):
    security_comment = forms.CharField(
        label="Комментарий ИБ", required=False, max_length=2000, widget=forms.Textarea(attrs={"rows": 3}),
    )
