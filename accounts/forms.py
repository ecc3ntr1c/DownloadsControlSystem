from django import forms


class DemoNameForm(forms.Form):
    name = forms.CharField(
        label="Ваше имя",
        max_length=150,
        widget=forms.TextInput(attrs={"autocomplete": "name"}),
    )

    def clean_name(self):
        name = " ".join(self.cleaned_data["name"].split())
        if not name.isprintable():
            raise forms.ValidationError("Укажите имя без управляющих символов.")
        return name
