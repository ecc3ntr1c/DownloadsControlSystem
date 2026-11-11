from django.db import migrations


def keep_clamav_enabled(apps, schema_editor):
    providers = apps.get_model("scanning", "AntivirusProvider").objects.using(schema_editor.connection.alias)
    providers.get_or_create(name="ClamAV", defaults={"kind": "CLAMAV", "enabled": True})


class Migration(migrations.Migration):
    dependencies = [("scanning", "0003_alter_scanresult_provider_antivirusprovider_and_more")]
    operations = [migrations.RunPython(keep_clamav_enabled, migrations.RunPython.noop)]
