from django.db import migrations


def seed_default_policy(apps, schema_editor):
    policy = apps.get_model("files_app", "DownloadsPolicy")
    policies = policy.objects.using(schema_editor.connection.alias)
    if not policies.exists():
        policies.create(
            name="Базовая политика HTTP/HTTPS",
            is_active=True,
            allowed_ports=[80, 443],
            max_file_size_mb=50,
        )


class Migration(migrations.Migration):
    dependencies = [("files_app", "0004_alter_storedfile_storage_zone")]

    operations = [migrations.RunPython(seed_default_policy, migrations.RunPython.noop)]
