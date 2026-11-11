from django.core.management.base import BaseCommand

from files_app.services.storage import FileStorageService


class Command(BaseCommand):
    help = "Создаёт каталоги закрытого файлового хранилища."

    def handle(self, *args, **options):
        FileStorageService().ensure_structure()
        self.stdout.write(self.style.SUCCESS("Хранилище подготовлено."))
