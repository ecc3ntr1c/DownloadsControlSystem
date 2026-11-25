from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.urls import reverse


@override_settings(DEMO_NAME_LOGIN=True, LOGIN_URL="portal-entry", LOGOUT_REDIRECT_URL="portal-entry")
class DemoNameLoginTests(TestCase):
    def test_name_never_selects_an_existing_account(self):
        users = get_user_model().objects
        admin = users.create_superuser("admin", password="admin-test-password")
        browser = Client(enforce_csrf_checks=True)
        entry = reverse("portal-entry")
        self.assertRedirects(browser.get("/requests/new/"), f"{entry}?next=/requests/new/")
        self.assertEqual(browser.post(entry, {"name": "admin"}).status_code, 403)
        self.assertRedirects(browser.post(entry, {
            "name": " admin ", "next": "/requests/new/",
            "csrfmiddlewaretoken": browser.cookies["csrftoken"].value,
        }), "/requests/new/")

        user = users.get(pk=browser.session["_auth_user_id"])
        self.assertNotEqual(user.pk, admin.pk)
        self.assertEqual(user.get_full_name(), "admin")
        self.assertFalse(user.has_usable_password())
        self.assertFalse(user.is_staff)
        self.assertEqual(browser.get("/security/").status_code, 403)
        self.assertContains(browser.get("/"), "admin")

        other_browser = Client()
        self.assertRedirects(other_browser.post(entry, {"name": "admin"}), "/")
        self.assertNotEqual(other_browser.session["_auth_user_id"], browser.session["_auth_user_id"])
        self.assertRedirects(browser.post(reverse("logout"), {
            "csrfmiddlewaretoken": browser.cookies["csrftoken"].value,
        }), entry)
        self.assertNotIn("_auth_user_id", browser.session)

    def test_invalid_name_and_external_redirect(self):
        entry = reverse("portal-entry")
        for name in ("   ", "x" * 151, "имя\u202e"):
            with self.subTest(name=name):
                self.assertEqual(self.client.post(entry, {"name": name}).status_code, 200)
                self.assertFalse(get_user_model().objects.exists())
        self.assertRedirects(self.client.post(entry, {"name": "Иван", "next": "https://example.org/"}), "/")

    @override_settings(DEMO_NAME_LOGIN=False)
    def test_disabled_entry_redirects_to_password_login_without_creating_user(self):
        response = self.client.post(reverse("portal-entry"), {"name": "Иван", "next": "/requests/new/"})
        self.assertRedirects(response, reverse("login", query={"next": "/requests/new/"}))
        self.assertFalse(get_user_model().objects.exists())
