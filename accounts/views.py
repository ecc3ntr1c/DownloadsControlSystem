from uuid import uuid4

from django.conf import settings
from django.contrib.auth import get_user_model, login
from django.contrib.auth.views import RedirectURLMixin
from django.http import HttpResponseRedirect
from django.urls import reverse, reverse_lazy
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.generic import FormView

from .forms import DemoNameForm


@method_decorator(never_cache, name="dispatch")
class PortalEntryView(RedirectURLMixin, FormView):
    template_name = "registration/portal_entry.html"
    form_class = DemoNameForm
    next_page = reverse_lazy("portal-requests")

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return HttpResponseRedirect(self.get_success_url())
        if not settings.DEMO_NAME_LOGIN:
            return HttpResponseRedirect(reverse("login", query={"next": self.get_success_url()}))
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        return super().get_context_data(next_url=self.get_redirect_url(), **kwargs)

    def form_valid(self, form):
        # The name is a display label. Ownership is tied to a new user ID.
        user = get_user_model().objects.create_user(
            username=f"demo-{uuid4().hex}",
            first_name=form.cleaned_data["name"],
        )
        login(self.request, user, backend="django.contrib.auth.backends.ModelBackend")
        return HttpResponseRedirect(self.get_success_url())
