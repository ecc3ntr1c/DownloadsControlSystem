"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path

from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularSwaggerView,
)

from files_app.views import download_approved_file
from notifications import views as notifications
from requests_app import web

urlpatterns = [
    path("", web.my_requests, name="portal-requests"),
    path("login/", auth_views.LoginView.as_view(), name="login"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("requests/new/", web.create_request, name="portal-create"),
    path("requests/<int:pk>/", web.request_detail, name="portal-request"),
    path("security/", web.security_requests, name="portal-security"),
    path("security/<int:pk>/", web.security_detail, name="portal-security-request"),
    path("security/<int:pk>/<str:action>/", web.security_action, name="portal-security-action"),
    path("notifications/", notifications.inbox, name="notification-inbox"),
    path("notifications/read/", notifications.mark_all_read, name="notifications-read"),
    path("downloads/<int:pk>/", download_approved_file, name="approved-file-download"),
    path("admin/", admin.site.urls),
    path("api-auth/", include("rest_framework.urls")),

    path("api/v1/requests/", include("requests_app.urls")),
    path("api/v1/security/requests/", include("requests_app.security_urls")),

    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path(
        "api/docs/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger-ui",
    ),
]
