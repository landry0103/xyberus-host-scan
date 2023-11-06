from django.contrib import admin
from django.urls import path, include
from rest_framework.authtoken.views import obtain_auth_token
from . import views
from .views import scan_configuration

urlpatterns = [
    path('admin/', admin.site.urls),
    path("", views.HomeView.as_view(), name="home"),
    path("targets/", views.TargetView.as_view(), name="targets"),
    path("scan/", views.ScanView.as_view(), name="scan"),
    path("pricing/", views.PricingView.as_view(), name="pricing"),
    path("dashboard", views.DashboardView.as_view(), name="dashboard"),
    path("dashboard/", include("dashboard.urls")),
    path("login/", views.LoginView.as_view(), name="login"),
    path("signup/", views.SignupView.as_view(), name="signup"),
    path("user/", include('extra_user_info.urls')),
    path("", include("allauth.urls")),
    path("logout", views.google_logout, name="logout"),

    # Scan Configuration API
    path('api/scan-configuration/', scan_configuration, name='scan_configuration'),
]
