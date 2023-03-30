"""djangoALPC URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
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
from django.urls import re_path, path
from django.contrib.auth.decorators import login_required
from website import views


urlpatterns = [
    path('', views.hello, name='hello'),
    path('hello/', views.hello, name='hello'),
    path('accounts/login/', views.login_view, name='login'),
    path('accounts/register/', views.register_view, name='register'),
    path('admin/', admin.site.urls),
    path('start_scan/',  views.start_scan.as_view(), name='start_scan'),
    path('get_scan_result/', views.get_scan_result.as_view(), name='get_scan_result'),
]
