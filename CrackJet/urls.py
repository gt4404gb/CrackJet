"""CrackJet URL Configuration

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
    path('accounts/logout/', views.logout_View.as_view(), name='logout'),
    path('admin/', admin.site.urls),
    #path('crackjet/start_scan/',  views.start_scan.as_view(), name='start_scan'),
    #path('crackjet/get_scan_result/', views.get_scan_result.as_view(), name='get_scan_result'),
    path('crackjet/create_project/', views.create_project.as_view(), name='create_project'),
    path('crackjet/search_all_project/', views.search_all_project.as_view(), name='search_all_project'),
    path('crackjet/search_all_website/', views.search_all_website.as_view(), name='search_all_website'),
    path('crackjet/create_scan/', views.create_scan.as_view(), name='create_scan'),
    path('crackjet/scan_status/', views.scan_status.as_view(), name='scan_status'),
]
