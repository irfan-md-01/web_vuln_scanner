from django.contrib import admin
from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.scan_url, name='scan'),
    path('download/', views.download_report, name='download_report'),
]
