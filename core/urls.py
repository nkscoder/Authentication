from django.conf.urls import include, url
from core import views
from django.views.decorators.csrf import csrf_exempt
from django.urls import path
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.contrib import admin
admin.autodiscover()

urlpatterns = [
    path('', views.index, name='index'),
]
