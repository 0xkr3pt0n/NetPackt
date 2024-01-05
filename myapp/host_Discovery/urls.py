from django.urls import path
from . import views

urlpatterns = [
    path('discover/', views.scan_network, name='discover'),
]