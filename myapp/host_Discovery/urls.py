from django.urls import path,include
from . import views

urlpatterns = [
    path('scan/', views.scan_network, name='scan_network'),
]