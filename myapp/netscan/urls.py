from django.urls import path,include
from . import views
urlpatterns = [
    path('scan/', views.networkscanning, name="scan"),
    
]
