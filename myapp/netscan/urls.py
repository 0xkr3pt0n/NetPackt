from django.urls import path,include
from . import views

urlpatterns = [
    path('scan/', views.networkscanning, name="scan"),
    path('scans/', views.scans, name="scans"),
    path('report/<int:report_id>/', views.report, name="report_detils"),
]
