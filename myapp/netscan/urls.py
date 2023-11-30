from django.urls import path,include
from . import views

urlpatterns = [
    path('scans/', views.scans, name="scans"),
    path('report/<int:report_id>/', views.report, name="report_detils"),
]
