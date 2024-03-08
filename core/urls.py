from django.urls import path,include
from . import views


urlpatterns = [
    path('', views.home, name="home"),
    path('', views.dashboard),
    path('login/', views.user_login, name="login"),
    path('register/', views.register, name="register"),
    path('forget_password/', views.forget_password, name="forget_password"),
    path('dashboard/', views.dashboard, name="dashboard"),
    path('logout/', views.user_logout, name="logout"),
    path('network_scan/', views.network_scan, name="network_scan"),
    path('host_discovery/', views.host_discover, name="host_discovery"),
    path('myscans/', views.myreports, name="myscans"),
    path('sharedscans/', views.sharedreports, name="sharedscans"),
    path('setting/', views.setting, name="setting"),
    path('delete_account/', views.delete_account, name='delete_account'),
    path('report/<int:report_id>/', views.scan_report, name='report'),
    path('delete_report/<int:report_id>/', views.delete_report, name='delete_report'),
    path('ajax_data/,', views.get_scans_data, name="ajax_data")
    # path('export/<int:report_id>/', views.export, name='export'),
]