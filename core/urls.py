from django.urls import path,include
from . import views

urlpatterns = [
    path('', views.home, name="home"),
    path('login/', views.user_login, name="login"),
    path('register/', views.register, name="register"),
    path('forget_password/', views.forget_password, name="forget_password"),
    path('dashboard/', views.dashboard, name="dashboard"),
    path('logout/', views.user_logout, name="logout"),
    path('network_scan/', views.network_scan, name="network_scan"),
    path('host_discovery/', views.host_discovery, name="host_discovery"),
    
    path('myscans/', views.myreports, name="myscans"),
    path('sharedscans/', views.sharedreports, name="sharedscans"),
    path('setting/', views.setting, name="setting"),
    path('delete_account/', views.delete_account, name='delete_account'),
]