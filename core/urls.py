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
    path('stop_scan/<int:report_id>/', views.stop_scan, name="stop_scan"),
    path('ajax_data/,', views.get_scans_data, name="ajax_data"),
    path('ajax_data_chats/<str:selected_username>/,', views.ajax_data_chats, name="ajax_data_chats"),
    path('webscan/', views.webscan, name="webscan"),
    path('waf_enumeration/', views.waf_enumeration, name="waf_enumeration"),
    path('my_workspaces/', views.my_workspaces, name="my_workspaces"),
    path('delete_workspace/<int:space_id>/', views.delete_workspace, name='delete_workspace'),
    path('workspace/<int:space_id>/', views.edit_workspace, name='workspace'),
    path('incident_investigate/', views.network_forensics, name="network_forensics"),
    path('view_workspace/<int:space_id>/', views.view_workspace, name='view_workspace'),
    path('chat/<str:username>/', views.chat_page, name='chat'),
    path('search/', views.search_users, name='search_users'),
    path('friend-requests/', views.friend_requests, name='friend_requests'),
    path('search/', views.search_users, name='search_users'),
    path('send-friend-request/<int:to_user_id>/', views.send_friend_request, name='send_friend_request'),
    path('accept-friend-request/<int:request_id>/', views.accept_friend_request, name='accept_friend_request'),
    path('reject-friend-request/<int:request_id>/', views.reject_friend_request, name='reject_friend_request'),
    path('accepted-users/', views.accepted_users, name='accepted_users'),

    
    

    
    # path('export/<int:report_id>/', views.export, name='export'),
]