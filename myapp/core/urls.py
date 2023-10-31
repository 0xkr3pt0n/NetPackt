from django.urls import path,include
from django.contrib.auth import views as auth_views
from . import views
from .forms import LoginForm

urlpatterns = [
    path('', auth_views.LoginView.as_view(template_name='core/login.html', authentication_form=LoginForm), name='login' ),
    path('register/', views.signup, name="register"),
    path('login/', auth_views.LoginView.as_view(template_name='core/login.html', authentication_form=LoginForm), name='login'),
    path('home/', views.home, name="home"),
    path('logout/', views.user_logout, name='logout'),
    path('scan/', views.new_scan, name="scan"),
    path('password_reset/',auth_views.PasswordResetView.as_view(template_name='core/reset.html'),name='password_reset'),
    path('password_reset/done/',auth_views.PasswordResetDoneView.as_view(template_name='core/resetdone.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/',auth_views.PasswordResetConfirmView.as_view(template_name='core/passwordset.html'),name='password_reset_confirm'),
    path('reset/done/',auth_views.PasswordResetCompleteView.as_view(template_name='core/reset_complete.html'),name='password_reset_complete'),

]
