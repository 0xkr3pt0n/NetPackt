from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.shortcuts import render,redirect
from .forms import LoginForm,SignupForm
from django.contrib.auth.models import User

# Create your views here.

def user_login(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            messages.error(request, 'Username or password is not correct')
    else:
        form = LoginForm()
    return render(request, 'core/login.html', {'form':form})

def register(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)

        if form.is_valid():
            username = form.cleaned_data.get('username')
            if User.objects.filter(username=username).exists():
                messages.error(request, 'Username already exists.')
            else:
                form.save()
                messages.success(request, 'Account created successfully.')
                return redirect('login')
        else:
            messages.error(request, 'Invalid information !')
    else:
        form = SignupForm()
    return render(request, 'core/register.html', {'form': form})

@login_required(login_url='/login/')
def user_logout(request):
    logout(request)
    return redirect('/login/')

def forget_password(request):
    return render(request, 'core/forget_password.html')

@login_required(login_url='/login/')
def dashboard(request):
    return render(request, 'core/dashboard.html')

@login_required(login_url='/login/')
def network_scan(request):
    return render(request, 'core/networkscan.html')

@login_required(login_url='/login/')
def host_discovery(request):
    return render(request, 'core/hostdiscovery.html')

@login_required(login_url='/login/')
def settings(request):
    return render(request, 'core/settings.html')