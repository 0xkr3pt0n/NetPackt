from django.shortcuts import render, redirect
from django.contrib.auth import login
from .forms import RegistrationForm, EmailAuthenticationForm

def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('login')  # Redirect to the login page after successful registration
    else:
        form = RegistrationForm()

    return render(request, 'login/register.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = EmailAuthenticationForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('home')  # Redirect to the home page after successful login
    else:
        form = EmailAuthenticationForm()

    return render(request, 'login/login.html', {'form': form})

def home(request):
    return render(request, 'login/home.html')
