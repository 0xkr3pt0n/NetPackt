from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .forms import SignupForm
from django.contrib.auth import logout
from django.contrib import messages
from django.contrib.auth.models import User

def signup(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)

        if form.is_valid():
            form.save()
            return redirect('/login/')
            
        else:
            messages.error(request, 'Invalid, check requirement fields.')

    else:
        form = SignupForm()

    return render(request, 'core/register.html', {'form': form})

@login_required(login_url='/login/')
def user_logout(request):
    logout(request)
    return redirect('/login/')

@login_required
def home(request):
    return render(request, 'core/index.html')

@login_required(login_url='/login/')
def scans(request):
    return render(request, "core/scans.html")

@login_required(login_url='/login/')
def soon(request):
    return render(request, "core/soon.html")

