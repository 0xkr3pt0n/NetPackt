from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .forms import SignupForm
from django.contrib.auth import logout
from django.contrib import messages


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

def user_logout(request):
    logout(request)
    return redirect('/login/')

@login_required
def home(request):
    return render(request, 'core/index.html')


def new_scan(requesr):
    return render(requesr, "core/networkscan.html")

