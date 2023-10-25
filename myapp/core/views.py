from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .forms import SignupForm
from django.contrib.auth import logout

def signup(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)

        if form.is_valid():
            
            form.save()

            return redirect('/login/')
    else:
        form = SignupForm()

    return render(request, 'core/register.html', {
        'form': form
    })
def signup(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)

        if form.is_valid():
            
            form.save()

            return redirect('/login/')
    else:
        form = SignupForm()

    return render(request, 'core/register.html', {
        'form': form
    })


@login_required
def home(request):
    return render(request, 'core/index.html')

def user_logout(request):
    logout(request)
    return redirect('/login/')