from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.shortcuts import render,redirect
from .forms import LoginForm,SignupForm
from django.contrib.auth.models import User
from .scan_generator import scan_create
from .vulnerability_scan import vscanner
from .scan_fetcher import fetch_scans
from background_task import background
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
    if request.method == "POST":
        scan_name = request.POST.get('scan_name')
        ip_addr = request.POST.get('ip_addr')
        port_scanType = request.POST.get('portscantype')
        port_rangeType = request.POST.get('portrangetype')
        intrustivity_type = request.POST.get('intrusive_type')
        user_id = request.user.id
        
        #create new scan record in db
        create_scan = scan_create.scan_create()
        scan_id = create_scan.vulnerability_scan(scan_name, ip_addr, user_id)
        
        min_port = 0
        max_port = 0
        #start the vulnerability scan
        if port_rangeType == "0":
            min_port = 1
            max_port = 10
        elif port_rangeType == "1":
            min_port = 1
            max_port = 100
        elif port_rangeType == "2":
            min_port = 1
            max_port = 1000
        else:
            min_port = 1
            max_port = 65535
        
        if port_scanType == "1":
            scan_type = 1
        else:
            scan_type = 2
        
        schedule_vulnerability_scan(scan_id, ip_addr, min_port, max_port, scan_type)
        return redirect('myscans')
    return render(request, 'core/networkscan.html')

@background(schedule=None)  # Execute immediately
def schedule_vulnerability_scan(scan_id, ip_addr, min_port, max_port, scan_type):
    print("start")
    vscanning = vscanner.vulnerability_scanner(ip_addr, min_port, max_port, scan_type, scan_id, 100)
    vscanning.vulnerability_scan()

@login_required(login_url='/login/')
def host_discovery(request):
    return render(request, 'core/hostdiscovery.html')

@login_required(login_url='/login/')
def settings(request):
    return render(request, 'core/settings.html')

@login_required(login_url='/login/')
def myreports(request):
    fs = fetch_scans.scans_fetch()
    data = fs.fetch_scans(request.user.id)
    return render(request, 'core/reports.html', {'data':data})
