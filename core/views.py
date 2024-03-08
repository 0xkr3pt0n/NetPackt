from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.shortcuts import render,redirect
from .forms import LoginForm,SignupForm
from django.contrib.auth.models import User
from .scan_generator import scan_create
from .vulnerability_scan import vscanner
from .scan_fetcher import fetch_scans
from .users_fetcher import users_fetch
from background_task import background
from background_task.models import Task
from .vulnerability_scan import api_database
from .host_discovery import hdisocver

# from .pdf_report import pdf_gen
# Create your views here.

def home(request):
    return render(request, "core/home.html")

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
        custom_portRange = request.POST.get('port_range')
        custom_range = ''
        if custom_portRange == 'on':
            custom_range = request.POST.get('customPortRange')
            
        # print(custom_range)
        user_id = request.user.id
        # preparing shared users ids list
        shared_users_list = []
        req_list = list(request.POST)
        for i in req_list[6:]:
            try:
                shared_users_list.append(int(i))
            except:
                pass
        #create new scan record in db
        create_scan = scan_create.scan_create()
        scan_id = create_scan.vulnerability_scan(scan_name, ip_addr, user_id, shared_users_list)
        
        min_port = 0
        max_port = 0
        #start the vulnerability scan
        
        if port_rangeType == "0" and custom_portRange != 'on' :
            min_port = 1
            max_port = 10
            
        elif port_rangeType == "1" and custom_portRange != 'on':
            min_port = 1
            max_port = 100
        elif port_rangeType == "2" and custom_portRange != 'on':
            min_port = 1
            max_port = 1000
        elif port_rangeType == "3" and custom_portRange != 'on':
            min_port = 1
            max_port = 65535
        elif custom_portRange == 'on':
            start, end = custom_range.split("-")
            min_port = int(start)
            max_port = int(end)
        else:
            print("invalid")
        
        if port_scanType == "1":
            scan_type = 1
        else:
            scan_type = 2
        print(min_port)
        print(max_port)
        schedule_vulnerability_scan(scan_id, ip_addr, min_port, max_port, scan_type, repeat=Task.NEVER)
        return redirect('myscans')
    users = users_fetch.users_fetch()
    users_data = users.get_all_users(request.user.id)
    # print(users_data)
    return render(request, 'core/networkscan.html', {'users':users_data})


@background  # Execute immediately
def schedule_vulnerability_scan(scan_id, ip_addr, min_port, max_port, scan_type):
    print("start")
    vscanning = vscanner.vulnerability_scanner(ip_addr, min_port, max_port, scan_type, scan_id, 100)
    vscanning.vulnerability_scan()

@login_required(login_url='/login/')
def host_discover(request):
    if request.method == "POST":
        scan_name = request.POST.get('scan_name')
        subnet = request.POST.get('subnet')
        ping_option = request.POST.get('ping_option')
        
        create_scan = scan_create.scan_create()
        user_id = request.user.id
        shared_users_list = []
        req_list = list(request.POST)
        for i in req_list:
            try:
                shared_users_list.append(int(i))
            except:
                pass
        scan_id = create_scan.host_discovery(scan_name, subnet, user_id, shared_users_list)
        host_dicovery_scan(scan_id, subnet, ping_option, repeat=Task.NEVER)
        return redirect('myscans')
    users = users_fetch.users_fetch()
    users_data = users.get_all_users(request.user.id)
    return render(request, 'core/hostdiscovery.html', {'users':users_data})

@background
def host_dicovery_scan(scan_id, subnet, ping_option):
    print("start 2")
    hs = hdisocver.hdiscover()
    hs.scan(scan_id, subnet, ping_option)

@login_required(login_url='/login/')
def settings(request):
    return render(request, 'core/settings.html')

@login_required(login_url='/login/')
def myreports(request):
    fs = fetch_scans.scans_fetch()
    data = fs.fetch_scans(request.user.id)
    return render(request, 'core/reports.html', {'data':data})

def get_scans_data(request):
    fs = fetch_scans.scans_fetch()
    data = fs.fetch_scans(request.user.id)
    return JsonResponse({"scans":data})

@login_required(login_url='/login/')
def sharedreports(request):
    fs = fetch_scans.scans_fetch()
    data = fs.fetch_shared_scans(request.user.id)
    usernames = []
    for userids in data:
        user = User.objects.get(pk=userids[5])
        usernames.append((user.id, user.username))
    return render(request, 'core/shared_reports.html', {'data':data, 'usernames':usernames})

@login_required
def setting(request):
    apoption = api_database.api_database()
    if request.method == "POST":
        api_option = request.POST.get("apioption")
        if api_option == "on":
            apoption.EnableAPI(request.user.id)
        else:
            apoption.DisableAPI(request.user.id)
    api = apoption.get_apiOption(request.user.id)
    return render(request, 'core/setting.html', {'api':api})

@login_required
def delete_account(request):
    if request.method == 'POST':
        user = request.user
        user.delete()
        messages.success(request, 'Your account has been deleted.')
        return redirect('/login/')
    return render(request, 'core/setting')

@login_required
def scan_report(request, report_id):
    fs = fetch_scans.scans_fetch()
    report_data = fs.fetch_scan_result(report_id)
    scan_data = fs.fetch_scan_info(report_id)
    user_data = User.objects.get(id=scan_data[0][5])
    username = user_data.username
    cve_data_list = []
    cve_refrences_list = []
    for cve_id in report_data:
        cve_data, cve_refrences = fs.get_vulnerability_detils(cve_id[5])
        cve_data_list.append(cve_data)
        cve_refrences_list.append(cve_refrences)
    
    cve_data_front = [item for sublist in cve_data_list for item in sublist]
    refrence_data_front = [item for sublist in cve_refrences_list for item in sublist]
    scan_type = scan_data[0][2]
    fhds = fs.fetch_hostdiscovery_result(report_id)
    if scan_type == 0:
        return render(request, 'core/scanreport.html', {'report_data':report_data, 'scan_data':scan_data, 'user_name':username, 'cve_data':cve_data_front, 'cve_refs':refrence_data_front, 'scan_type':scan_type })
    else:
        return render(request, 'core/scanreport.html', {'scan_data':scan_data,'results':fhds, 'user_name':username,  'scan_type':scan_type })

@login_required
def delete_report(request, report_id):
    delete = fetch_scans.scans_fetch()
    delete.delete_scan(report_id)
    return redirect('myscans')

# @login_required
# def export(request, report_id):
#     fs = fetch_scans.scans_fetch()
#     report_data = fs.fetch_scan_result(report_id)
#     scan_data = fs.fetch_scan_info(report_id)
#     user_data = User.objects.get(id=scan_data[0][5])
#     username = user_data.username
#     pdf_gen.PDFPSReporte(f'report_{scan_data[0][1]}.pdf',f'{scan_data[0][1]}', f'{scan_data[0][6]}', f'{username}')
#     return render(request, 'core/export.html')