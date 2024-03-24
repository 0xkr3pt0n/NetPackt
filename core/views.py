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
from .webscan import wscanner
from urllib.parse import urlparse


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
        
        #specfing port ranges
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
        
        # checking for scan type 1 for tcp connect, 2 for stealth
        if port_scanType == "1":
            scan_type = 1
        elif port_scanType == "2":
            scan_type = 2
        else:
            print("invalid input")
        print(min_port)
        print(max_port)
        
        thread_value = 0
        #checking for intrusitivity
        if intrustivity_type == '1':
            thread_value = 1
        elif intrustivity_type == '2':
            thread_value = 50
        elif intrustivity_type == '3':
            thread_value = 100
        else:
            thread_value = 1
        task = schedule_vulnerability_scan(scan_id, ip_addr, min_port, max_port, scan_type, thread_value, repeat=Task.NEVER)
        task_id = task.id
        fs = fetch_scans.scans_fetch()
        fs.add_taskid(scan_id, task_id)
        print(f"task id {task_id}")
        return redirect('myscans')
    
    users = users_fetch.users_fetch()
    users_data = users.get_all_users(request.user.id)
    # print(users_data)
    return render(request, 'core/networkscan.html', {'users':users_data})


@background  # Execute immediately
def schedule_vulnerability_scan(scan_id, ip_addr, min_port, max_port, scan_type, thread_value):
    print("start vulnerability")
    print(thread_value)
    vscanning = vscanner.vulnerability_scanner(ip_addr, min_port, max_port, scan_type, scan_id, thread_value)
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

@login_required(login_url='/login/')
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

@login_required(login_url='/login/')
def delete_account(request):
    if request.method == 'POST':
        user = request.user
        user.delete()
        messages.success(request, 'Your account has been deleted.')
        return redirect('/login/')
    return render(request, 'core/setting')

@login_required(login_url='/login/')
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
    fws_domains, fws_dirs = fs.fetch_webscan_result(report_id)
    print(fws_dirs)
    if scan_type == 0:
        print(scan_data)
        return render(request, 'core/scanreport.html', {'report_data':report_data, 'scan_data':scan_data, 'user_name':username, 'cve_data':cve_data_front, 'cve_refs':refrence_data_front, 'scan_type':scan_type })
    elif scan_type == 1:
        return render(request, 'core/scanreport.html', {'scan_data':scan_data,'results':fhds, 'user_name':username,  'scan_type':scan_type })
    elif scan_type == 2:
        return render(request, 'core/scanreport.html', {'scan_data':scan_data, 'results_subdirs':fws_dirs, 'results_subdomains':fws_domains, 'user_name':username,  'scan_type':scan_type })

@login_required(login_url='/login/')
def delete_report(request, report_id):
    delete = fetch_scans.scans_fetch()
    delete.delete_scan(report_id)
    return redirect('myscans')

@login_required(login_url='/login/')
def stop_scan(request, report_id):
    fs = fetch_scans.scans_fetch()
    fs.pause_scan(report_id)
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

@login_required(login_url='/login/')
def webscan(request):
    users = users_fetch.users_fetch()
    users_data = users.get_all_users(request.user.id)
    
    if request.method == 'POST':
        #getting post request parameters
        scan_name = request.POST.get('scan_name')
        scan_target = request.POST.get('target')
        subdomain_enum = request.POST.get('subdomain_enum')
        dig_level = request.POST.get('dig_level')
        dig_level_dirs = request.POST.get('dig_level_dirs')
        thread_level = request.POST.get('thread_level')
        subdirs_enum = request.POST.get('subdirs_enum')

        user_id = request.user.id
        create_scan = scan_create.scan_create()
        shared_users_list = []
        scan_id = create_scan.webscan(scan_name, scan_target, user_id, shared_users_list)
        scan_list = []

        # parsing url to filter it
        parsed_url = urlparse(scan_target)
        scan_target_domain = parsed_url.netloc
        if scan_target_domain.startswith('www.'):
            scan_target_domain = scan_target_domain[4:]
        else:
            return render(request, 'core/webscan.html', {'error_message2': True, 'users':users_data})
        print(scan_target_domain)
        
        #creating a webscan class inistance
        # w = wscanner.wscanner(scan_target_domain)
        #thread level
        threads = 0
        print(thread_level)
        if thread_level == "0":
            threads = 0
        elif thread_level == "1":
            threads = 1
        elif thread_level == "2":
            threads = 2
        elif thread_level == "3":
            threads = 3
        else:
            return render(request, 'core/webscan.html', {'error_message': True, 'users':users_data})
        
        digs = 0
        if subdomain_enum == 'on':
            # dig level for subdomain enumeration
            scan_list.append(1)
            if dig_level == "0":
                digs = 0
            elif dig_level == "1":
                digs = 1
            elif dig_level == "2":
                digs = 2
            elif dig_level == "3":
                digs = 3
            else:
                return render(request, 'core/webscan.html', {'error_message1': True, 'users':users_data})
            # w.subdomain_enum(digs, threads, scan_id)
            
        
        digs_dirs = 0
        if subdirs_enum == 'on':
            
            if dig_level_dirs == "0":
                digs_dirs = 0
            elif dig_level_dirs == "1":
                digs_dirs = 1
            elif dig_level_dirs == "2":
                digs_dirs = 2
            elif dig_level_dirs == "3":
                digs_dirs = 3
            else:
                return render(request, 'core/webscan.html', {'error_message1': True, 'users':users_data})
            # w.subdirs_enum(digs, threads, scan_id)
            scan_list.append(2)
            
        # w.finish_scan(scan_id)
        print("background will start")
        
        schedule_web_scan(scan_id, threads, scan_target_domain, scan_list, digs_dirs, digs, repeat=Task.NEVER)
        return redirect('myscans')
        
    return render(request, 'core/webscan.html', {'users':users_data})

@background
def schedule_web_scan(scan_id, thread_level, target, scans_list, digs_dirs=0, digs_domains=0):
    w = wscanner.wscanner(target)
    print(f'scan list {scans_list}')
    
    if 1 in scans_list:
        w.subdomain_enum(digs_domains, thread_level, scan_id)
    
    if 2 in scans_list:
        print("2 in list ")
        w.subdirs_enum(digs_dirs, thread_level, scan_id)
    w.finish_scan(scan_id)