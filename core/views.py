from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.shortcuts import render,redirect
from .forms import LoginForm,SignupForm,Pcap_form
from .models import pcap_file
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
from .waf_enum import waf_enummer
from urllib.parse import urlparse
from .workspaces import workspace_create
from .workspaces import workspace_fetch
from .network_forensics import nforensics
from .chat import fetch_users_info, fetch_chat, send_message
from django.db import connection
import ipaddress


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
            us = users_fetch.users_fetch()
            us.userlogin_status(request.user.id)
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
    us = users_fetch.users_fetch()
    us.userlogout_status(request.user.id)
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
        custom = 0
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
            custom = 1
            if min_port >= max_port:
                return render(request, 'core/networkscan.html', {'invalid_port':True})
        else:
            return render(request, 'core/networkscan.html', {'invalid_port':True})
        
        # checking for scan type 1 for tcp connect, 2 for stealth
        if port_scanType == "1":
            scan_type = 1
        elif port_scanType == "2":
            scan_type = 2
        else:
            return render(request, 'core/networkscan.html', {'invalid_stype':True})
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
            return render(request, 'core/networkscan.html', {'invalid_thread':True})
        
        task = schedule_vulnerability_scan(scan_id, ip_addr, min_port, max_port, scan_type, custom, thread_value, repeat=Task.NEVER)
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
def schedule_vulnerability_scan(scan_id, ip_addr, min_port, max_port, scan_type, custom, thread_value):
    print("start vulnerability")
    print(thread_value)
    vscanning = vscanner.vulnerability_scanner(ip_addr, min_port, max_port, scan_type, scan_id, custom, thread_value)
    vscanning.vulnerability_scan()

def ip_address_validator(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return 1
    except ValueError:
        return 0
            

@login_required(login_url='/login/')
def host_discover(request):
    if request.method == "POST":
        scan_name = request.POST.get('scan_name')
        subnet = request.POST.get('subnet')
        ping_option = request.POST.get('ping_option')
        
        if(len(scan_name) == 0 ):
            return render(request, 'core/hostdiscovery.html', {'empty_name':True})
        
        if(len(subnet) == 0 ):
            return render(request, 'core/hostdiscovery.html', {'empty_subnet':True})
        
        if (ping_option == "on" or ping_option == "off"):
            pass
        else:
            return render(request, 'core/hostdiscovery.html', {'Invalid_ping':True})

        if(ip_address_validator(subnet) == 0):
            return render(request, 'core/hostdiscovery.html', {'Invalid_ip':True})
        
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

def ajax_data_chats(request, selected_username):
    cm = fetch_chat.fetch_chat_info()
    data = cm.get_messages(request.user.username, selected_username)
    return JsonResponse({"chat":data})

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

def scan_report(request, report_id):
    fs = fetch_scans.scans_fetch()
    scan_type = fs.get_scan_type(report_id)
    scan_info = fs.fetch_scan_info(report_id)
    user_data = User.objects.get(id=scan_info[0][5])
    username = user_data.username
    
    #network vulnerablility scan
    if scan_type == 0:
        cve_data_list = []
        cve_refrences_list = []
        report_data = fs.fetch_scan_result(report_id)
        for cve_id in report_data:
            cve_data, cve_refrences = fs.get_vulnerability_detils(cve_id[5])
            cve_data_list.append(cve_data)
            cve_refrences_list.append(cve_refrences)
        cve_data_front = [item for sublist in cve_data_list for item in sublist]
        refrence_data_front = [item for sublist in cve_refrences_list for item in sublist]
        return render(request, 'core/networkscan_report.html', {'report_data':report_data, 'scan_info':scan_info, 'username':username, 'cve_data':cve_data_front, 'cve_refs':refrence_data_front})
    #host discovery scan
    elif scan_type == 1:
        fhds = fs.fetch_hostdiscovery_result(report_id)
        return render(request, 'core/hostdiscovery_report.html', {'scan_info':scan_info, 'username':username, 'results':fhds})
    #webscan
    elif scan_type == 2:
        fws_domains, fws_dirs = fs.fetch_webscan_result(report_id)
        print(fws_domains)
        print(fws_dirs)
        return render(request, 'core/webscan_report.html',{'scan_info':scan_info, 'username':username, 'results_subdirs':fws_dirs, 'results_subdomains':fws_domains})
    #waf scan
    elif scan_type == 3:
        firewalls_data = fs.fetch_waf_result(report_id)
        return render(request, 'core/wafenum_report.html', {'scan_info':scan_info, 'username':username, 'firewalls_data':firewalls_data})
    #forensics scan
    elif scan_type == 4:
        nf_stats = fs.fetch_nf_stats(report_id)
        nf_ips = fs.fetch_nf_ips(report_id)
        return render(request, 'core/networkForensics_report.html', {'scan_info':scan_info, 'username':username, 'nf_stats':nf_stats, 'nf_ips':nf_ips})
    else:
        return render(request, 'core/report.html')



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

@login_required(login_url='/login/')
def waf_enumeration(request):
    users = users_fetch.users_fetch()
    users_data = users.get_all_users(request.user.id)

    if request.method == 'POST':
        scan_name = request.POST.get('scan_name')
        target = request.POST.get('target')
        print(scan_name)
        print(target)
        user_id = request.user.id
        create_scan = scan_create.scan_create()
        shared_users_list = []
        scan_id = create_scan.waf_enum(scan_name, target, user_id, shared_users_list)

        w = waf_enummer.waf_enumer(target, scan_id)
        w.scan_target()
        return redirect('myscans')

    return render(request, 'core/waf_enum.html', {'users':users_data})

@login_required(login_url='/login/')
def my_workspaces(request):
    if request.method == 'POST':
        workspace_name = request.POST.get('workspace_name')
        print(workspace_name)
        wc = workspace_create.workspace_create(workspace_name)
        wc.create_workspace()

        wsdata = workspace_fetch.workspace_fetcher()
        wspaces = wsdata.fetch_workspaces()
        return render(request, 'core/my_workspaces.html', {'workspaces': wspaces})
    wsdata = workspace_fetch.workspace_fetcher()
    wspaces = wsdata.fetch_workspaces()
    return render(request, 'core/my_workspaces.html', {'workspaces': wspaces})

@login_required(login_url='/login/')
def delete_workspace(request, space_id):
    delete = workspace_fetch.workspace_fetcher()
    delete.delete_workspace(space_id)
    return redirect('my_workspaces')

@login_required(login_url='/login/')
def edit_workspace(request, space_id):
    ws = workspace_fetch.workspace_fetcher()
    wsdata = ws.fetch_workspace(space_id)
    wsScans = ws.workspace_scans_fetch(space_id)
    scans = fetch_scans.scans_fetch()
    user_id = request.user.id
    scans_data = scans.fetch_scans_workspace(user_id)
    
    if request.method == 'POST':
        scan_id = request.POST.get('scan_select')
        ws.addscan_workspace(scan_id, space_id)
        return render(request, 'core/workspace_edit.html', {'wsdata': wsdata, 'scans':scans_data})
        
    return render(request, 'core/workspace_edit.html', {'wsdata': wsdata, 'scans':scans_data, 'wsScans':wsScans})

@login_required(login_url='/login/')
def view_workspace(request, space_id):
    s = workspace_fetch.workspace_fetcher()
    workspace_data = s.fetch_workspace(space_id)
    
    scans_information = s.workspace_scans_fetch_all(space_id)
    
    fs = fetch_scans.scans_fetch()
    vulnerability_scan_data = []
    hds_scan_data = []
    web_scan_data_domains = []
    web_scan_data_dirs = []
    waf_scan_data = []
    for i in scans_information:
        
        if i[2] == 0:
            vulnscan_id = i[0]
            report_data = fs.fetch_scan_result(vulnscan_id)
            vulnerability_scan_data.append(report_data)
        elif i[2] == 1:
            hostdisc_id = i[0]
            host_data = fs.fetch_hostdiscovery_result(hostdisc_id)
            hds_scan_data.append(host_data)
        elif i[2] == 2:
            webscan_id = i[0]
            web_data_dn, web_data_dr = fs.fetch_webscan_result(webscan_id)
            web_scan_data_domains.append(web_data_dn)
            web_scan_data_dirs.append(web_scan_data_dirs)
        elif i[2] == 3:
            wafenum_id = i[0]
            waf_result = fs.fetch_waf_result(wafenum_id)
            waf_scan_data.append(waf_result)

    
    print(hds_scan_data)
    print(web_scan_data_domains)
    print(web_scan_data_dirs)
    print(waf_scan_data)

    vulnresult_proccesd = []
    for i in vulnerability_scan_data:
        for j in i:
            vulnresult_proccesd.append(j)
    
    cve_data_list = []
    cve_data_refrences = []
    for cve in vulnresult_proccesd:
        cve_id = cve[5]
        vulndetails, ref_details = fs.get_vulnerability_detils(cve_id)
        cve_data_list.append(vulndetails)
        cve_data_refrences.append(ref_details)


    cve_data = []
    for i in cve_data_list:
        for j in i:
            cve_data.append(j)
    print(cve_data)
    print(f'you are viewing workspace : {space_id}')
    return render(request, 'core/workspace_report.html', {'wdata':workspace_data, 'scans_information':scans_information,'vulnresult':vulnresult_proccesd, 'cve_data':cve_data, 'cve_ref': cve_data_refrences})


@login_required(login_url='/login/')   
def network_forensics(request):
    users = users_fetch.users_fetch()
    users_data = users.get_all_users(request.user.id)
    
    if request.method == 'POST':
        form = Pcap_form(request.POST, request.FILES)
        
        scan_name = request.POST.get('scan_name')
        target = request.FILES['pfile'].name
        shared_users_list = []
        user_id = request.user.id
        create_scan = scan_create.scan_create()
        scan_id = create_scan.network_forensics(scan_name, target, user_id, shared_users_list)
        saved_file_name = ''
        if form.is_valid():
            saved_file = form.save()
            saved_file_name = saved_file.pfile.name
        print(saved_file_name)
        
        nf = nforensics.pcap_analyzer(saved_file_name, scan_id)
        data = nf.pacp_analyze()
        nf.result_insertion(data)
        return redirect('myscans')
        
    else:
        form = Pcap_form()

    return render(request, 'core/network_forensics.html', {'form':form, 'users':users_data})

@login_required(login_url='/login/') 
def chat_page(request, username):
    
    fs = fetch_users_info.fetch_users_info()
    fc = fetch_chat.fetch_chat_info()
    
    user_id = request.user.id
    users = fs.get_all_users(user_id)
    #if no username is set then set the first username
    if username == request.user.username:
        username=users[0][1]
    user1_username=request.user.username
    user2_laslogin = fs.get_user_lastlogin(username)[0][0]
    messagess = fc.get_messages(user1_username, username)
    last_message = ""
    if len(messagess[-1][3]) > 40:
        last_message = f"{messagess[-1][3][:40]}......"
    else:
        last_message = messagess[-1][3]
    print(last_message)
    
    if request.method == 'POST':
        message = request.POST.get('message')
        sm = send_message.send_message()
        sm.send_message(user1_username, username, message)

    return render(request, 'core/chat.html', {"users":users,'messagess':messagess, 'selected_username':username, 'selected_lastlogin':user2_laslogin, 'last_message':last_message})

@login_required(login_url='/login/')
def friend_requests(request):
    # Assuming you have a PostgreSQL table named friend_request
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT fr.id, u.username
            FROM friend_request fr
            JOIN auth_user u ON fr.from_user_id = u.id
            WHERE fr.to_user_id = %s
        """, [request.user.id])
        friend_requests = cursor.fetchall()

    return render(request, 'core/add_friend.html', {'friend_requests': friend_requests})




@login_required(login_url='/login/')   
def search_users(request):
    if request.method == 'GET':
        query = request.GET.get('q', '')
        users = User.objects.filter(username__icontains=query)
        return render(request, 'core/search_results.html', {'users': users, 'query': query})
    else:
        return redirect('core/dashboard.html')

@login_required(login_url='/login/')   
def send_friend_request(request, to_user_id):
    if request.method == 'POST':
        from_user_id = request.user.id
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO friend_request (from_user_id, to_user_id) VALUES (%s, %s)",
                    [from_user_id, to_user_id]
                )
            # Provide feedback to the user
            messages.success(request, 'Friend request sent successfully.')
        except Exception as e:
            # Handle any database errors
            messages.error(request, 'An error occurred while sending the friend request.')
        return redirect('home')

@login_required(login_url='/login/')
def accept_friend_request(request, request_id):
    if request.method == 'POST':
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE friend_request SET accepted = TRUE WHERE id = %s",
                    [request_id]
                )
            # Provide feedback to the user
            messages.success(request, 'Friend request accepted successfully.')
        except Exception as e:
            # Handle any database errors
            messages.error(request, 'An error occurred while accepting the friend request.')
        return redirect('home')

@login_required(login_url='/login/')
def reject_friend_request(request, request_id):
    if request.method == 'POST':
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM friend_request WHERE id = %s",
                    [request_id]
                )
            # Provide feedback to the user
            messages.success(request, 'Friend request rejected successfully.')
        except Exception as e:
            # Handle any database errors
            messages.error(request, 'An error occurred while rejecting the friend request.')
        return redirect('home')
    
@login_required(login_url='/login/')
def accepted_users(request):
    # Fetch users who have sent friend requests that were accepted
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT u.username AS sender_username, u2.username AS receiver_username FROM auth_user u INNER JOIN friend_request fr ON u.id = fr.from_user_id INNER JOIN auth_user u2 ON u2.id = fr.to_user_id WHERE fr.accepted = TRUE AND (fr.from_user_id = %s OR fr.to_user_id = %s)",
            [request.user.id, request.user.id]
        )
        accepted_users = [{'sender': row[0], 'receiver': row[1]} for row in cursor.fetchall()]

    return render(request, 'core/accepted_users.html', {'accepted_users': accepted_users})
