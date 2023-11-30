from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .forms import SignupForm
from django.contrib.auth import logout
from django.contrib import messages
from django.contrib.auth.models import User
import datetime
import pyxploitdb
from .backend import networkscan
from .backend import search
from .backend import generate_scan

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
    gscan = generate_scan.GenerateScan()
    if request.method == 'POST':
        if 'scan' in request.POST:
        #getting parameters by post request
            ip_address = request.POST.get('TargetAddress')
            scan_name = request.POST.get('ScanName')
            shared_with = request.POST.get('shared_with')
            scan_type = request.POST.get('scan_type')
            is_runscript = request.POST.get('is_runscript')
            current_user = request.user.username
            current_datetime = datetime.datetime.now()
            status = 'pending'
            #generating scan entry in db
            scan_id = gscan.insert_scan(current_user, scan_name, ip_address, shared_with, current_datetime, status, scan_type, is_runscript)
            #start scanning the target
            scan = networkscan.networkscan()
            scan_result = scan.scan(ip_address, scan_type)
            # insert scan result into the database
            for result_item in scan_result:
                gscan.insert_scan_result(scan_id, result_item['Name'],result_item['product'], result_item['version'], result_item['PortNum'], result_item['scripts'])
            
            #retrving cves from database
            query_db = search.SearchDatabase()
            query_result = query_db.getData(scan_result)
            query_db.onlineSearch(scan_result, scan_id)
            
            #change scan status to completed
            gscan.scancomplete(scan_id)
            
            for j in query_result:
                for infected_service,v in j.items():
                    cve_ids = [item[0] for item in v]
                    if not cve_ids:
                        pass
                    else:
                        for cveid in cve_ids:
                            services = infected_service.split(',')
                            inf_ser = services[0]
                            port_number = services[1]
                            exploitdb = pyxploitdb.searchEDB(cve=cveid)
                            if exploitdb:
                                is_easy = True
                                exploit_link = []
                                for i in range(len(exploitdb)):
                                    exploit_link.append(exploitdb[i].link)
                                exploit_links = ','.join(exploit_link)
                            else:
                                is_easy = False
                                exploit_links = "None"
                            gscan.insert_finding(cveid, scan_id, inf_ser, port_number, is_easy, exploit_links)
            return redirect('scans')
    users = gscan.retrive_users()
    return render(request, 'core/index.html', {'users':users})


@login_required(login_url='/login/')
def soon(request):
    return render(request, "core/soon.html")

def setting(request):
    return render(request, "core/setting.html")

@login_required
def delete_account(request):
    if request.method == 'POST':
        user = request.user
        user.delete()
        return redirect('/login/')  

    return redirect('setting') 