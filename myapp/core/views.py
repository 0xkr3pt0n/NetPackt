from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .forms import SignupForm
from django.contrib.auth import logout
from django.contrib import messages
from django.contrib.auth.models import User
import datetime
from .backend import networkscan
from .backend import vulnsapi
from .backend import generate_scan
from .backend import user_settingsdb
from .backend import vulnsdb
from .backend import exploits

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
        #network scanning code
        if 'Network_Scan' in request.POST:
        #getting parameters by post request
            ip_address = request.POST.get('TargetAddress')
            scan_name = request.POST.get('ScanName')
            shared_with = request.POST.get('shared_with')
            scan_type = request.POST.get('scan_type')
            is_intrusive = request.POST.get('is_intrusive')
            current_user = request.user.username
            current_datetime = datetime.datetime.now()
            status = 'pending'
            
            #getting user scanner option
            settings = user_settingsdb.upateSettings()
            userid = request.user.id
            is_api_activated = settings.get_api_option(userid)
            
            if is_intrusive == "1":
                scan_intrusive = 1
            else:
                scan_intrusive = 0
                
            #generating scan entry in db
            scan_id = gscan.insert_scan(current_user, scan_name, ip_address, shared_with, current_datetime, status, scan_type, scan_intrusive, is_api_activated)
            
            #start scanning the target
            scan = networkscan.networkscan()
            scan_result = scan.scan(ip_address, scan_intrusive)
            
            # insert scan result into the database
            for result_item in scan_result:
                gscan.insert_scan_result(scan_id, result_item['Name'],result_item['product'], result_item['version'], result_item['PortNum'], result_item['scripts'])
           

            query_api = vulnsapi.searchApi() # an object of searchapi class
            query_db = vulnsdb.SearchDatabase() # an object of searchdatabase class
            
            # checking if user enabled online scanner feature to scan system with api
            if is_api_activated == 1:
                # if enabled online scanner it will scan with api
                query_api.seachMitre(scan_result, scan_id)
                query_api.searchNist(scan_result, scan_id)
            else:
                # if disabled online scanner it will search through database
                #retrving cves from database
                query_result = query_db.getData(scan_result)
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
                                is_easy, exploit_links = exploits.exploits.exploit_finder(cveid)
                                gscan.insert_finding(cveid, scan_id, inf_ser, port_number, is_easy, exploit_links)
            
            #change scan status to completed
            gscan.scancomplete(scan_id)
            return redirect('scans')
    users = gscan.retrive_users()
    return render(request, 'core/index.html', {'users':users})


@login_required(login_url='/login/')
def soon(request):
    return render(request, "core/soon.html")

@login_required(login_url='/login/')
def setting(request):
    settings = user_settingsdb.upateSettings()
    userid = request.user.id
    if request.method == 'POST':
        if 'save_settings' in request.POST:
            is_api = request.POST.get('is_api')
            print(is_api)
            if is_api == "on":
                settings.update_api_activate(userid)
            else:
                settings.update_api_disable(userid)
    is_api_activated = settings.get_api_option(userid)
    
    return render(request, "core/setting.html", {'is_api':is_api_activated})

@login_required
def delete_account(request):
    if request.method == 'POST':
        user = request.user
        user.delete()
        return redirect('/login/')  

    return redirect('setting') 