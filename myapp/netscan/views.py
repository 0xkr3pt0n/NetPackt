from django.shortcuts import render
from django.contrib.auth.decorators import login_required

import datetime
from .backend import networkscan
from .backend import search
from .backend import generate_scan
# Create your views here.


@login_required(login_url='/login/')
def networkscanning(request):
    if request.method == 'POST':
        #getting parameters by post request
        ip_address = request.POST.get('ip_address')
        scan_name = request.POST.get('scan_name')
        shared_with = request.POST.get('shared_with')
        current_user = request.user.username
        current_datetime = datetime.datetime.now()
        status = 'pending'
        #generating scan entry in db
        gscan = generate_scan.GenerateScan()
        scan_id = gscan.insert_scan(current_user, scan_name, ip_address, shared_with, current_datetime, status)
        
        #start scanning the target
        scan = networkscan.networkscan()
        scan_result = scan.scan(ip_address)
        
        #retrving cves from database
        query_db = search.SearchDatabase()
        query_result = query_db.getData(scan_result)
        
        cve_list = [cve[0] for sublist in query_result for cve in sublist]
        for cveid in cve_list:
            gscan.insert_finding(cveid, scan_id)
        #printing the result
         
    return render(request, "netscan/netscan.html")
