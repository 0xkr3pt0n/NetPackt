from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
import datetime
from .backend import networkscan
from .backend import search
from .backend import generate_scan
# Create your views here.


@login_required(login_url='/login/')
def networkscanning(request):
    gscan = generate_scan.GenerateScan()
    if request.method == 'POST':
        #getting parameters by post request
        ip_address = request.POST.get('ip_address')
        scan_name = request.POST.get('scan_name')
        shared_with = request.POST.get('shared_with')
        current_user = request.user.username
        current_datetime = datetime.datetime.now()
        status = 'pending'
        #generating scan entry in db
        scan_id = gscan.insert_scan(current_user, scan_name, ip_address, shared_with, current_datetime, status)
        
        #start scanning the target
        scan = networkscan.networkscan()
        scan_result = scan.scan(ip_address)
        
        #retrving cves from database
        query_db = search.SearchDatabase()
        query_result = query_db.getData(scan_result)

        #change scan status to completed
        gscan.scancomplete(scan_id)
        for j in query_result:
            for infected_service,v in j.items():
                cve_ids = [item[0] for item in v]
                if not cve_ids:
                    pass
                else:
                    for cveid in cve_ids:
                        gscan.insert_finding(cveid, scan_id, infected_service)
        return redirect('scans')
    users = gscan.retrive_users()
    return render(request, "netscan/netscan.html", {'users':users})


@login_required(login_url='/login/')
def scans(request):
    gscan = generate_scan.GenerateScan()
    scans = gscan.getscans()
    return render(request, "netscan/scans.html", {'scans':scans})

@login_required(login_url='/login/')
def report(request,report_id):
    get_report = generate_scan.GenerateScan()
    report_data = get_report.getreport(report_id)
    findings_data = get_report.getfindings(report_id)
    discoverd_findings = []
    for cve in findings_data:
        cve_data = get_report.retrive_cves(cve[1])
        combined_data = cve+cve_data
        discoverd_findings.append(combined_data)
    print(discoverd_findings)
    return render(request, 'netscan/report.html', {'report':report_data, 'findings':discoverd_findings})