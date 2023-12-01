from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .backend import generate_scan
# Create your views here.




@login_required(login_url='/login/')
def scans(request):
    gscan = generate_scan.GenerateScan()
    scans = gscan.getscans(request.user.username)
    return render(request, "netscan/scans.html", {'scans':scans})

@login_required(login_url='/login/')
def report(request,report_id):
    get_report = generate_scan.GenerateScan()
    report_data = get_report.getreport(report_id)
    findings_data = get_report.getfindings(report_id)
    findings_online = get_report.getOnline(report_id)
    scan_result = get_report.get_scan_result(report_id)
    discoverd_findings = []
    for cve in findings_data:
        cve_data = get_report.retrive_cves(cve[1])
        combined_data = cve+cve_data
        discoverd_findings.append(combined_data)
    users = get_report.retrive_users()
    if request.method == 'POST':
        new_name = request.POST.get('new_name')
        new_share = request.POST.get('new_share')
        get_report.updatescan(new_name, new_share, report_id)
        return redirect('report_detils', report_id=report_id)
    if report_data[8] == 1:
        return render(request, 'netscan/report.html', {'report':report_data, 'users':users, 'online':findings_online, 'scan_result':scan_result,'is_online':1})
    else:
        return render(request, 'netscan/report.html', {'report':report_data, 'findings':discoverd_findings, 'users':users, 'scan_result':scan_result, 'is_online':0})