from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .backend import networkscan
# Create your views here.


@login_required(login_url='/login/')
def networkscanning(request):
    if request.method == 'POST':
        ip_address = request.POST.get('ip_address', '')
        scan = networkscan.networkscan()
        print(scan.scan(ip_address))
    return render(request, "netscan/netscan.html")
