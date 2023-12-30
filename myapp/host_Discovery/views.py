# Inside views.py
from django.shortcuts import render
from .backend.HostDiscover import ARPScanner
from django.contrib.auth.decorators import login_required

@login_required(login_url='/login/')
def scan_network(request):
    target_subnet = request.POST.get('target_subnet', '') if request.method == 'POST' else ''
    exclude_ips_str = request.POST.get('exclude_ips', '') if request.method == 'POST' else ''
    output_file = request.POST.get('output_file', '') if request.method == 'POST' else ''

    exclude_ips = exclude_ips_str.split(',') if exclude_ips_str else None

    scanner = ARPScanner()
    results = []
    error_message = None

    if request.method == 'POST' and target_subnet:
        try:
            # Get the list of dictionaries containing host details
            results = scanner.arp_scan(target_subnet, exclude_ips, output_file)
        except Exception as e:
            error_message = str(e)

    return render(request, 'host_discovery/H_D.html', {
        'target_subnet': target_subnet,
        'exclude_ips': exclude_ips_str,
        'output_file': output_file,
        'results': results,  # Pass the results directly
        'error_message': error_message,
    })
