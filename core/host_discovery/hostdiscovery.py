import logging
from scapy.all import srp, Ether, ARP
from mac_vendor_lookup import MacLookup
import subprocess
import threading
from queue import Queue
import ipaddress
import sys
import socket

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

print_lock = threading.Lock()

class hostDiscovery:
    def __init__(self):
        self.mac_lookup = MacLookup()

    def arp_scan(self, target_subnet, exclude_ips=None):
        print(f"Scanning hosts on {target_subnet}...")

        try:
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_subnet)
            ans, _ = srp(arp_request, timeout=5, verbose=False)

            if not ans:
                print("No live hosts found.")
                return []

            live_hosts = []
            for response in ans:
                ip_address = response[1][ARP].psrc
                mac_address = response[1][ARP].hwsrc
                vendor = self.get_vendor(mac_address)

                if exclude_ips and ip_address in exclude_ips:
                    continue

                host_details = {
                    "IP": ip_address,
                    "MAC": mac_address,
                    "Vendor": vendor,
                }

                live_hosts.append(host_details)

            return live_hosts

        except Exception as e:
            print(f"Error: {str(e)}")
            return []

    def ping_sweep(self, target_subnet, timeout=1):
        def pingsweep(ip):
            """
              does a ping sweep using subprocess
              for 1 count, with a 1000ms wait
              accepts ip as input
              builds list as it occurs
              spits out unreachable messages only, not timeouts
              in practice, some computers on the local network took up to 300ms to respond.
              If you set the timeout too low, you might get an incomplete response list
              """
            output = ''
            if sys.platform.startswith('win32'):
                output = subprocess.Popen(['ping', '-n', '1', '-w',
                                           '1000', str(all_hosts[ip])], stdout=subprocess.PIPE,
                                          startupinfo=info).communicate()[0]
            elif sys.platform.startswith('linux'):
                output = subprocess.Popen(['ping', '-c', '1', '-w',
                                           '1000', str(all_hosts[ip])], stdout=subprocess.PIPE,
                                          startupinfo=info).communicate()[0]
            else:
                print("Cannot determine OS type")
                sys.exit()
            """
             code logic if we have/don't have good response
             used casefold for case insenstive search
             Win: Reply from 8.8.8.8: bytes=32 time=19ms TTL=53
             Nix: 64 bytes from 8.8.8.8: icmp_seq=4 ttl=53 time=22.003 ms
            """

            with print_lock:
                if 'ttl'.casefold() in output.decode('utf-8').casefold():
                    iplist.append(all_hosts[ip])
                elif "reachable" in output.decode('utf-8'):
                    pass
                elif "timed" in output.decode('utf-8'):
                    pass
                elif "failed" in output.decode('utf-8'):
                    pass
                else:
                    print(str(all_hosts[ip]), '\033[90m' + "is Unknown")

        def threader():
            """
              defines a new ping using def pingsweep for each thread
              holds task until thread completes
              """
            while True:
                worker = q.get()
                pingsweep(worker)
                q.task_done()

        iplist = []
        q = Queue()
        net_addr = target_subnet.split('/')[0]
        ip_net = ipaddress.ip_network(target_subnet)
        all_hosts = list(ip_net.hosts())
        info = subprocess.STARTUPINFO()
        info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        info.wShowWindow = subprocess.SW_HIDE
        print('Sweeping Network with ICMP: ', net_addr)
        # up to 100 threads, daemon for cleaner shutdown
        # just spawns the threads and makes them daemon mode
        for x in range(100):
            t = threading.Thread(target=threader)
            t.daemon = True
            t.start()

        for worker in range(len(all_hosts)):
            q.put(worker)

        q.join()

        live_hosts = []
        for ip in sorted(iplist, key=ipaddress.IPv4Address):
            live_hosts.append({"IP": str(ip)})

        return live_hosts

    def discover_hosts(self, option, target_subnet, exclude_ips=None):
        if option == "0":
            return self.arp_scan(target_subnet, exclude_ips)
        elif option == "1":
            return self.ping_sweep(target_subnet)
        else:
            print("Invalid choice. Exiting.")
            return []

    def get_vendor(self, mac_address):
        try:
            vendor = self.mac_lookup.lookup(mac_address)
            return vendor if vendor else "Unknown Vendor"
        except Exception:
            return "Unknown Vendor"



if __name__ == "__main__":
    scanner = hostDiscovery()
    live_hosts = scanner.discover_hosts("0", "192.168.1.0/24")
    print("Live Hosts:")
    for host in live_hosts:
        print(host)
