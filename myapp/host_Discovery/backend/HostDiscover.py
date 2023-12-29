import logging
from scapy.all import srp, Ether, ARP
from mac_vendor_lookup import MacLookup

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


class ARPScanner:
    def __init__(self):
        self.mac_lookup = MacLookup()

    def arp_scan(self, target_subnet, exclude_ips=None, output_file=None):
        print(f"Scanning hosts on {target_subnet}...")

        try:
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_subnet)
            ans, _ = srp(arp_request, timeout=5, verbose=False)

            if not ans:
                print("No live hosts found.")
                return []  # Return an empty list if no live hosts are found

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
                self.print_host_details(host_details)

            if output_file:
                self.save_to_file(live_hosts, output_file)

            return live_hosts  # Return the list of live hosts

        except Exception as e:
            print(f"Error: {str(e)}")
            return []  # Return an empty list in case of an error

    def get_vendor(self, mac_address):
        try:
            vendor = self.mac_lookup.lookup(mac_address)
            return vendor if vendor else "Unknown Vendor"
        except Exception:
            return "Unknown Vendor"

    @staticmethod
    def print_host_details(details):
        print(f"{details['IP']}\t{details['MAC']}\t{details['Vendor']}")

    @staticmethod
    def save_to_file(data, filename):
        with open(filename, 'w') as file:
            for item in data:
                file.write(f"{item['IP']}\t{item['MAC']}\t{item['Vendor']}\n")
        print(f"Results saved to {filename}")