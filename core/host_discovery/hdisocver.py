from . import hostdiscovery
from . import host_discoveryDB

class hdiscover:
    def scan(self, scan_id, subnet, ping_option):
        hs = hostdiscovery.hostDiscovery()
        if ping_option == "on":
            result = hs.discover_hosts("1", subnet)
        else:
            result = hs.discover_hosts("0", subnet)
        hsdb = host_discoveryDB.host_discoverDB()
        hsdb.insertfindings(result, scan_id)
        hsdb.scan_complete(scan_id)