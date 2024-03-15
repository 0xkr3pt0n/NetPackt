from . import subdomain_enum
from . import result_insertion
class wscanner:
    def __init__(self, target, scan_type):
        self.target = target
        self.scan_type = scan_type
    
    def subdomain_enum(self, dig_level, thread_level, scan_id):
        print("start subdomain scan")
        s = subdomain_enum.subdomain_enum(self.target, dig_level, thread_level)
        #discoverd subdomain list returned from subdomain discovery module
        discoverd = s.discover()
        r = result_insertion.insert_finding()
        print("inserting findings")
        r.insert_subdomains(discoverd,scan_id)
