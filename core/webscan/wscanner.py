from . import subdomain_enum
from . import subdir_enum
from . import result_insertion
class wscanner:
    def __init__(self, target):
        self.target = target
        self.r = result_insertion.insert_finding()
    
    def subdomain_enum(self, dig_level, thread_level, scan_id):
        print("start subdomain scan")
        s = subdomain_enum.subdomain_enum(self.target, dig_level, thread_level)
        #discoverd subdomain list returned from subdomain discovery module
        discoverd = s.discover()
        print(self.target)
        print("inserting findings")
        print(discoverd)
        self.r.insert_subdomains(discoverd, scan_id)
        
    
    def subdirs_enum(self, dig_level, thread_level, scan_id):
        print("start subdirs enumeration")
        s = subdir_enum.subdir_enum(self.target, dig_level, thread_level)
        discoverd = s.discover()
        print(discoverd)
        print("insert findings")
        self.r.insert_subdirectories(discoverd, scan_id)
    
    def finish_scan(self, scan_id):
        self.r.finish_scan(scan_id)
        print('scan finished')

if __name__ == "__main__":
    w = wscanner('tesla.com')
    w.subdomain_enum(0, 3, 9)
