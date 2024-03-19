import requests
import sys
import concurrent.futures

class subdomain_enum:
    def __init__(self, url, dig_level, thread_level):
        self.dig_level = dig_level
        self.thread_level = thread_level
        self.url = url
        if dig_level == 0:
            sub_list = open("core/webscan/lists/subdomain-500.txt").read()
        elif dig_level == 1:
            sub_list = open("core/webscan/lists/subdomain-5000.txt").read()
        elif dig_level == 2:
            sub_list = open("core/webscan/lists/subdomain-20000.txt").read()
        elif dig_level == 3:
            sub_list = open("core/webscan/lists/subdomain-110000.txt").read()
        else:
            sub_list = open("core/webscan/lists/subdomain-150000.txt").read()
        self.subdoms = sub_list.splitlines()
        self.disocverd_subdomains = []
        self.thread_num = 0
        if thread_level == 0:
            self.thread_num=1
        elif thread_level == 1:
            self.thread_num = 10
        elif thread_level == 2:
            self.thread_num = 50
        else:
            self.thread_num = 100

    
    def discover_single_subdomain(self, sub):
        subdomain = f"http://{sub}.{self.url}"
        try:
            requests.get(subdomain, timeout=3)
        except requests.ConnectionError:
            pass
        else:
            self.disocverd_subdomains.append(subdomain)
            
    
    def discover(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.thread_num) as executor:
            executor.map(self.discover_single_subdomain, self.subdoms)
        
        return self.disocverd_subdomains

if __name__ == "__main__":
    sub_enum = subdomain_enum("microsoft.com", 0, 3)
    s=sub_enum.discover()
    print(s)

