import requests
from urllib.parse import urlparse
import concurrent.futures

class subdir_enum:
    def __init__(self, target, dig_level, thread_level):
        self.dig_level = dig_level
        self.thread_level = thread_level
        self.target = f'http://www.{target}'
        #detrminig dig level (how much subdirectories)
        if dig_level == 0:
            dirs_list = open("core/webscan/lists/dirs-1500.txt").read()
        elif dig_level == 1:
            dirs_list = open("core/webscan/lists/dirs-90000.txt").read()
        elif dig_level == 2:
            dirs_list = open("core/webscan/lists/dirs-140000.txt").read()
        elif dig_level == 3:
            dirs_list = open("core/webscan/lists/dirs-220000.txt").read()
        else:
            dirs_list = open("core/webscan/lists/dirs-1200000.txt").read()
        self.subdirs = dirs_list.splitlines()
        self.thread_num = 0
        #detrmining thread level (req/sec) (how faster the tool is)
        if thread_level == 0:
            self.thread_num = 1
        elif thread_level == 1:
            self.thread_num = 10
        elif thread_level == 2:
            self.thread_num = 50
        else:
            self.thread_num = 100 
        self.discoverd_subdirs = []
        
        print(f'taget is {target}')

    def disover_single_subdir(self, directory):
        #parsing url
        parsed_url = urlparse(self.target)
        #constructing base url
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        #url+directory 
        full_url = base_url + '/' + directory
        
        response = requests.get(full_url)
        if response.status_code == 200:
            print(f"[+] Discovered subdirectory: {full_url}")
            self.discoverd_subdirs.append(full_url)
    
    def discover(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.thread_num) as executor:
            executor.map(self.disover_single_subdir, self.subdirs)
        return self.discoverd_subdirs

if __name__ == "__main__":
    s = subdir_enum('https://fci.bu.edu.eg',0,1)
    print(s.discover())
