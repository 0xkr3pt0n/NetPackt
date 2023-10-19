import nmap

class networkscan:
    #constructor that initiate scan
    def __init__(self,hosts):
        self.hosts(hosts)
    
    #function to recieve hosts file and loop in it to scan each host or network (it may contain an ip or network prefix)
    def hosts(self, hosts):
        with open(self.hosts) as hosts:
            for host in hosts:
                infodb,infodisplay = self.scan(host)
                print(infodb)
                print("-"*17)
                print(infodisplay)

    #function to for scanning netowrk or a only one host 
    def scan(self,network_prefix):
        nm = nmap.PortScanner()
        #argument T4 for threading
        scan_raw_result = nm.scan(hosts=network_prefix, arguments='-v -n -A -T4')
        
        services_for_db = [] #this list will at last contain each service running and it's version to query the database with
        services_for_display = [] #this list will at last contain each port and it's information for user display
        #extracting results
        for host, result in scan_raw_result['scan'].items():
            if result['status']['state'] == 'up':
                
                # extracting tcp ports detils
                try:
                    for port in result['tcp']:
                        try:
                            portnumber = str(port)
                            try:
                                portstatus = result['tcp'][port]['state']
                            except:
                                portstatus = "unknown"
                            try:
                                reason = result['tcp'][port]['reason']+' response'
                            except:
                                reason = "port is responding to communication"
                            try:
                                addinfo = result['tcp'][port]['extrainfo']
                            except:
                                addinfo = "there is no additional information"
                            try:
                                service_name = result['tcp'][port]['name']
                            except:
                                service_name = "service name is not detected"
                            try:
                                cur_ver = result['tcp'][port]['version']
                            except:
                                cur_ver = "Current version is not detected"
                            tcp_port = {'PortNum':portnumber, 'status':portstatus, 'reason': reason,'addinfo':addinfo,'Name':service_name,'version':cur_ver}
                        except:
                            pass
                        service = result['tcp'][port]['name'] + " " + result['tcp'][port]['version']
                        services_for_db.append(service)
                        services_for_display.append(tcp_port)
                except:
                    pass
                
                #extracting udp ports results
                try:
                    for port in result['udp']:
                        try:
                            portnumber = str(port)
                            try:
                                portstatus = result['udp'][port]['state']
                            except:
                                portstatus = "unknown"
                            try:
                                reason = result['udp'][port]['reason']+' response'
                            except:
                                reason = "port is responding to communication"
                            try:
                                addinfo = result['udp'][port]['extrainfo']
                            except:
                                addinfo = "there is no additional information"
                            try:
                                service_name = result['udp'][port]['name']
                            except:
                                service_name = "service name is not detected"
                            try:
                                cur_ver = result['udp'][port]['version']
                            except:
                                cur_ver = "Current version is not detected"
                            try:
                                cur_soft_title = result['udp'][port]['product']
                                if ' ' in cur_soft_title:
                                    cur_soft_title = cur_soft_title.split()[0].lower()
                                if 'windows' in cur_soft_title or 'linux' in cur_soft_title :
                                    cur_soft_title = "operating system service"
                            except:
                                cur_soft_title = "software running couldn't be detected"
                            udp_port = {'PortNum':portnumber, 'status':portstatus, 'reason': reason,'addinfo':addinfo,'Name':service_name,'version':cur_ver}
                        except:
                            pass
                        service = result['udp'][port]['name'] + " " + result['udp'][port]['version']
                        services_for_db.append(service)
                        services_for_display.append(udp_port)
                except:
                    pass
        return services_for_db,services_for_display



scan = networkscan("hosts.txt")
   