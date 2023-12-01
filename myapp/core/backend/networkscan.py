from . import mynmap
import base64
'''
this class responsable for scanning targeted network or a whole network by giving it a network prefix
Usage Example : scan = networkscan("hosts.txt"), infodb,infodisplay = self.scan(host)
Note : 
    [*] hosts.txt expected content
        192.168.1.1 or 192.168.1.0/24 or 192.168.1.1,192.168.1.2
'''

class networkscan:    
    #function to for scanning netowrk or a only one host
     
    def scan(self,network_prefix, scan_option):
        
        nm = mynmap.PortScanner()
        #argument T4 for threading
        if scan_option == '1':
            scan_raw_result = nm.scan(hosts=network_prefix, arguments='-p- -Sv -A -n -T4')
        else:
            scan_raw_result = nm.scan(hosts=network_prefix, arguments='-p- -v -n -A -T0')
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
                                product = result['tcp'][port]['product']
                            except:
                                product = "product name is not detected"
                            try:
                                cur_ver = result['tcp'][port]['version']
                            except:
                                cur_ver = "Current version is not detected"
                            if scan_option == "1":
                                tcp_port = {'PortNum':portnumber, 'status':portstatus, 'reason': reason,'addinfo':addinfo,'Name':service_name,'product':product,'version':cur_ver}
                            else:
                                try:
                                    scripts = result['tcp'][port]['script']
                                    dict_string = ', '.join([f'{key}:{value}' for key, value in scripts.items()])
                                except:
                                    scripts = "No script for this service"
                                tcp_port = {'PortNum':portnumber, 'status':portstatus, 'reason': reason,'addinfo':addinfo,'Name':service_name,'product':product, 'version':cur_ver, 'scripts':dict_string}
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
        return services_for_display




