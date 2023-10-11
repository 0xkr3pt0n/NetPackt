import nmap

def nmap_A_scan(network_prefix):
    nm = nmap.PortScanner()
    
    scan_raw_result = nm.scan(hosts=network_prefix, arguments='-v -n -A')
    
    
    for host, result in scan_raw_result['scan'].items():
        if result['status']['state'] == 'up':
            print('#' * 17 + 'Host:' + host + '#' * 17)
            idno = 1
            try:
                for port in result['tcp']:
                    try:
                        print('-' * 17 + "TCP server details" + '[' + str(idno) + ']' + '-' * 17)
                        idno += 1
                        print('port number TCP:' + str(port))
                        try:
                            print('status:' + result['tcp'][port]['state'])
                        except:
                            pass
                        try:
                            print('reason:' + result['tcp'][port]['reason']+' response')
                        except:
                            pass
                        try:
                            print('additional information:' + result['tcp'][port]['extrainfo'])
                        except:
                            pass
                        try:
                            print('Name:' + result['tcp'][port]['name'])
                        except:
                            pass
                        try:
                            cur_ver = result['tcp'][port]['version']
                            # cur_ver = '8.2.0'
                            print('version:' + result['tcp'][port]['version'])
                        except:
                            pass
                    except:
                        pass
            except:
                pass

            idno = 1
            try:
                for port in result['udp']:
                    try:
                        print('-' * 17 + "Server detils UDP" + '[' + str(idno) + ']' + '-' * 17)
                        idno += 1
                        print('port number UDP:' + str(port))
                        try:
                            print('state:' + result['udp'][port]['state'])
                        except:
                            pass
                        try:
                            print('reason:' + result['udp'][port]['reason'])
                        except:
                            pass
                        try:
                            print('additional information:' + result['udp'][port]['extrainfo'])
                        except:
                            pass
                        try:
                            print('Name:' + result['udp'][port]['name'])
                        except:
                            pass
                        try:
                            print('Version:' + result['udp'][port]['version'])
                            cur_ver =result['udp'][port]['version']
                        except:
                            pass
                        try:
                            cur_soft_title = result['udp'][port]['product']
                            print('сервис:' + cur_soft_title)
                            if ' ' in cur_soft_title:
                                cur_soft_title = cur_soft_title.split()[0].lower()
                            if 'windows' in cur_soft_title or 'linux' in cur_soft_title :
                                cur_soft_title = None
                        except:
                            pass
                        try:
                            print('CPE:' + result['udp'][port]['cpe'])
                        except:
                            pass
                        try:
                            print("script:" + result['udp'][port]['script'])
                        except:
                            pass
                            
                    except:
                        pass
            except:
                pass


if __name__ == '__main__':
    print('start...')
    with open('hosts.txt') as hosts:
        for host in hosts:
            nmap_A_scan(host)
