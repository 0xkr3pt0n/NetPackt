from scapy.all import *
from pysafebrowsing import SafeBrowsing
import psycopg2
class pcap_analyzer:
    def __init__(self, pcap_file, scan_id):
        self.pcap_file = pcap_file
        self.scan_id = scan_id
        try:
            # Connection to the CVE database
            connection = psycopg2.connect(
                host="localhost",
                database="netpackt",  
                user="postgres",
                password="postgres"
            )
            self.connection = connection
            self.cursor = connection.cursor()
        except Exception as e:
            print("Error connecting to database : ", e)
    
    #basic analyzer func returns pcap file statistics
    def pacp_analyze(self):
        packets = rdpcap(self.pcap_file)
        packets_number = len(packets) # number of packets contained in the pcap file
        tcp_number = 0 # number of tcp packets in the pcap file
        udp_number = 0 # number of udp packets in the pcap file
        for packet in packets:
            if TCP in packet:
                tcp_number +=1
            elif UDP in packet:
                udp_number +=1
        ip_number = 0 # number of IP addresses in the pacp file

        ip_address = {} # contains ip address found in the pcap file
        for packet in packets:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                if src_ip not in ip_address:
                    ip_address[src_ip] = "src"
                    ip_number +=1
                if dst_ip not in ip_address:
                    ip_number +=1
                    ip_address[dst_ip] = "dst"
        data = {'packets_number':packets_number, 'tcp_number':tcp_number, 'udp_number':udp_number, 'ip_number':ip_number , 'ip_address':ip_address}
        return data
    
    def result_insertion(self, data):
        query = f"UPDATE scans SET progress = 0 WHERE id = {self.scan_id}"
        self.cursor.execute(query)
        self.connection.commit()
        packets_num = data['packets_number']
        tcp_num = data['tcp_number']
        udp_num = data['udp_number']
        ip_num = data['ip_number']
        query2 = f"INSERT INTO nf_statistics (scan_id, packets_num, tcp_packets, udp_packets, ips_count) VALUES ('{self.scan_id}', '{packets_num}', '{tcp_num}', '{udp_num}', '{ip_num}')"
        self.cursor.execute(query2)
        self.connection.commit()
        
        for ip,direction in data['ip_address'].items():
            query3 = f"INSERT INTO nf_ips (scan_id, ip, ip_type) VALUES ('{self.scan_id}', '{ip}', '{direction}')"
            self.cursor.execute(query3)
            self.connection.commit()

        
            
        



# s = pcap_analyzer("sus.pcap")
# s.pacp_analyzer()

# s = SafeBrowsing("AIzaSyCUanWShpIGTKGY2Wr4-YIPtLnIWnITnQM")
# r = s.lookup_urls([''])
# print(r)