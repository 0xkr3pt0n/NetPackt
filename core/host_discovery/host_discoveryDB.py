import psycopg2
class host_discoverDB:
    def __init__(self):
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
    def insertfindings(self, hosts_list, scan_id):
        for host in hosts_list:
            ip = host['IP']
            try:
                MAC = host['MAC']
            except:
                MAC = 'n/a'
            try:
                Vendor = host['Vendor']
            except:
                Vendor = 'n/a' 
            query = f"INSERT INTO discoverd_ip (report_id, ip_address, mac_address, device_name) VALUES ('{scan_id}', '{ip}', '{MAC}', '{Vendor}')"
            self.cursor.execute(query)
            self.connection.commit()
    def scan_complete(self, scan_id):
        progress = 0
        query = f"UPDATE scans set progress = 0 where id = {scan_id}"
        self.cursor.execute(query)
        self.connection.commit()