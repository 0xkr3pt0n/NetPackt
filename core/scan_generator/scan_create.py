import psycopg2

class scan_create:
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
    def vulnerability_scan(self, scan_name, ip_subnet, user_id):
        scan_progress = 1 #started
        scan_type = 0
        create_scan_query = f"INSERT INTO scans (scan_name, scan_type, progress, ip_subnet, user_id) VALUES ('{scan_name}', '{scan_type}', '{scan_progress}','{ip_subnet}','{user_id}') RETURNING id"
        self.cursor.execute(create_scan_query)
        scan_id = self.cursor.fetchone()[0]
        self.connection.commit()
        return scan_id
