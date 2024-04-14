import psycopg2

class insert_finding:
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
    def insert_subdomains(self, subdomains_list, scan_id):
        for domain in subdomains_list:
            query = f"INSERT INTO subdomains_discoverd (scan_id, domain) VALUES ('{scan_id}', '{domain}')"
            self.cursor.execute(query)
            self.connection.commit()
    def insert_subdirectories(self, subdirs_list, scan_id):
        for directory in subdirs_list:
            query = f"INSERT INTO subdirectories_discoverd (scan_id, directory) VALUES ('{scan_id}', '{directory}')"
            self.cursor.execute(query)
            self.connection.commit()
    def finish_scan(self, scan_id):
        query = f"UPDATE scans SET progress = 0 WHERE id = {scan_id}"
        self.cursor.execute(query)
        self.connection.commit()