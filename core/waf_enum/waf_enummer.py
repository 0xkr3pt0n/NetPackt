import psycopg2
from . import main

class waf_enumer:
    def __init__(self, target, scan_id):
        self.target = target
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
    
    def scan_target(self):
        discoverd_waf = main.main([self.target])
        print(discoverd_waf)
        if len(discoverd_waf) > 0:
            self.insert_result(discoverd_waf[0])
        else:
            self.insert_result("No WAF Detected")
        self.finish_scan()
    
    def insert_result(self, result):
        query = f"INSERT INTO discoverd_waf (scan_id, waf) VALUES ('{self.scan_id}', '{result}')"
        self.cursor.execute(query)
        self.connection.commit()
    def finish_scan(self):
        query = f"UPDATE scans SET progress = 0 WHERE id = {self.scan_id}"
        self.cursor.execute(query)
        self.connection.commit()
