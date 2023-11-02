import psycopg2
import datetime

class GenerateScan:
    
    def __init__(self):
        try:
            #connection to database ([!] dont forget to modify connection parameters)
            connection = psycopg2.connect(
                host="localhost", #keep the same
                database="netimpact", #database name (change according to your dbname)
                user="postgres", # database username (change according to your username of postgres)
                password="postgres" # database password (change according to your password of postgres)
            )
            cursor = connection.cursor()
            self.connection = connection
            self.cursor = cursor         
        except Exception as e:
            print("Error connecting to database : ", e)
    
    def insert_scan(self, username, scan_name, ip_address, shared_with, current_datetime, status):
        
        insert_query = f"INSERT INTO scans (scan_name, system_ip, username, shared_with, scan_date, current_status) VALUES ('{scan_name}', '{ip_address}', '{username}', '{shared_with}', '{current_datetime}','{status}') RETURNING id"
        self.cursor.execute(insert_query)
        inserted_id = self.cursor.fetchone()[0]
        self.connection.commit()
        return inserted_id
    
    def insert_finding(self, cveid, scanid):
        insert_query = f"INSERT INTO findings (cveid, scan_id) VALUES ('{cveid}', '{scanid}')"
        self.cursor.execute(insert_query)
        self.connection.commit()
    def __del__(self):
        self.cursor.close()
        self.connection.close()