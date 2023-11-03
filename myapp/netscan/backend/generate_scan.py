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
    def getscans(self):
        fetch_query = f"SELECT * FROM scans"
        self.cursor.execute(fetch_query)
        result = self.cursor.fetchall()
        self.connection.commit()
        return result
    def scancomplete(self, scanid):
        update_query = f"UPDATE scans SET current_status = 'completed' WHERE id = {scanid}"
        self.cursor.execute(update_query)
        self.connection.commit()
    def getreport(self, reportid):
        fetch_query = f"SELECT * FROM scans WHERE id = {reportid}"
        self.cursor.execute(fetch_query)
        result = self.cursor.fetchone()
        self.connection.commit()
        if result:
            report_dict = (result[0], result[1], result[2], result[3], result[4],result[5], result[6])
            return report_dict
        else:
            return "none"
    def getfindings(self, scanid):
        fetch_query = f"SELECT * FROM findings WHERE scan_id = {scanid}"
        self.cursor.execute(fetch_query)
        result = self.cursor.fetchall()
        self.connection.commit()
        return result
    def retrive_cves(self, cveid):
        fetch_query = f"SELECT * FROM vulnerabilities WHERE cveid = '{cveid}'"
        self.cursor.execute(fetch_query)
        result = self.cursor.fetchone()
        self.connection.commit()
        return result
    def __del__(self):
        self.cursor.close()
        self.connection.close()