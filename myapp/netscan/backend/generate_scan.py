import psycopg2
from . import database_connection

class GenerateScan:
    def __init__(self):
        self.db = database_connection.database()
    # function to insert new scan in the database when the user triggers a new scan
    def insert_scan(self, username, scan_name, ip_address, shared_with, current_datetime, status, scan_type, is_intrusive, scan_online):
        inserted_id = self.db.commit_to_database_rid(f"INSERT INTO scans (scan_name, system_ip, username, shared_with, scan_date, current_status, scan_type, is_intrusive, scan_online) VALUES ('{scan_name}', '{ip_address}', '{username}', '{shared_with}', '{current_datetime}','{status}', '{scan_type}','{is_intrusive}', '{scan_online}') RETURNING id")
        return inserted_id
    # fucntion to insert scan results
    def insert_scan_result(self, scan_id, svc, svc_product, svc_ver, port_number, script):
        self.db.commit_to_database( f"INSERT INTO netowrk_scan_result (scan_id, svc, svc_product, svc_ver, port_number, script) VALUES ('{scan_id}', '{svc}', '{svc_product}', '{svc_ver}', '{port_number}','{script}')")
    
    #function to insert findings and result of each scan
    def insert_finding(self, cveid, scanid, infected_service, port_number, is_easy, exploit_links):
        self.db.commit_to_database(f"INSERT INTO findings (cveid, scan_id, infected_service, port_number, is_easy, exploit_links) VALUES ('{cveid}', '{scanid}', '{infected_service}','{port_number}', '{is_easy}', '{exploit_links}')")
    
    #function to retrive scan from database
    def getscans(self, username):
        result = self.db.commit_to_database_data(f"SELECT * FROM scans where username = '{username}' or shared_with like '%{username}%'")
        return result
    
    #set scan status from pending to completed when a scan finishes
    def scancomplete(self, scanid):
        self.db.commit_to_database(f"UPDATE scans SET current_status = 'completed' WHERE id = {scanid}")
    
    def updatescan(self, new_name, new_share, scanid):
        self.db.commit_to_database(f"UPDATE scans SET scan_name = '{new_name}', shared_with = '{new_share}' WHERE id = {scanid}")
    #function to get scan from database to display a report
    def getreport(self, reportid):
        result = self.db.commit_to_database_dataOne(f"SELECT * FROM scans WHERE id = {reportid}")
        if result:
            report_dict = (result[0], result[1], result[2], result[3], result[4],result[5], result[6],result[9])
            print(report_dict)
            return report_dict
        else:
            return "none"
    
    #function to get findings associated with each scan (it takes scanid as a forigen key)
    def getfindings(self, scanid):
        result = self.db.commit_to_database_data(f"SELECT * FROM findings WHERE scan_id = {scanid}")
        return result
    
    #function to retrive scan result that scanned with api not the local DB
    def getOnline(self, scanid):
        result = self.db.commit_to_database_data(f"SELECT * FROM api_result WHERE scan_id = {scanid}")
        returned_formatted_list = []
        for i in result:
            formatted_links = i[3].split(',')
            formatted_result = (i[0], i[1], i[2],formatted_links, i[4],i[5],i[6],i[7])
            returned_formatted_list.append(formatted_result)
        return returned_formatted_list
    
    #function to retrive cve details from database
    def retrive_cves(self, cveid):
        result = self.db.commit_to_database_dataOne(f"SELECT * FROM vulnerabilities WHERE cveid = '{cveid}'")
        if result:
            refrences = result[11].split(',')
            cve_dict = (result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7], result[8], result[9], result[10], refrences, result[12])
        return cve_dict
    
    #function to retrive users to select a shared with user
    def retrive_users(self):
        result = self.db.commit_to_database_data(f"SELECT username FROM auth_user")
        return result
    def get_scan_result(self, scan_id):
        result = self.db.commit_to_database_data(f"SELECT * FROM netowrk_scan_result WHERE scan_id = {scan_id}")
        return result