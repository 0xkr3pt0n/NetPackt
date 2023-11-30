import psycopg2


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
    
    # function to insert new scan in the database when the user triggers a new scan
    def insert_scan(self, username, scan_name, ip_address, shared_with, current_datetime, status, scan_type, is_runscript):
        insert_query = f"INSERT INTO scans (scan_name, system_ip, username, shared_with, scan_date, current_status, scan_type, is_runscript) VALUES ('{scan_name}', '{ip_address}', '{username}', '{shared_with}', '{current_datetime}','{status}', '{scan_type}','{is_runscript}') RETURNING id"
        self.cursor.execute(insert_query)
        inserted_id = self.cursor.fetchone()[0]
        self.connection.commit()
        return inserted_id
    # fucntion to insert scan results
    def insert_scan_result(self, scan_id, svc, svc_product, svc_ver, port_number, script):
        insert_query = f"INSERT INTO netowrk_scan_result (scan_id, svc, svc_product, svc_ver, port_number, script) VALUES ('{scan_id}', '{svc}', '{svc_product}', '{svc_ver}', '{port_number}','{script}')"
        self.cursor.execute(insert_query)
        self.connection.commit()
    
    #function to insert findings and result of each scan
    def insert_finding(self, cveid, scanid, infected_service, port_number, is_easy, exploit_links):
        insert_query = f"INSERT INTO findings (cveid, scan_id, infected_service, port_number, is_easy, exploit_links) VALUES ('{cveid}', '{scanid}', '{infected_service}','{port_number}', '{is_easy}', '{exploit_links}')"
        self.cursor.execute(insert_query)
        self.connection.commit()
    
    #function to retrive scan from database
    def getscans(self, username):
        fetch_query = f"SELECT * FROM scans where username = '{username}' or shared_with like '%{username}%'"
        self.cursor.execute(fetch_query)
        result = self.cursor.fetchall()
        self.connection.commit()
        return result
    
    #set scan status from pending to completed when a scan finishes
    def scancomplete(self, scanid):
        update_query = f"UPDATE scans SET current_status = 'completed' WHERE id = {scanid}"
        self.cursor.execute(update_query)
        self.connection.commit()
    
    def updatescan(self, new_name, new_share, scanid):
        update_query = f"UPDATE scans SET scan_name = '{new_name}', shared_with = '{new_share}' WHERE id = {scanid}"
        self.cursor.execute(update_query)
        self.connection.commit()
    #function to get scan from database to display a report
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
    
    #function to get findings associated with each scan (it takes scanid as a forigen key)
    def getfindings(self, scanid):
        fetch_query = f"SELECT * FROM findings WHERE scan_id = {scanid}"
        self.cursor.execute(fetch_query)
        result = self.cursor.fetchall()
        self.connection.commit()
        return result
    
    def getOnline(self, scanid):
        fetch_query = f"SELECT * FROM api_result WHERE scan_id = {scanid}"
        self.cursor.execute(fetch_query)
        result = self.cursor.fetchall()
        returned_formatted_list = []
        self.connection.commit()
        for i in result:
            formatted_links = i[3].split(',')
            formatted_result = (i[0], i[1], i[2],formatted_links, i[4],i[5],i[6],i[7])
            returned_formatted_list.append(formatted_result)
        return returned_formatted_list
    #function to retrive cve details from database
    def retrive_cves(self, cveid):
        fetch_query = f"SELECT * FROM vulnerabilities WHERE cveid = '{cveid}'"
        self.cursor.execute(fetch_query)
        result = self.cursor.fetchone()
        if result:
            refrences = result[11].split(',')
            cve_dict = (result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7], result[8], result[9], result[10], refrences, result[12])
        self.connection.commit()
        return cve_dict
    
    #function to retrive users to select a shared with user
    def retrive_users(self):
        fetch_query = f"SELECT username FROM auth_user"
        self.cursor.execute(fetch_query)
        result = self.cursor.fetchall()
        return result
    
    #class destructor
    def __del__(self):
        self.cursor.close()
        self.connection.close()