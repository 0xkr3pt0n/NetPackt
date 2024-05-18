import psycopg2
import time
import run



class scans_fetch:
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
        try:
            # Connection to the CVE database
            cve_connection = psycopg2.connect(
                host="localhost",
                database="cves",  
                user="postgres",
                password="postgres"
            )
            self.cve_connection = cve_connection
            self.cve_cursor = cve_connection.cursor()
        except Exception as e:
            print("Error connecting to database : ", e)
    def fetch_scans(self, user_id):
        fetch_query = f"SELECT * FROM scans where user_id = {user_id}"
        self.cursor.execute(fetch_query)
        result = self.cursor.fetchall()
        self.connection.commit()
        return result
    def fetch_shared_scans(self, user_id):
        fetch_query = f"SELECT * FROM shared_users WHERE user_id = {user_id}"
        self.cursor.execute(fetch_query)
        result = self.cursor.fetchall()
        self.connection.commit()
        scans = []
        for scanid in result:
            fetch_shared_scans = f"select * FROM scans where id = {scanid[0]}"
            self.cursor.execute(fetch_shared_scans)
            result = self.cursor.fetchall()
            self.connection.commit()
            scans.append(result)
        proccesed_data = [inner_tuple for sublist in scans for inner_tuple in sublist]
        return proccesed_data
    def fetch_scan_result(self, scan_id):
        query = f"SELECT * FROM vulnscan_report WHERE scan_id = {scan_id}"
        self.cursor.execute(query)
        report = self.cursor.fetchall()
        self.connection.commit()
        return report
    def fetch_scan_info(self, scan_id):
        query = f"SELECT * FROM scans WHERE id = {scan_id}"
        self.cursor.execute(query)
        scans = self.cursor.fetchall()
        self.connection.commit()
        return scans
    def get_vulnerability_detils(self, cve_id):
        query = f"SELECT * FROM cve WHERE cve_id = '{cve_id}' "
        self.cve_cursor.execute(query)
        cve_data = self.cve_cursor.fetchall()
        self.cve_connection.commit()
        query2 = f"SELECT * FROM refrences WHERE cve_id = '{cve_id}' "
        self.cve_cursor.execute(query2)
        refrences_data = self.cve_cursor.fetchall()
        self.cve_connection.commit()
        return cve_data, refrences_data
    def fetch_hostdiscovery_result(self, scan_id):
        query = f"select * from discoverd_ip where report_id = {scan_id}"
        self.cursor.execute(query)
        result = self.cursor.fetchall()
        self.connection.commit()
        print(result)
        return result
        
    def fetch_webscan_result(self, scan_id):
        query1 = f"SELECT * FROM subdomains_discoverd WHERE scan_id = {scan_id}"
        query2 = f"SELECT * FROM subdirectories_discoverd WHERE scan_id = {scan_id}"
        self.cursor.execute(query1)
        subdomains = self.cursor.fetchall()
        self.connection.commit()

        self.cursor.execute(query2)
        subdirs = self.cursor.fetchall()
        self.connection.commit()
        return subdomains, subdirs
    
    def fetch_waf_result(self, scan_id):
        query = f"SELECT * FROM discoverd_waf WHERE scan_id = {scan_id}"
        self.cursor.execute(query)
        wafs = self.cursor.fetchall()
        self.connection.commit()
        return wafs
    
    def get_user_scans(self, user_id):
        query = f"select * from scans where user_id = {user_id}"
        self.cursor.execute(query)
        scans = self.cursor.fetchall()
        self.connection.commit()
        return scans

    def delete_scan(self, scan_id):
        query1 =  f"DELETE FROM vulnscan_report where scan_id = {scan_id}"
        query2 = f"DELETE FROM subdomains_discoverd where scan_id = {scan_id}"
        query3 = f"DELETE FROM subdirectories_discoverd WHERE scan_id = {scan_id}"
        query4 = f"DELETE FROM discoverd_ip WHERE report_id = {scan_id}"
        query5 = f"DELETE FROM discoverd_waf WHERE scan_id = {scan_id}"
        query6 = f"DELETE FROM nf_ips WHERE scan_id = {scan_id}"
        query7 = f"DELETE FROM nf_statistics WHERE scan_id = {scan_id}"
        query8 = f"DELETE FROM workspaces_scans WHERE scan_id = {scan_id}"
        query9 = f"DELETE FROM scans where id = {scan_id}"
        self.cursor.execute(query1)
        self.cursor.execute(query2)
        self.cursor.execute(query3)
        self.cursor.execute(query4)
        self.cursor.execute(query5)
        self.cursor.execute(query6)
        self.cursor.execute(query7)
        self.cursor.execute(query8)
        self.cursor.execute(query9)
        self.connection.commit()
    
    def add_taskid(self, scan_id, task_id):
        query = f"UPDATE scans SET task_id = {task_id} where id = {scan_id}"
        self.cursor.execute(query)
        self.connection.commit()
    def pause_scan(self, scan_id):
        print('pausing scan')
        
        run.terminate_current()
        query = f"SELECT task_id from scans where id = {scan_id}"
        self.cursor.execute(query)
        task_id = self.cursor.fetchall()
        task_key = task_id[0][0]
        self.connection.commit()
        
        query2 = f"DELETE FROM background_task where id = {task_key}"
        self.cursor.execute(query2)
        self.connection.commit()
        
        query3 = f"UPDATE scans SET progress = 2 where id = {scan_id}"
        self.cursor.execute(query3)
        self.connection.commit()
        run.runAPP().process_tasks()
    
    def fetch_scans_workspace(self, user_id):
        fetch_query = f"SELECT id, scan_name FROM scans where user_id = {user_id}"
        self.cursor.execute(fetch_query)
        result = self.cursor.fetchall()
        self.connection.commit()
        return result
    
    def get_scan_type(self, scan_id):
        query = f"select scan_type from scans where id = {scan_id}"
        self.cursor.execute(query)
        scan_type = self.cursor.fetchall()
        self.connection.commit()
        scanType = scan_type[0][0]
        return scanType
    
    def fetch_nf_stats(self, scan_id):
        query = f"SELECT * from nf_statistics where scan_id = {scan_id}"
        self.cursor.execute(query)
        data = self.cursor.fetchall()
        self.connection.commit()
        return data
    
    def fetch_nf_ips(self, scan_id):
        query = f"SELECT * from nf_ips where scan_id = {scan_id}"
        self.cursor.execute(query)
        data = self.cursor.fetchall()
        self.connection.commit()
        return data

       
                
        

            


if __name__ == "__main__":
    scans = scans_fetch()
    data = scans.fetch_scans(3)
    print(data)