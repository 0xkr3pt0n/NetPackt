import psycopg2

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

            


if __name__ == "__main__":
    scans = scans_fetch()
    data = scans.fetch_scans(3)
    print(data)