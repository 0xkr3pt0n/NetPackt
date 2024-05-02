import psycopg2

class users_fetch:
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
    def get_all_users(self, user_id):
        get_query  = f"select id,username from auth_user where id != {user_id}"
        self.cursor.execute(get_query)
        users_data = self.cursor.fetchall()
        self.connection.commit()
        return users_data
    
    def userlogin_status(self, user_id):
        update_query = f"UPDATE auth_user set status = 1 where id = {user_id}"
        self.cursor.execute(update_query)
        self.connection.commit()
    
    def userlogout_status(self, user_id):
        update_query = f"UPDATE auth_user set status = 0 where id = {user_id}"
        self.cursor.execute(update_query)
        self.connection.commit()
    
    def delete_alluserdata(self, user_id):
        query1 = f"DELETE FROM vulnscan_report where scan_id = {scan_id}"
        query2 = f"DELETE FROM subdomains_discoverd where scan_id = {scan_id}"
        query3 = f"DELETE FROM subdirectories_discoverd WHERE scan_id = {scan_id}"
        query4 = f"DELETE FROM discoverd_ip WHERE report_id = {scan_id}"
        query5 = f"DELETE FROM discoverd_waf WHERE scan_id = {scan_id}"
        query6 = f"DELETE FROM nf_ips WHERE scan_id = {scan_id}"
        query7 = f"DELETE FROM nf_statistics WHERE scan_id = {scan_id}"
        query8 = f"DELETE FROM workspaces_scans WHERE scan_id = {scan_id}"
        query9 = f"DELETE FROM scans where id = {scan_id}"
    
if __name__ == "__main__":
    users = users_fetch()
    print(users.get_all_users())