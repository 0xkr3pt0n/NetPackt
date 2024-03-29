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
    def vulnerability_scan(self, scan_name, ip_subnet, user_id, shared_list):
        scan_progress = 1 #started
        scan_type = 0
        create_scan_query = f"INSERT INTO scans (scan_name, scan_type, progress, ip_subnet, user_id) VALUES ('{scan_name}', '{scan_type}', '{scan_progress}','{ip_subnet}','{user_id}') RETURNING id"
        self.cursor.execute(create_scan_query)
        scan_id = self.cursor.fetchone()[0]
        self.connection.commit()
        if len(shared_list) > 0:
            for shared_user_id in shared_list:
                insert_shared_query = f"INSERT INTO shared_users (scan_id, user_id) VALUES ('{scan_id}' , '{shared_user_id}')"
                self.cursor.execute(insert_shared_query)
                self.connection.commit()
        return scan_id
    def host_discovery(self, scan_name, subnet, user_id, shared_list):
        scan_type = 1
        progress = 1 
        create_scan_query = f"insert into scans (scan_name, scan_type, progress, ip_subnet, user_id) VALUES ('{scan_name}', '{scan_type}','{progress}', '{subnet}','{user_id}') RETURNING id"
        self.cursor.execute(create_scan_query)
        scan_id = self.cursor.fetchone()[0]
        self.connection.commit()
        if len(shared_list) > 0:
            for shared_user_id in shared_list:
                insert_shared_query = f"INSERT INTO shared_users (scan_id, user_id) VALUES ('{scan_id}' , '{shared_user_id}')"
                self.cursor.execute(insert_shared_query)
                self.connection.commit()
        return scan_id
    def webscan(self, scan_name, target, user_id, shared_list):
        scan_type = 2
        progress = 1 
        create_scan_query = f"insert into scans (scan_name, scan_type, progress, ip_subnet, user_id) VALUES ('{scan_name}', '{scan_type}','{progress}', '{target}','{user_id}') RETURNING id"
        self.cursor.execute(create_scan_query)
        scan_id = self.cursor.fetchone()[0]
        self.connection.commit()
        if len(shared_list) > 0:
            for shared_user_id in shared_list:
                insert_shared_query = f"INSERT INTO shared_users (scan_id, user_id) VALUES ('{scan_id}' , '{shared_user_id}')"
                self.cursor.execute(insert_shared_query)
                self.connection.commit()
        return scan_id
    def waf_enum(self, scan_name, target, user_id, shared_list):
        scan_type = 3
        progress = 1 
        create_scan_query = f"insert into scans (scan_name, scan_type, progress, ip_subnet, user_id) VALUES ('{scan_name}', '{scan_type}','{progress}', '{target}','{user_id}') RETURNING id"
        self.cursor.execute(create_scan_query)
        scan_id = self.cursor.fetchone()[0]
        self.connection.commit()
        if len(shared_list) > 0:
            for shared_user_id in shared_list:
                insert_shared_query = f"INSERT INTO shared_users (scan_id, user_id) VALUES ('{scan_id}' , '{shared_user_id}')"
                self.cursor.execute(insert_shared_query)
                self.connection.commit()
        return scan_id