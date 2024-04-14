import psycopg2

class workspace_fetcher:
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
        
    
    def fetch_workspaces(self):
        query = f"SELECT * FROM workspaces"
        self.cursor.execute(query)
        workspaces = self.cursor.fetchall()
        self.connection.commit()
        return workspaces
    
    def fetch_workspace(self, space_id):
        query = f"SELECT * FROM workspaces where id = {space_id}"
        self.cursor.execute(query)
        workspaces = self.cursor.fetchall()
        self.connection.commit()
        return workspaces
    
    def delete_workspace(self, space_id):
        query = f"DELETE FROM workspaces where id = {space_id}"
        self.cursor.execute(query)
        self.connection.commit()
    
    def addscan_workspace(self, scan_id, space_id):
        query = f"INSERT INTO workspaces_scans (workspace_id, scan_id) VALUES ('{space_id}', '{scan_id}')"
        self.cursor.execute(query)
        self.connection.commit()
    
    def workspace_scans_fetch(self, space_id):
        query = f"SELECT scan_id FROM workspaces_scans WHERE workspace_id = {space_id}"
        self.cursor.execute(query)
        scans = self.cursor.fetchall()
        self.connection.commit()
        data_returned = []
        for i in scans:
            for j in i:
                query2 = f"select scan_name, scan_type from scans where id = {j}"
                self.cursor.execute(query2)
                scanss = self.cursor.fetchall()
                self.connection.commit()
                data_returned.append(scanss)
        proccesed_list = []
        for i in data_returned:
            for j in i:
                proccesed_list.append(j)
        return proccesed_list
    
    def workspace_scans_fetch_all(self, space_id):
        query = f"SELECT scan_id FROM workspaces_scans WHERE workspace_id = {space_id}"
        self.cursor.execute(query)
        scans = self.cursor.fetchall()
        self.connection.commit()
        data_returned = []
        for i in scans:
            for j in i:
                query2 = f"select * from scans where id = {j}"
                self.cursor.execute(query2)
                scanss = self.cursor.fetchall()
                self.connection.commit()
                data_returned.append(scanss)
        proccesed_list = []
        for i in data_returned:
            for j in i:
                proccesed_list.append(j)
        return proccesed_list