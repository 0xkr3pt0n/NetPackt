import psycopg2

class workspace_create:
    def __init__(self, workspace):
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
        self.workspace = workspace
    
    def create_workspace(self):
        query = f"INSERT INTO workspaces (name) VALUES ('{self.workspace}')"
        self.cursor.execute(query)
        self.connection.commit()
