import psycopg2

class insert_finding:
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
    def insert_subdomains(self, subdomains_list, scan_id):
        for domain in subdomains_list:
            query = f"INSERT INTO subdomains_discoverd (scan_id, domain) VALUES ('{scan_id}', '{domain}')"
            self.cursor.execute(query)
            self.connection.commit()