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
    def fetch_scans(self, user_id):
        fetch_query = f"SELECT * FROM scans where user_id = {user_id}"
        self.cursor.execute(fetch_query)
        result = self.cursor.fetchall()
        self.connection.commit()
        return result

if __name__ == "__main__":
    scans = scans_fetch()
    data = scans.fetch_scans(3)
    print(data)