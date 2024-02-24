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
            


if __name__ == "__main__":
    scans = scans_fetch()
    data = scans.fetch_scans(3)
    print(data)