import psycopg2

class send_message:
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
    def send_message(self, sender_username, reciver_username, message):
        query = f"INSERT INTO messages (sender, reciver, message, status) values ('{sender_username}', '{reciver_username}', '{message}', 0)"
        self.cursor.execute(query)
        self.connection.commit()