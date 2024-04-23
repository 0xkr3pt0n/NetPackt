import psycopg2

class fetch_chat_info:
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
    def get_messages(self, username1, username2):
        query = f"select * from messages where sender = '{username1}' and reciver = '{username2}' or sender = '{username2}' and reciver = '{username1}'"
        self.cursor.execute(query)
        messages = self.cursor.fetchall()
        self.connection.commit()
        return messages
    