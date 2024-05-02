import psycopg2

class delete_messages:
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
    def delete_allusermessages(self, username):
        query = f"DELETE from messages where sender = '{username}' or reciver= '{username}' "
        self.cursor.execute(query)
        self.connection.commit()