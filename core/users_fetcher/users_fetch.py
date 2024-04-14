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
if __name__ == "__main__":
    users = users_fetch()
    print(users.get_all_users())