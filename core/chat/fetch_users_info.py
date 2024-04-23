import psycopg2

class fetch_users_info:
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
        get_query  = f"select id,username,status,last_login from auth_user where id != {user_id}"
        self.cursor.execute(get_query)
        users_data = self.cursor.fetchall()
        self.connection.commit()
        return users_data
    def get_user_lastlogin(self, username):
        get_query  = f"select last_login from auth_user where username = '{username}'"
        self.cursor.execute(get_query)
        users_data = self.cursor.fetchall()
        self.connection.commit()
        return users_data