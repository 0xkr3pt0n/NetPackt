import psycopg2


class database:
    def __init__(self):
        try:
            #connection to database ([!] dont forget to modify connection parameters)
            connection = psycopg2.connect(
                host="localhost", #keep the same
                database="netimpact", #database name (change according to your dbname)
                user="postgres", # database username (change according to your username of postgres)
                password="postgres" # database password (change according to your password of postgres)
            )
            cursor = connection.cursor()
            self.connection = connection
            self.cursor = cursor         
        except Exception as e:
            print("Error connecting to database : ", e)
        #class destructor
    def commit_to_database(self, query, parameter=None):
        self.cursor.execute(query, parameter)
        self.connection.commit()
    def commit_to_database_data(self, query, parameter=None):
        self.cursor.execute(query)
        result = self.cursor.fetchall()
        self.connection.commit()
        return result
    def commit_to_database_rid(self,query, parameter=None):
        self.cursor.execute(query)
        inserted_id = self.cursor.fetchone()[0]
        self.connection.commit()
        return inserted_id
    def commit_to_database_dataOne(self, query, parameter=None):
        self.cursor.execute(query)
        result = self.cursor.fetchone()
        self.connection.commit()
        return result
    
    def __del__(self):
        self.cursor.close()
        self.connection.close()