import psycopg2
# from .networkscan import networkscan

class SearchDatabase:
    #class constructor
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


    def getData(self, infodisplay):
        searchresult = []
        for record in infodisplay:
            if record['version'] != '':
                version = record['version']
                service = record['Name']
                search_query = f"SELECT cveid FROM vulnerabilities WHERE product ILIKE '%{service}%' AND versions like '%{version}%' "
                # sending the query to postgres
                self.cursor.execute(search_query)
                result = self.cursor.fetchall()
                self.connection.commit()
                searchresult.append(result)

        return searchresult
    
    # closing database connection
    # class destructor to finsih database connection at the end.
    def __del__(self):
        self.cursor.close()
        self.connection.close()
