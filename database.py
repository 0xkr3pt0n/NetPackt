import psycopg2

class database_prepare:
    def __init__(self):
        try:
            #connection to database ([!] dont forget to modify connection parameters)
            connection = psycopg2.connect(
                host="localhost", #keep the same
                database="netpackt", #database name (change according to your dbname)
                user="postgres", # database username (change according to your username of postgres)
                password="postgres" # database password (change according to your password of postgres)
            )
            cursor = connection.cursor()
            self.connection = connection
            self.cursor = cursor         
        except Exception as e:
            print("Error connecting to database : ", e)
        #class destructor

        #create tables
        self.create_Vulnscanreport_table()
        self.create_hostdiscoveryreport_table()
        self.create_discoverdip_table()
        self.create_scans_table()
        self.create_sharedusers_table()

    
    def create_Vulnscanreport_table(self):
        try:
            create_table_query = '''
            CREATE TABLE IF NOT EXISTS vulnscan_report (
                id SERIAL PRIMARY KEY,
                cve_id VARCHAR(255),
                scan_id INTEGER,
                exploitability INTEGER
            )
            '''
            self.cursor.execute(create_table_query)
            self.connection.commit()
            print("Table 'vulnscanreport' created successfully or already exists.")
        except Exception as e:
            print("Error creating table: ", e)
    
    def create_hostdiscoveryreport_table(self):
        try:
            create_table_query = '''
            CREATE TABLE IF NOT EXISTS hostdiscovery_report (
                id SERIAL PRIMARY KEY,
                scan_id INTEGER
            )
            '''
            self.cursor.execute(create_table_query)
            self.connection.commit()
            print("Table 'hostdiscovert_report' created successfully or already exists.")
        except Exception as e:
            print("Error creating table: ", e)
    
    def create_discoverdip_table(self):
        try:
            create_table_query = '''
            CREATE TABLE IF NOT EXISTS discoverd_ip (
                report_id INTEGER REFERENCES hostdiscovery_report(id),
                ip_address VARCHAR(255),
                MAC_address VARCHAR(255),
                device_name VARCHAR(255)
            )
            '''
            self.cursor.execute(create_table_query)
            self.connection.commit()
            print("Table 'discoverd_ip' created successfully or already exists.")
        except Exception as e:
            print("Error creating table: ", e)
    def create_scans_table(self):
        try:
            # SQL query to create the scans table if it does not exist
            create_table_query = '''
                CREATE TABLE IF NOT EXISTS scans (
                    id SERIAL PRIMARY KEY,
                    scan_name VARCHAR(255),
                    scan_type INTEGER,
                    progress INTEGER,
                    IP_SUBNET VARCHAR(255),
                    USER_ID INTEGER REFERENCES auth_user(id),
                    vulnreport_id INTEGER REFERENCES vulnscan_report(id) DEFAULT 0,
                    hostdiscover_id INTEGER REFERENCES hostdiscovery_report DEFAULT 0,
                    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            '''
            # execute the create table query
            self.cursor.execute(create_table_query)
            self.connection.commit()
            print("Table 'scans' created successfully or already exists.")
        except Exception as e:
            print("Error creating table: ", e)
    def create_sharedusers_table(self):
        try:
            # SQL query to create the scans table if it does not exist
            create_table_query = '''
                CREATE TABLE IF NOT EXISTS shared_users (
                    scan_id INTEGER REFERENCES scans(id) DEFAULT 0,
                    USER_ID INTEGER REFERENCES auth_user(id)
                )
            '''
            # execute the create table query
            self.cursor.execute(create_table_query)
            self.connection.commit()
            print("Table 'shared_users' created successfully or already exists.")
        except Exception as e:
            print("Error creating table: ", e)


db = database_prepare()