import psycopg2
import subprocess

class netpackt_database_prepare:
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
        self.create_djangousers_table()
        self.add_api_column()
        self.add_status_column()
        self.create_scans_table()
        self.create_Vulnscanreport_table()
        self.create_apiresults_table()
        self.api_refrences_table()
        self.create_hostdiscoveryreport_table()
        self.create_discoverdip_table()
        self.create_sharedusers_table()
        self.create_disoverd_subdomains_table()
        self.create_disoverd_subdirs_table()
        self.add_isempty_columns()
        self.add_background_taskid()
        self.create_db()
        self.create_discoverd_waf_table()
        self.create_workspaces_table()
        self.create_workspaces_scans_table()
        self.create_nfstatistics_table()
        self.create_nfIps_table()
        self.create_messages_table()
        self.create_friend_request_table()  # Add this line to create the friend_request table
    
    def create_db(self):
        self.cursor.execute("SELECT 1 FROM pg_catalog.pg_database WHERE datname = 'netpackt'")
        db_exists = self.cursor.fetchone()

        # If the database does not exist, create it
        if not db_exists:
            try:
                query = "CREATE DATABASE netpackt WITH OWNER = postgres ENCODING = 'UTF8' LOCALE_PROVIDER = 'libc' CONNECTION LIMIT = -1 IS_TEMPLATE = False"
                self.cursor.execute(query)
                self.connection.commit()
                print("Database 'netpackt' created successfully.")
            except psycopg2.Error as e:
                print("Error: Unable to create database.")
                print(e)
        else:
            print("Database 'netpackt' already exists.")
            
    def create_messages_table(self):
        try:
            # SQL query to create the scans table if it does not exist
            create_table_query = '''
                CREATE TABLE IF NOT EXISTS messages (
                    id SERIAL PRIMARY KEY,
                    sender text REFERENCES auth_user(username),
                    reciver text REFERENCES auth_user(username),
                    message TEXT,
                    Date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status INTEGER
                )
            '''
            # execute the create table query
            self.cursor.execute(create_table_query)
            self.connection.commit()
            print("Table 'messages' created successfully or already exists.")
        except Exception as e:
            print("Error creating table: ", e)

    def create_djangousers_table(self):
        command1 = "python manage.py makemigrations"
        command2 = "python manage.py migrate"
        result1 = subprocess.run(command1, shell=True, capture_output=True, text=True) 
        result2 = subprocess.run(command2, shell=True, capture_output=True, text=True) 
        print(result1.stdout)
        print(result2.stdout)
    
    def add_api_column(self):
        try:
            add_column_query = "ALTER TABLE auth_user ADD COLUMN IF NOT EXISTS api_option INTEGER DEFAULT 0;"
            self.cursor.execute(add_column_query)
            self.connection.commit()
            print("column 'api_option' added successfully or already exists.")
        except Exception as e:
            print("Error creating table: ", e)
            
    def add_status_column(self):
        try:
            add_column_query = "ALTER TABLE auth_user ADD COLUMN IF NOT EXISTS status INTEGER DEFAULT 0;"
            self.cursor.execute(add_column_query)
            self.connection.commit()
            print("column 'status' added successfully or already exists.")
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
                    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            '''
            # execute the create table query
            self.cursor.execute(create_table_query)
            self.connection.commit()
            print("Table 'scans' created successfully or already exists.")
        except Exception as e:
            print("Error creating table: ", e)
    
    def create_Vulnscanreport_table(self):
        try:
            create_table_query = '''
            CREATE TABLE IF NOT EXISTS vulnscan_report (
                id SERIAL PRIMARY KEY,
                scan_id INTEGER REFERENCES scans(id),
                portnumber VARCHAR(255),
                service VARCHAR(255),
                version VARCHAR(255),
                cve_id VARCHAR(255),
                exploitability INTEGER
            )
            '''
            self.cursor.execute(create_table_query)
            self.connection.commit()
            print("Table 'vulnscanreport' created successfully or already exists.")
        except Exception as e:
            print("Error creating table: ", e)
    
    def create_apiresults_table(self):
        try:
            create_table_query = '''
                CREATE TABLE IF NOT EXISTS api_results (
                    id SERIAL PRIMARY KEY,    
                    scan_id INTEGER REFERENCES scans(id),
                    portnumber VARCHAR(255),
                    service VARCHAR(255),
                    version VARCHAR(255),
                    CVE_ID VARCHAR(255),
                    Impact DOUBLE PRECISION,
                    Description TEXT
                )
            '''
            self.cursor.execute(create_table_query)
            self.connection.commit()
            print("Table 'api_results' created successfully or already exists.")
        except Exception as e:
            print("Error creating table", e)
    
    def api_refrences_table(self):
        try:
            create_table_query = '''
                CREATE TABLE IF NOT EXISTS api_refrences (   
                    api_id INTEGER REFERENCES api_results(id),
                    refrence TEXT,
                    refrence_type INTEGER
                )
            '''
            self.cursor.execute(create_table_query)
            self.connection.commit()
            print("Table 'api_refrences' created successfully or already exists.")
        except Exception as e:
            print("Error creating table", e)

    def create_hostdiscoveryreport_table(self):
        try:
            create_table_query = '''
            CREATE TABLE IF NOT EXISTS hostdiscovery_report (
                id SERIAL PRIMARY KEY,
                scan_id INTEGER REFERENCES scans(id)
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
    
    def create_disoverd_subdomains_table(self):
        try:
            create_table_query = '''
            CREATE TABLE IF NOT EXISTS subdomains_discoverd (
                id SERIAL PRIMARY KEY,
                scan_id INTEGER REFERENCES scans(id),
                domain TEXT
            )
            '''
            self.cursor.execute(create_table_query)
            self.connection.commit()
            print("Table 'subdomain' created successfully or already exists.")
        except Exception as e:
            print("Error creating table: ", e)
    
    def create_disoverd_subdirs_table(self):
        try:
            create_table_query = '''
            CREATE TABLE IF NOT EXISTS subdirectories_discoverd (
                id SERIAL PRIMARY KEY,
                scan_id INTEGER REFERENCES scans(id),
                directory TEXT
            )
            '''
            self.cursor.execute(create_table_query)
            self.connection.commit()
            print("Table 'subdires' created successfully or already exists.")
        except Exception as e:
            print("Error creating table: ", e)
        
    def add_isempty_columns(self):
        try:
            add_column_query1 = "ALTER TABLE scans ADD COLUMN IF NOT EXISTS isportscan_empty INTEGER DEFAULT 0;"
            add_column_query2 = "ALTER TABLE scans ADD COLUMN IF NOT EXISTS isvulnscan_empty INTEGER DEFAULT 0;"
            self.cursor.execute(add_column_query1)
            self.cursor.execute(add_column_query2)
            self.connection.commit()
            print("column 'isportscan_empty, isvulnscan_empty' added successfully or already exists.")
        except Exception as e:
            print("Error creating table: ", e)
    
    def add_background_taskid(self):
        try:
            add_column_query1 = "ALTER TABLE scans ADD COLUMN IF NOT EXISTS task_id INTEGER;"
            self.cursor.execute(add_column_query1)
            self.connection.commit()
            print("column 'task_id, isvulnscan_empty' added successfully or already exists.")
        except Exception as e:
            print("Error creating table: ", e)

    def create_discoverd_waf_table(self):
        try:
            create_table_query = '''
            CREATE TABLE IF NOT EXISTS discoverd_waf (
                id SERIAL PRIMARY KEY,
                scan_id INTEGER REFERENCES scans(id),
                waf TEXT
            )
            '''
            self.cursor.execute(create_table_query)
            self.connection.commit()
            print("Table 'discoverd_waf' created successfully or already exists.")
        except Exception as e:
            print("Error creating table: ", e)
    
    def create_nfIps_table(self):
        try:
            create_table_query = '''
            CREATE TABLE IF NOT EXISTS nf_ips (
                id SERIAL PRIMARY KEY,
                scan_id INTEGER REFERENCES scans(id),
                ip TEXT,
                ip_type TEXT
            )
            '''
            self.cursor.execute(create_table_query)
            self.connection.commit()
            print("Table 'nf_ips' created successfully or already exists.")
        except Exception as e:
            print("Error creating table: ", e)
    def create_nfstatistics_table(self):
        try:
            create_table_query = '''
            CREATE TABLE IF NOT EXISTS nf_statistics (
                id SERIAL PRIMARY KEY,
                scan_id INTEGER REFERENCES scans(id),
                packets_num INTEGER,
                tcp_packets INTEGER,
                udp_packets INTEGER,
                ips_count INTEGER
            )
            '''
            self.cursor.execute(create_table_query)
            self.connection.commit()
            print("Table 'nf_statistics' created successfully or already exists.")
        except Exception as e:
            print("Error creating table: ", e)

    def create_workspaces_table(self):
        try:
            create_table_query = '''
            CREATE TABLE IF NOT EXISTS workspaces (
                id SERIAL PRIMARY KEY,
                name TEXT,
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            '''
            self.cursor.execute(create_table_query)
            self.connection.commit()
            print("Table 'workspaces' created successfully or already exists.")
        except Exception as e:
            print("Error creating table: ", e)
    
    def create_workspaces_scans_table(self):
        try:
            create_table_query = '''
            CREATE TABLE IF NOT EXISTS workspaces_scans (
                workspace_id INTEGER REFERENCES workspaces(id),
                scan_id INTEGER REFERENCES scans(id)    
            )
            '''
            self.cursor.execute(create_table_query)
            self.connection.commit()
            print("Table 'workspaces_scans' created successfully or already exists.")
        except Exception as e:
            print("Error creating table: ", e)
            
    def create_friend_request_table(self):
        try:
            create_table_query = '''
            CREATE TABLE IF NOT EXISTS friend_request (
                id SERIAL PRIMARY KEY,
                from_user_id INTEGER REFERENCES auth_user(id),
                to_user_id INTEGER REFERENCES auth_user(id),
                created_at TIMESTAMP DEFAULT NOW(),
                accepted BOOLEAN DEFAULT FALSE
            )
            '''
            self.cursor.execute(create_table_query)
            self.connection.commit()
            print("Table 'friend_request' created successfully or already exists.")
        except Exception as e:
            print("Error creating table: ", e)

class cves_database_prepare:
    def __init__(self):
        try:
            #connection to database ([!] dont forget to modify connection parameters)
            connection = psycopg2.connect(
                host="localhost", #keep the same
                database="cves", #database name (change according to your dbname)
                user="postgres", # database username (change according to your username of postgres)
                password="postgres" # database password (change according to your password of postgres)
            )
            cursor = connection.cursor()
            self.connection = connection
            self.cursor = cursor         
        except Exception as e:
            print("Error connecting to database : ", e)
        self.create_cve_table()
        self.create_cpes_table()
        self.create_refrences_table()
        self.create_cpeMatchURI_table()
        self.create_cpeMatchNames_table()
    def create_db(self):
        query = "CREATE DATABASE cves IF NOT EXISTS WITH OWNER = postgres ENCODING = 'UTF8' LOCALE_PROVIDER = 'libc' CONNECTION LIMIT = -1 IS_TEMPLATE = False"
        self.connection.autocommit = True
        self.cursor.execute(query)
        self.connection.commit()
    def create_cve_table(self):
        try:
            # SQL query to create the scans table if it does not exist
            create_cve_table_query = '''
                CREATE TABLE IF NOT EXISTS cve (
                    cve_id VARCHAR(255) PRIMARY KEY,
                    cve_description TEXT,
                    exploitability_score DOUBLE PRECISION,
                    impact_score DOUBLE PRECISION,
                    attack_complexity VARCHAR(255)
                )
            '''
            # execute the create table query
            self.cursor.execute(create_cve_table_query)
            self.connection.commit()
            print("Table 'cve' created successfully or already exists.")
        except Exception as e:
            print("Error creating table: ", e)
    def create_cpes_table(self):
        try:
            # SQL query to create the scans table if it does not exist
            create_cpes_table_query = '''
                CREATE TABLE IF NOT EXISTS cpes (
                    cve_id VARCHAR(255) REFERENCES cve(cve_id),
                    cpe TEXT
                )
            '''
            # execute the create table query
            self.cursor.execute(create_cpes_table_query)
            self.connection.commit()
            print("Table 'cpes' created successfully or already exists.")
        except Exception as e:
            print("Error creating table: ", e)
    
    def create_refrences_table(self):
        try:
            # SQL query to create the scans table if it does not exist
            create_refrences_table_query = '''
                CREATE TABLE IF NOT EXISTS refrences (
                    cve_id VARCHAR(255) REFERENCES cve(cve_id),
                    refrence TEXT,
                    refrence_type INTEGER  
                )
            '''
            # execute the create table query
            self.cursor.execute(create_refrences_table_query)
            self.connection.commit()
            print("Table 'cpes' created successfully or already exists.")
        except Exception as e:
            print("Error creating table: ", e)
    
    def create_cpeMatchURI_table(self):
        try:
            # SQL query to create the scans table if it does not exist
            create_cpeMatch_table_query = '''
                CREATE TABLE IF NOT EXISTS cpe_match_uri (
                    id SERIAL PRIMARY KEY,
                    cpe23uri TEXT
                )
            '''
            # execute the create table query
            self.cursor.execute(create_cpeMatch_table_query)
            self.connection.commit()
            print("Table 'cpe_match_uri' created successfully or already exists.")
        except Exception as e:
            print("Error creating table: ", e)
    
    def create_cpeMatchNames_table(self):
        try:
            # SQL query to create the scans table if it does not exist
            create_cpeMatch_table_query = '''
                CREATE TABLE IF NOT EXISTS cpe_match_names (
                    cpe_id INTEGER REFERENCES cpe_match_uri(id),
                    cpe_name TEXT

                )
            '''
            # execute the create table query
            self.cursor.execute(create_cpeMatch_table_query)
            self.connection.commit()
            print("Table 'cpe_match_names' created successfully or already exists.")
        except Exception as e:
            print("Error creating table: ", e)



db1 = netpackt_database_prepare()
db2 = cves_database_prepare()