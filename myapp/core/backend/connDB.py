import psycopg2

DB_NAME = "netimpact"
DB_USER = "postgres"
DB_PASS = "Dodo@1"
DB_PORT = "5432"
DB_HOST = "localhost"

conn = psycopg2.connect(
    dbname=DB_NAME,
    user=DB_USER,
    password=DB_PASS,
    host=DB_HOST,
    port=DB_PORT,

)
cursor = conn.cursor()

create_api_result = """ 
CREATE TABLE IF NOT EXISTS api_result(
    id SERIAL PRIMARY KEY NOT NULL,
    description text ,
    nvd text,
    refrences text,
    cvi_id text,
    infected_service text,
    scan_id text,
    impact text,
    port_number text,
    is_easy text,
    exploit_links text
);
"""

alter_auth_user = """
ALTER TABLE auth_user
ADD COLUMN IF NOT EXISTS is_api integer;
"""

create_findings = """
CREATE TABLE IF NOT EXISTS findings(
    id  SERIAL PRIMARY KEY NOT NULL,
    cveid text,
    scan_id integer,
    infected_service text,
    port_number text,
    is_easy boolean,
    exploit_links text
);
"""

create_network_scan_result = """
CREATE TABLE IF NOT EXISTS network_scan_result(
    id  SERIAL PRIMARY KEY NOT NULL,
    scan_id integer,
    svc text,
    svc_product text,
    svc_ver text,
    port_number text,
    script text
);
"""

create_scans = """
CREATE TABLE IF NOT EXISTS scans(
    id  SERIAL PRIMARY KEY NOT NULL,
    scan_name text,
    system_ip text,
    username text,
    shared_with text,
    scan_date text,
    current_status text,
    scan_type text,
    is_intrusive text,
    scan_online text
);
"""

create_vulns = """
CREATE TABLE IF NOT EXISTS vulns(
    "dataType" text,
    "dataVersion" bigint,
    "cveMetadata" text,
    "containers" text
);
"""

cursor.execute(create_api_result)
cursor.execute(alter_auth_user)
cursor.execute(create_findings)
cursor.execute(create_network_scan_result)
cursor.execute(create_scans)
cursor.execute(create_vulns)

conn.commit()

cursor.close()
conn.close()
