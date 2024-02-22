import json
import psycopg2

try:
    # Connection to the CVE database
    cve_connection = psycopg2.connect(
        host="localhost",
        database="cves",  # Change to your CVE database name
        user="postgres",
        password="postgres"
    )
    cve_cursor = cve_connection.cursor()
except Exception as e:
    print("Error connecting to database : ", e)

with open('nvdcpematch-1.0.json', 'r') as file:
    data = json.load(file)

for cpe in range(len(data['matches'])):
    cpe_uri = data['matches'][cpe]['cpe23Uri']
    insert_cpeuri_query = "INSERT INTO cpe_match_uri (cpe23uri) VALUES (%s) RETURNING id"
    cve_cursor.execute(insert_cpeuri_query, (cpe_uri,))
    cpe_uri_id = cve_cursor.fetchone()[0]
    cve_connection.commit()
    cpe_names_list = data['matches'][cpe]['cpe_name']
    for cpe_name in cpe_names_list:
        cpe_name_proccesed = cpe_name['cpe23Uri']
        insert_cpename_query = "INSERT INTO cpe_match_names (cpe_id, cpe_name) VALUES (%s , %s)"
        cve_cursor.execute(insert_cpename_query , (cpe_uri_id, cpe_name_proccesed))
        cve_connection.commit()
    print(f"cpe number {cpe} finished")