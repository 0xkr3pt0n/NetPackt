import json
import psycopg2

#connecting to databases
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

# Load JSON data from file
with open('nvdcve-1.1-2011.json', 'r') as file:
    data = json.load(file)

# Extract CVE data from cvemetadata
for cve_count in range(len(data['CVE_Items'])):
    cve_id = data['CVE_Items'][cve_count]['cve']['CVE_data_meta']['ID']
    cve_description = data['CVE_Items'][cve_count]['cve']['description']['description_data'][0]['value']
    
    #case handling for cvss2
    if 'baseMetricV2' in data['CVE_Items'][cve_count]['impact'] and 'baseMetricV3' not in data['CVE_Items'][cve_count]['impact']:
        exploitability_score = data['CVE_Items'][cve_count]['impact']['baseMetricV2']['exploitabilityScore']
        impact_score = data['CVE_Items'][cve_count]['impact']['baseMetricV2']['impactScore']
        attack_complexity = 'n/a'
    #case handling for cvss3
    elif 'baseMetricV3' in data['CVE_Items'][cve_count]['impact']:
        attack_complexity = data['CVE_Items'][cve_count]['impact']['baseMetricV3']['cvssV3']['attackComplexity']
        exploitability_score = data['CVE_Items'][cve_count]['impact']['baseMetricV3']['exploitabilityScore']
        impact_score = data['CVE_Items'][cve_count]['impact']['baseMetricV3']['impactScore']
        
    #case handling for no data
    else:
        attack_complexity = 'n/a'
        exploitability_score = 0
        impact_score = 0
    # handling cpes
    cpes_affected = []
    for cpe_match in data['CVE_Items'][cve_count]['configurations']['nodes']:
        for cpe_23Uri in cpe_match['cpe_match']:
            if cpe_23Uri['vulnerable'] == True:
                cpes_affected.append(cpe_23Uri['cpe23Uri'])
    #handling refrences links
    exploit_links = []
    patch_links = []
    refrences = []
    for entry in data['CVE_Items'][cve_count]['cve']['references']['reference_data']:
        if 'Exploit' in entry['tags']:
            exploit_links.append(entry['url'])
        elif 'Patch' in entry['tags']:
            patch_links.append(entry['url'])
        else:
            refrences.append(entry['url'])
    
    #inserting cve data into database
    cve_data_query = "INSERT INTO cve (cve_id, cve_description, exploitability_score, impact_score, attack_complexity) VALUES (%s, %s, %s, %s, %s)"
    cve_cursor.execute(cve_data_query, (cve_id, str(cve_description), float(exploitability_score), float(impact_score), attack_complexity))
    cve_connection.commit()

    #inserting cpe data into database
    for cpe in cpes_affected:
        cpe_data_query = "INSERT INTO cpes (cve_id, cpe) VALUES (%s, %s)"
        cve_cursor.execute(cpe_data_query, (cve_id, cpe))
        cve_connection.commit()
    
    #inserting refrences into database
    for ref in exploit_links:
        ref_type = 2
        cpe_data_query = f"INSERT INTO refrences (cve_id, refrence, refrence_type) VALUES ('{cve_id}', '{ref}', '{ref_type}')"
        cve_cursor.execute(cpe_data_query)
        cve_connection.commit()
    
    for ref in patch_links:
        ref_type = 1
        cpe_data_query = f"INSERT INTO refrences (cve_id, refrence, refrence_type) VALUES ('{cve_id}', '{ref}', '{ref_type}')"
        cve_cursor.execute(cpe_data_query)
        cve_connection.commit()
    
    for ref in refrences:
        ref_type = 0
        cpe_data_query = f"INSERT INTO refrences (cve_id, refrence, refrence_type) VALUES ('{cve_id}', '{ref}', '{ref_type}')"
        cve_cursor.execute(cpe_data_query)
        cve_connection.commit()
    print(f"cve : {cve_id} inserted into database")  

cve_cursor.close()
cve_connection.close()
print("----------done----------")