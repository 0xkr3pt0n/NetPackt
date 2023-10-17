import os
import json
import psycopg2
# Function to find and process JSON files in a directory and its subdirectories
def process_json_files_in_directory(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.json'):
                json_file_path = os.path.join(root, file)
                process_json_file(json_file_path)

# Function to process a JSON file
def process_json_file(json_file_path):
    with open(json_file_path, 'r') as json_file:
        json_load = json.load(json_file)
        
    cve_id = json_load['cveMetadata']['cveId']
    try:
        date_updated = json_load['cveMetadata']['dateUpdated']
    except:
        date_updated = json_load['cveMetadata']['datePublished']

    vulnerabillites = [] # a list of vulnerabillites affected with the same cve

    #this loop will check if there is multiple servcies affected with the same cve
    try:
        for i in range(len(json_load['containers']['cna']['affected'])):
            vend=json_load['containers']['cna']['affected'][i]['vendor']
            prod=json_load['containers']['cna']['affected'][i]['product']
            vers=json_load['containers']['cna']['affected'][i]['versions']
            desc = []
            refr = []
            conf = ""
            inte = ""
            aval = ""
            scor = ""
            sevr = ""
            if 'metrics' in json_load['containers']['cna']:
                if 'cvssV3_1' in json_load['containers']['cna']['metrics'][0] or 'cvssV3_0' in json_load['containers']['cna']['metrics'][0] :
                    try:
                        conf = json_load['containers']['cna']['metrics'][0]['cvssV3_1']['confidentialityImpact'] #confedintiallity impact
                    except:
                        conf = "None"
                    try:
                        inte = json_load['containers']['cna']['metrics'][0]['cvssV3_1']['integrityImpact'] #integrity impact
                    except:
                        conf = "None"
                    try:
                        aval = json_load['containers']['cna']['metrics'][0]['cvssV3_1']['availabilityImpact'] #availability impact
                    except:
                        aval = "None"
                    try:
                        scor = json_load['containers']['cna']['metrics'][0]['cvssV3_1']['baseScore'] #base score
                    except:
                        scor = "None"
                    try:
                        sevr = json_load['containers']['cna']['metrics'][0]['cvssV3_1']['baseSeverity'] #base severity
                    except:
                        sevr = "None"
            else:
                conf = "None"
                inte = "None"
                aval = "None"
                scor = "None"
                sevr = "None"
            #this loop will check if there is multiple descriptions for the cve
            try:
                for j in range(len(json_load['containers']['cna']['descriptions'])):
                    desc.append(json_load['containers']['cna']['descriptions'][j]['value'])
            except:
                desc.append("None")
            #this loop will check if there is multiple refrences for the cve
            try:
                for j in range(len(json_load['containers']['cna']['references'])):
                    refr.append(json_load['containers']['cna']['references'][j]['url'])
            except:
                refr.append("None")
            vulnerabillites.append({"CVEID":cve_id, "dataupdated":date_updated,"vendor":vend,"product":prod,"versions":vers, "description":desc,"refrences":refr,"cimpact":conf,"iimpact":inte,"aimpact":aval,"baseScore":scor,"baseSeverity":sevr})
    except:
        vend="None"
        prod="None"
        vers="None"
        desc = []
        refr = []
        conf = ""
        inte = ""
        aval = ""
        scor = ""
        sevr = ""
        if 'metrics' in json_load['containers']['cna']:
            if 'cvssV3_1' in json_load['containers']['cna']['metrics'][0] or 'cvssV3_0' in json_load['containers']['cna']['metrics'][0] :
                try:
                    conf = json_load['containers']['cna']['metrics'][0]['cvssV3_1']['confidentialityImpact'] #confedintiallity impact
                except:
                    conf = "None"
                try:
                    inte = json_load['containers']['cna']['metrics'][0]['cvssV3_1']['integrityImpact'] #integrity impact
                except:
                    conf = "None"
                try:
                    aval = json_load['containers']['cna']['metrics'][0]['cvssV3_1']['availabilityImpact'] #availability impact
                except:
                    aval = "None"
                try:
                    scor = json_load['containers']['cna']['metrics'][0]['cvssV3_1']['baseScore'] #base score
                except:
                    scor = "None"
                try:
                    sevr = json_load['containers']['cna']['metrics'][0]['cvssV3_1']['baseSeverity'] #base severity
                except:
                    sevr = "None"
        else:
            conf = "None"
            inte = "None"
            aval = "None"
            scor = "None"
            sevr = "None"
        #this loop will check if there is multiple descriptions for the cve
        try:
            for j in range(len(json_load['containers']['cna']['descriptions'])):
                desc.append(json_load['containers']['cna']['descriptions'][j]['value'])
        except:
            desc.append("None")
        #this loop will check if there is multiple refrences for the cve
        try:
            for j in range(len(json_load['containers']['cna']['references'])):
                refr.append(json_load['containers']['cna']['references'][j]['url'])
        except:
            refr.append("None")
        vulnerabillites.append({"CVEID":cve_id, "dataupdated":date_updated,"vendor":vend,"product":prod,"versions":vers, "description":desc,"refrences":refr,"cimpact":conf,"iimpact":inte,"aimpact":aval,"baseScore":scor,"baseSeverity":sevr})

    try:
        #connection to database
        connection = psycopg2.connect(
            host="localhost", #keep the same
            database="netimpact", #database name (change according to your dbname)
            user="postgres", # database username (change according to your username of postgres)
            password="postgres" # database password (change according to your password of postgres)
        )

        cursor = connection.cursor()
    except Exception as e:
        # print("Error:", e)
        print("error")

    for i in range(len(vulnerabillites)):
        #preparing data for insertion in database, converting any datatype to string
        cve_id = vulnerabillites[i]['CVEID']
        date_update = vulnerabillites[i]['dataupdated']
        vendor = vulnerabillites[i]['vendor']
        product = vulnerabillites[i]['product']
        try:
            version_extracting = [item['version'] for item in vulnerabillites[i]['versions']]
            versions = ', '.join(version_extracting)
        except:
            versions = "None"
        description = vulnerabillites[i]['description']
        description = ', '.join(description)
        refrences = vulnerabillites[i]['refrences']
        refrences = ', '.join(refrences)
        confedintiallity_impact = vulnerabillites[i]['cimpact']
        integtrity_impact = vulnerabillites[i]['iimpact']
        availabillity_impact = vulnerabillites[i]['aimpact']
        base_score = vulnerabillites[i]['baseScore']
        base_severity = vulnerabillites[i]['baseSeverity']

        insert_query = "INSERT INTO vulnerabilities (cveid, dateupdated, vendor, product, versions, description, reference, confidentialityimpact, integrityimpact, availabilityimpact, basescore, baseseverity) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        data_to_insert = (cve_id, date_update, vendor, product, versions, description, refrences, confedintiallity_impact, integtrity_impact, availabillity_impact, base_score, base_severity)

        cursor.execute(insert_query, data_to_insert)
        connection.commit()
        print("Data inserted successfully.")

    cursor.close()
    connection.close()


# Start processing JSON files from the current directory
current_directory = os.getcwd()
process_json_files_in_directory(current_directory)