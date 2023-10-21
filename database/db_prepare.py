import os
import json
import psycopg2

'''
this class is resposable for inserting data onto the database for first time use.
Usage Example : db = initdatabase()
'''
class initdatabase:
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
        current_directory = os.getcwd()#getting current directory 
        self.process_json_files_in_directory(current_directory) #start parsing hson files
    
    # Function to find and process JSON files in a directory and its subdirectories
    def process_json_files_in_directory(self,directory):
        #for loop to start walking into directories and nested directories
        for root, _, files in os.walk(directory):
            for file in files:
                #check if a file ends with .json extension
                if file.endswith('.json'):
                    #concatinating file name with full directory (EX: "D:/myfiles/cves/2023/0xxx" + "CVE-2023-0111.JSON")
                    json_file_path = os.path.join(root, file)
                    #parsing the json file
                    self.process_json_file(json_file_path)

    # Function to process a JSON file
    def process_json_file(self, json_file_path):
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
                try:
                    vers=json_load['containers']['cna']['affected'][i]['versions']
                except:
                    vers=json_load['containers']['cna']['affected'][0]['versions']
                desc = []
                refr = []
                conf = ""
                inte = ""
                aval = ""
                scor = ""
                sevr = ""
                
                if 'metrics' in json_load['containers']['cna']:
                    #case to handle metrics in case of cvss 3.1 or 3.0
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
            #case to handle metrics in case of cvss 2.0
                    elif 'cvssV2_0' in json_load['containers']['cna']['metrics'][0]:
                        try:
                            scor = json_load['containers']['cna']['metrics'][0]['cvssV2_0']['baseScore'] #base score
                        except:
                            scor = "None"
                        conf = "None"
                        inte = "None"
                        aval = "None"
                        sevr = "None"
                #case to handle metrics in case of other cases
                    else:
                        conf = "None"
                        inte = "None"
                        aval = "None"
                        scor = "None"
                        sevr = "None"
                #if metrics section is not found case
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
        
        except Exception as e:
            print(f"couldn't extract json data from {cve_id} because : {e}")
        
        #inserting data of vulnerabillites on the database.
        self.insert_data(vulnerabillites)
    
    #insert_data method to query the database to insert data.
    def insert_data(self, vulnerabillites):
        #looping through all vulnerabillites prepared in the list
        for i in range(len(vulnerabillites)):
            
            #preparing data for insertion in database, converting any datatype to string
            cve_id = vulnerabillites[i]['CVEID']
            date_update = vulnerabillites[i]['dataupdated']
            vendor = vulnerabillites[i]['vendor']
            product = vulnerabillites[i]['product']
            for j in range(len(vulnerabillites[i]['versions'])):
                if 'lessThan' in vulnerabillites[i]['versions'][j]:
                    versions = '< ' +  vulnerabillites[i]['versions'][j]['lessThan']
                elif 'lessThanOrEqual' in vulnerabillites[i]['versions'][j]:
                    versions = '<= ' +  vulnerabillites[i]['versions'][j]['lessThanOrEqual']
                elif 'version' in vulnerabillites[i]['versions'][j]:
                    versions = vulnerabillites[i]['versions'][j]['version']
                else:
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

            #inserting query
            insert_query = "INSERT INTO vulnerabilities (cveid, dateupdated, vendor, product, versions, description, reference, confidentialityimpact, integrityimpact, availabilityimpact, basescore, baseseverity) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            data_to_insert = (cve_id, date_update, vendor, product, versions, description, refrences, confedintiallity_impact, integtrity_impact, availabillity_impact, base_score, base_severity)

            #sending the query to postgres
            self.cursor.execute(insert_query, data_to_insert)
            self.connection.commit()
            print(f"data of cve {cve_id} inserted succsessfully. ")
        #closing database connection   
    #class destructor to finsih database connection at the end.
    def __del__(self):
        self.cursor.close()
        self.connection.close()
        
db = initdatabase()