import os
import json
import psycopg2

'''
this class is resposable for inserting data onto the database for first time use.
Usage Example : db = initdatabase()
Note : put this file in the root directory (cves/) which contain all json files and folders inside.
Note : This script will take up to 2 hours so kindly go drink ur coffe or do anything useful until it finishes.
'''
class initdatabase:
    #class constructor
    def __init__(self):
        try:
            #connection to database ([!] dont forget to modify connection parameters)
            connection = psycopg2.connect(
                host="192.168.1.50", #keep the same
                database="netimpact", #database name (change according to your dbname)
                user="postgres", # database username (change according to your username of postgres)
                password="123456" # database password (change according to your password of postgres)
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
        #check if cve is rejected or not (we don't want rejected vulnerabillites in our DB)
        if json_load['cveMetadata']['state'] == "PUBLISHED":
            vulnerabillites =[]
            #cve id cases
            try:
                cveid = json_load['cveMetadata']['cveId']
            except KeyError as e:
                cveid = "None"
            #data updated cases
            try:
                dateUpdated = json_load['cveMetadata']['dateUpdated']  
            except KeyError as e:
                if 'datePublished' in json_load['cveMetadata']:
                    dateUpdated = json_load['cveMetadata']['datePublished'] 
                else:
                    dateUpdated = "None"
            #service, product, versions cases, description, refrence, metrics
            try:
                for i in range(len(json_load['containers']['cna']['affected'])):
                    #---------vendor, product version cases start---------
                    service = json_load['containers']['cna']['affected'][i]
                    if 'packageName' in service or 'collectionURL' in service:
                        #product cases
                        try:
                            if 'product' in service:
                                if service['product'] and service['packageName']  != 'n/a':
                                    product = service['product'] + "," + service['packageName']
                                elif service['product'] == 'n/a' and service['packageName'] !='n/a':
                                    product = service['packageName']
                                elif service['product'] != 'n/a' and service['packageName'] =='n/a':
                                    product = service['product']
                                else:
                                    product = "None"
                            else:
                                if service['packageName'] != 'n/a':
                                    product = service['packageName']
                                else:
                                    product = "None"
                        except KeyError as e:
                            product = "None"
                        #vendor cases
                        try:
                            if 'vendor' in service:
                                if service['vendor'] != 'n/a' and service['collectionURL']  != 'n/a':
                                    vendor = service['vendor'] + "," + service['collectionURL']
                                elif service['vendor'] == 'n/a' and service['collectionURL'] !='n/a':
                                    vendor = service['collectionURL']
                                elif service['vendor'] != 'n/a' and service['collectionURL'] =='n/a':
                                    vendor = service['vendor']
                                else:
                                    vendor = "None"
                            else:
                                if service['collectionURL'] != 'n/a':
                                    vendor = service['collectionURL']
                                else:
                                    vendor = "None"
                        except KeyError as e:
                            vendor = "None"
                        #version cases
                        affected_versions = []
                        try:
                            if 'versions' in service and 'cpes' in service :
                                affected_versions.append(service['versions'])
                                affected_versions.append(service['cpes'])
                            elif 'versions' not in service and 'cpes' in service:
                                affected_versions.append(service['cpes'])
                            elif 'versions' in service and 'cpes' not in service:
                                affected_versions.append(service['versions'])
                            else:
                                affected_versions.append("None")
                        except KeyError as e:
                            affected_versions.append("None")
                    else: 
                        #product cases
                        try:
                            if service['product'] == 'n/a':
                                product = "None"
                            else:
                                product = service['product']
                        except KeyError as e:
                            product = "None"
                        #vendor cases
                        try:
                            if service['vendor'] == 'n/a':
                                vendor = "None"
                            else:
                                vendor = service['vendor']
                        except KeyError as e:
                            vendor = "None"
                        #version cases
                        affected_versions = []
                        try:
                            if 'versions' in service and 'cpes' in service :
                                affected_versions.append(service['versions'])
                                affected_versions.append(service['cpes'])
                            elif 'versions' not in service and 'cpes' in service:
                                affected_versions.append(service['cpes'])
                            elif 'versions' in service and 'cpes' not in service:
                                affected_versions.append(service['versions'])
                            else:
                                affected_versions.append("None")
                        except KeyError as e:
                            affected_versions.append("None")
                    #---------vendor, product version cases end---------

                    #description cases
                    descriptions = []
                    try:
                        for description in json_load['containers']['cna']['descriptions']:
                            descriptions.append(description['value'])
                    except KeyError as e:
                        descriptions.append("None")
                    #refrences cases
                    refrences = []
                    try:
                        for refrence in json_load['containers']['cna']['references']:
                            refrences.append(refrence['url'])
                    except KeyError as e:
                        refrences.append("None")
                    #metrics cases
                    try:
                        for metric in json_load['containers']['cna']['metrics']:
                            if 'cvssV3_1' in metric:
                                try:
                                    confeditiallity_impact = metric['cvssV3_1']['confidentialityImpact']
                                except KeyError as e:
                                    confeditiallity_impact = "None"
                                try:
                                    integrity_impact = metric['cvssV3_1']['confidentialityImpact']
                                except KeyError as e:
                                    integrity_impact = "None"
                                try:
                                    availability_impact = metric['cvssV3_1']['availabilityImpact']
                                except KeyError as e:
                                    availability_impact = "None"
                                try:
                                    base_score = metric['cvssV3_1']['baseScore']
                                except KeyError as e:
                                    base_score = "None"
                                try:
                                    base_severity = metric['cvssV3_1']['baseSeverity']
                                except KeyError as e:
                                    base_severity = "None"
                            
                            elif 'cvssV3_0' in metric:
                                try:
                                    confeditiallity_impact = metric['cvssV3_0']['confidentialityImpact']
                                except KeyError as e:
                                    confeditiallity_impact = "None"
                                try:
                                    integrity_impact = metric['cvssV3_0']['confidentialityImpact']
                                except KeyError as e:
                                    integrity_impact = "None"
                                try:
                                    availability_impact = metric['cvssV3_0']['availabilityImpact']
                                except KeyError as e:
                                    availability_impact = "None"
                                try:
                                    base_score = metric['cvssV3_0']['baseScore']
                                except KeyError as e:
                                    base_score = "None"
                                try:
                                    base_severity = metric['cvssV3_0']['baseSeverity']
                                except KeyError as e:
                                    base_severity = "None"
                            elif 'cvssV2_0' in metric:
                                try:
                                    confeditiallity_impact = metric['cvssV2_0']['confidentialityImpact']
                                except KeyError as e:
                                    confeditiallity_impact = "None"
                                try:
                                    integrity_impact = metric['cvssV2_0']['confidentialityImpact']
                                except KeyError as e:
                                    integrity_impact = "None"
                                try:
                                    availability_impact = metric['cvssV2_0']['availabilityImpact']
                                except KeyError as e:
                                    availability_impact = "None"
                                try:
                                    base_score = metric['cvssV2_0']['baseScore']
                                except KeyError as e:
                                    base_score = "None"
                                try:
                                    base_severity = metric['cvssV2_0']['baseSeverity']
                                except KeyError as e:
                                    base_severity = "None"
                            else:
                                confeditiallity_impact = "None"
                                integrity_impact = "None"
                                availability_impact = "None"
                                base_score = "None"
                                base_severity = "None"
                    except KeyError as e:
                                confeditiallity_impact = "None"
                                integrity_impact = "None"
                                availability_impact = "None"
                                base_score = "None"
                                base_severity = "None"  
                    vulnerabillites.append({"cveid":cveid,"dateupdated":dateUpdated,"vendor":vendor,"product":product,"version":affected_versions,"description":descriptions,"refrences":refrences,"confedintiallity_impact":confeditiallity_impact, "integrity_impact":integrity_impact,"availabillity_impact":availability_impact,"base_score":base_score,"base_severity":base_severity})     
                #sending each vulnerabillity to insert_data method to insert into db
                self.insert_data(vulnerabillites)
            except:
                pass
        else:
            print(f" [ ! ] cve {json_load['cveMetadata']['cveId']} rejected and not inserted in DB.")

    
    #insert_data method to query the database to insert data.
    def insert_data(self, vulnerabillites):
            for vulnerabillity in vulnerabillites:
                #preparing data to be inserted in database
                cve_id = vulnerabillity['cveid']
                date_update = vulnerabillity['dateupdated']
                vendor = vulnerabillity['vendor']
                product = vulnerabillity['product']
                version = vulnerabillity['version']
                for ver in version:
                    if ver !="None":
                        for item in ver:
                            if isinstance(item, str):
                                version=item
                            else:
                                if 'version' in item and 'lessThan' not in item and 'lessThanOrEqual' not in item:
                                    version = item['version']
                                elif 'lessThan' in item:
                                    version ="< " + item['lessThan']
                                    try:
                                        version = version + " , " + item['version']
                                    except:
                                        pass
                                    try:
                                        version = version + " , " + item['lessThanOrEqual']
                                    except:
                                        pass
                                else:
                                    version = "<= " + item['lessThanOrEqual']
                                    try:
                                        version = version + " , " + item['version']
                                    except:
                                        pass
                                    try:
                                        version = version + " , " + item['lessThan']
                                    except:
                                        pass
                    else:
                        version = "None"
                if version == 'n/a':
                    version = "None"
                description = vulnerabillity['description']
                description = ",".join(description)
                refrences = vulnerabillity['refrences']
                refrences = ",".join(refrences)
                integtrity_impact = vulnerabillity['integrity_impact']
                confedintiallity_impact = vulnerabillity['confedintiallity_impact']
                availabillity_impact = vulnerabillity['availabillity_impact']
                base_score = vulnerabillity['base_score']
                base_severity = vulnerabillity['base_severity']

                #inserting query
                insert_query = "INSERT INTO vulnerabilities (cveid, dateupdated, vendor, product, versions, description, reference, confidentialityimpact, integrityimpact, availabilityimpact, basescore, baseseverity) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                data_to_insert = (cve_id, date_update, vendor, product, version, description, refrences, confedintiallity_impact, integtrity_impact, availabillity_impact, base_score, base_severity)

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
