import psycopg2
import lxml.html as lh
import requests
import cve_lookup

# from .networkscan import networkscan

class SearchDatabase:
    #class constructor
    def __init__(self):
        # self.online = online
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
                portnum = record['PortNum']
                search_query = f"SELECT cveid FROM vulnerabilities WHERE product ILIKE '%{service}%' AND versions like '%{version}%' "
                # sending the query to postgres
                self.cursor.execute(search_query)
                result = self.cursor.fetchall()
                self.connection.commit()
                service_name = service + " " +version+"," +portnum
                searchresult.append({service_name:result})
        
        return searchresult

    def get_main_page(self, __package): 
        dictMain = {}
        id = 0 
        
        base_url = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=" + __package # __package can be a keyword or a CVE ID or a list of Keyword/CVE ID (separate with a +) 
        document = lh.fromstring(requests.get(base_url).text) 
        cve_entries = document.cssselect("div#TableWithRules table tr > td") # List of <tr> entries for CVE in main page

        for i in range(0, len(cve_entries) , 2):
            dictMain[id] = {
                "__PACKAGE" : __package,
                "ID"   : cve_entries[i].text_content(),
                "URL"  : "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + cve_entries[i].text_content(),
                "DESC" : cve_entries[i+1].text_content().strip()
            }
            id +=1

        return dictMain
    def get_cve_detail(self, cve_simple):
        cve_detail = {}

        for id, cve in cve_simple.items(): 
            details = self.get_detail(cve["URL"])

            cve_detail[id] = {
                "ID"   : cve_simple[id]["ID"],
                "DESC" : cve_simple[id]["DESC"],
                "NVD_URL" :  details["NVD_URL"],
                "CNA" : details["CNA"],
                "RELEASE_DATE" :details["RELEASE_DATE"],
                "CVE_REF_URL" :details["CVE_REF_URL"]
            }

        return cve_detail 
    def get_detail(self, url):
        results = {}
        # Add name, description and more like the non-optimized one
        document = lh.fromstring(requests.get(url, stream=True).text)  
        
        # SELECTOR
        ## Reference Selector -> reference link and source
        ref_selector = document.cssselect("div#GeneratedTable table tr td ul li a")

        cve_ref = [c.get("href") for c in ref_selector]
        results["CVE_REF_URL"] = cve_ref

        ## NVD Selector
        nvd_selector = document.cssselect("div#GeneratedTable .ltgreybackground a")
        nvd_link = nvd_selector[0].get("href")
        results["NVD_URL"] = nvd_link

        ## Assigning CNA Selector
        cna_selector = document.cssselect("div#GeneratedTable table tr:nth-child(9)")
        cna = cna_selector[0].text_content().strip()
        results["CNA"] = cna

        ## Date entry Selector
        date_selector = document.cssselect("div#GeneratedTable table tr:nth-child(11) td b")
        date = date_selector[0].text_content()
        date = date[0:4] + "/" + date[4:6] + "/" + date[6:]
        results["RELEASE_DATE"] = date

        return results
    def onlineSearch(self, infodisplay, scan_id):
        for record in infodisplay:
            version = record['version']
            service = record['Name']
            portnumber = record['PortNum']
            packge = service + " " + version
            search = self.get_main_page(packge)
            cves = self.get_cve_detail(search)
            for keys, values in cves.items():
                cveid = values['ID']
                description = values['DESC']
                nvd_ref = values['NVD_URL']
                ref_urls = values['CVE_REF_URL']
                refrences = ",".join(ref_urls)
                infected = service + " " + version
                try:
                    impact = cve_lookup.cve(str(cveid))
                    impact = impact.cvss2.score_name
                except:
                    impact = "None"
                # Use parameterized query to avoid SQL injection and handle data types correctly
                insert_query = "INSERT INTO api_result (cve_id, refrences, nvd, description, infected_service, scan_id, impact, port_number) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
                values = (cveid, refrences, nvd_ref, description, infected, scan_id, impact, portnumber)
                
                # Execute the parameterized query with values
                self.cursor.execute(insert_query, values)
                
                # Commit the transaction
                self.connection.commit()
    
    # closing database connection
    # class destructor to finsih database connection at the end.
    def __del__(self):
        self.cursor.close()
        self.connection.close()
