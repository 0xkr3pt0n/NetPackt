import lxml.html as lh
import requests
import cve_lookup
from urllib.parse import quote
import time
from . import database_connection
from . import exploits
"""
this class is for searching through api of nist nvd and mitre cve database
"""
class searchApi:
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
    def seachMitre(self, infodisplay, scan_id):
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
                    impact = impact.cvss2.score_name.upper()
                except:
                    impact = "None"
                # Use parameterized query to avoid SQL injection and handle data types correctly
                expoit_find = exploits.exploits()
                is_easy, exploit_links = expoit_find.exploit_finder(cveid)
                insert_query = "INSERT INTO api_result (cve_id, refrences, nvd, description, infected_service, scan_id, impact, port_number, is_easy, exploit_links) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                values = (cveid, refrences, nvd_ref, description, infected, scan_id, impact, portnumber, is_easy, exploit_links)

                db = database_connection.database()
                db.commit_to_database(insert_query, values)

    def searchNist(self, infodisplay, scan_id):
            db = database_connection.database()
            for record in infodisplay:
                version = record['version']
                service = record['Name']
                portnumber = record['PortNum']
                packge = service + " " + version
                encoded_parameter = quote(packge)
                api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded_parameter}"
                headers = {
                    'apiKey': "649376a5-c64c-4e6c-b5a9-1cfa2c2d70e1"  # Include this if required by the API
                }
                time.sleep(3)
                try:
                    response = requests.get(api_url, headers)
                    cves_data = response.json()
                    for cve in cves_data['vulnerabilities']:
                        cveid = cve['cve']['id']
                        data = db.commit_to_database_data(f"SELECT * FROM api_result WHERE cve_id = {cveid}")
                        if data:
                            pass
                        else:
                            metric_type = cve['cve']['metrics']
                            if 'cvssMetricV2' in metric_type:
                                impact = cve['cve']['metrics']['cvssMetricV2'][0]['baseSeverity'].upper()
                            else:
                                impact = cve['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity'].upper()

                            for desc in cve['cve']['descriptions']:
                                if desc['lang'] == 'en':
                                    description = desc['value']
                            refrs = []
                            for ref in cve['cve']['references']:
                                refrs.append(ref['url'])
                            refrences = ', '.join(refrs)
                            nvd_ref = f"https://nvd.nist.gov/vuln/detail/{cveid}"
                            expoit_find = exploits.exploits()
                            is_easy, exploit_links = expoit_find.exploit_finder(cveid)
                            insert_query = "INSERT INTO api_result (cve_id, refrences, nvd, description, infected_service, scan_id, impact, port_number, is_easy, exploit_links) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                            values = (cveid, refrences, nvd_ref, description, packge, scan_id, impact, portnumber, is_easy, exploit_links)
                            db.commit_to_database(insert_query, values)
                except:
                    pass
                # Parse the JSON response
                
                
