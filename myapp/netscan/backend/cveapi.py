import lxml.html as lh
import requests


def get_main_page(__package): 
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

def get_cve_detail(cve_simple):
    cve_detail = {}

    for id, cve in cve_simple.items(): 
        details = get_detail(cve["URL"])

        cve_detail[id] = {
            "ID"   : cve_simple[id]["ID"],
            "DESC" : cve_simple[id]["DESC"],
            "NVD_URL" :  details["NVD_URL"],
            "CNA" : details["CNA"],
            "RELEASE_DATE" :details["RELEASE_DATE"],
            "CVE_REF_URL" :details["CVE_REF_URL"]
        }

    return cve_detail 


def get_detail(url):
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
v = get_main_page("vsftpd 2.3.4")
cves = get_cve_detail(v)
for i,v in cves.items():
    urls = v['CVE_REF_URL']
    refrences = ",".join(urls)
    print(refrences)