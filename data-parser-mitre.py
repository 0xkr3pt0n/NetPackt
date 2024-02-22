import json

# Load JSON data from file
with open('CVE-2019-10028.json', 'r') as file:
    data = json.load(file)

# Extract CVE ID from cvemetadata
try:
    cve_id = data['cveMetadata']['cveId']
except:
    cve_id = "n/a"

#extracting english description from cve
try:
    cve_descriptions = data['containers']['cna']['descriptions']
    for description in cve_descriptions:
        if description['lang'] == 'en':
            cvedescription = description['value']
except:
    cvedescription = "n/a"


#extracting affected softwares and it's versions
try:
    affected = data['containers']['cna']['affected']
    affected_products = []
    for one_affect in affected:
        if 'product' in one_affect:
            product = one_affect['product']
            vendor = one_affect['vendor']
        else:
            product = one_affect['collectionURL']
            vendor = one_affect['packageName']
        versions_affected = []
        if 'versions' in one_affect:
            for version in one_affect['versions']:
                versions_affected.append(version['version'])
        else:
            versions_affected.append('n/a')
        affected_products.append({'product':product, 'vendor':vendor, "version":versions_affected})
except:
    affected_products = [{'product':'n/a', 'vendor':'n/a', 'version':['n/a']}]

#extracting cpes
try:
    affected = data['containers']['cna']['affected']
    cpe_list = []
    for affect in affected:
        if 'cpes' in affect:
            for cpe in affect['cpes']:
                cpe_list.append(cpe)
        else:
            print("cpe not found")
except:
     cpe_list = ['n/a']

# print(cvedescription)
# print("CVE ID:", cve_id)
# print(affected_products)
# print(cpe_list)