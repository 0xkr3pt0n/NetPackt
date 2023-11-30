import pyxploitdb

result = (pyxploitdb.searchEDB(cve="CVE-2011-2523"))

if result:
    print(result[0].link)
else:
    print("exploits not found")
