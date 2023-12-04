import psycopg2
import lxml.html as lh
import requests
import cve_lookup
from . import database_connection

"""
this class is for searching database of vulnerabillites
"""
class SearchDatabase:

    def getData(self, infodisplay):
        searchresult = []
        for record in infodisplay:
            if record['version'] != '':
                version = record['version']
                service = record['Name']
                portnum = record['PortNum']
                # sending the query to postgres
                db = database_connection.database()
                result = db.commit_to_database_data(f"SELECT cveid FROM vulnerabilities WHERE product ILIKE '%{service}%' AND versions like '%{version}%' ")
                
                service_name = service + " " +version+"," +portnum
                searchresult.append({service_name:result})
        
        return searchresult
