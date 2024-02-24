import requests
import zipfile
import os
import subprocess

cve_links = [
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2002.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2003.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2004.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2005.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2006.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2007.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2008.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2009.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2010.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2011.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2011.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2012.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2013.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2014.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2015.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2016.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2017.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2018.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2019.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2020.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2021.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2022.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2023.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.zip",
    "https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip",
]

def download_and_extract_zip(zip_link):
    filename = zip_link.split('/')[-1]
    
    if os.path.exists(filename):
        print(f"{filename} already exists. Skipping download.")
    else:
        print(f"Downloading {filename}...")
        r = requests.get(zip_link)
        with open(filename, 'wb') as f:
            f.write(r.content)
        print(f"{filename} downloaded successfully.")
    
    print(f"Extracting {filename}...")
    with zipfile.ZipFile(filename, 'r') as zip_ref:
        zip_ref.extractall()
    print(f"{filename} extracted successfully.")

def delete_zip_files():
    for link in cve_links:
        filename = link.split('/')[-1]
        if os.path.exists(filename):
            os.remove(filename)
            print(f"{filename} deleted successfully.")

def delete_json_files():
    for filename in os.listdir():
        if filename.endswith('.json'):
            os.remove(filename)
            print(f"{filename} deleted successfully.")

for link in cve_links:
    download_and_extract_zip(link)

subprocess.run(["python", "database.py"])
subprocess.run(["python", "data-parser-nist.py"])
subprocess.run(["python", "cpe-parser.py"])