# NetPackt (vulnerabillity assesment tool)

## Table of contents
- [downloading](#downloading)
- [installtion](#installtion)
- [running](#running)

## downloading
note : it's a private repo so you must configure and authorize git with github first with the following steps:<br>
```bash
git clone https://github.com/0xkr3pt0n/NetPackt.git
cd NetPackt
git checkout -b netpackt-new remotes/origin/netpackt-new
```

## installtion for first time only
download the following files extract them in the main folder (where manage.py located)<br>
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2002.json.zip <br>
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2003.json.zip <br>
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2004.json.zip <br>
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2005.json.zip <br>
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2006.json.zip <br>
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2007.json.zip <br>
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2008.json.zip <br>
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2009.json.zip <br>
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2010.json.zip <br>
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2011.json.zip <br>
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2012.json.zip <br>
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2013.json.zip <br>
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2014.json.zip <br>
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2015.json.zip <br>
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2016.json.zip <br>
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2017.json.zip <br>
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2018.json.zip <br>
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2019.json.zip <br>
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2020.json.zip <br>
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2021.json.zip <br>
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2022.json.zip <br>
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2023.json.zip <br>
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.zip <br>
https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip 
```bash
pip install -r requirements.txt
python database.py
python data-parser-nist.py
python cpe-parser.py
python run.py
```
## running
```bash

python run.py
WebAPP Socket : 127.0.0.1:8080

```
## pushing changes

```bash
in netpackt folder
git add .
git commit -m "message"
git push
```