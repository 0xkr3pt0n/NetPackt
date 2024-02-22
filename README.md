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
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2011.json.zip <br>
https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip 
```bash
pip install -r requirements.txt
python database.py
python data-parser-nist.py
python cpe-parser.py
python run.py
```

## pushing changes

```bash
in netpackt folder
git add .
git commit -m "message"
git push
```


## running
```bash

python run.py
WebAPP Socket : 127.0.0.1:8080

```
