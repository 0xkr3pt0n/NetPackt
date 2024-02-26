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

then create two databases in postgresql [netpackt, cves]

```bash
pip install -r requirements.txt
python CVE_download.py
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