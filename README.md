# NetPackt (vulnerabillity assesment tool)

## Table of contents
- [downloading](#downloading)
- [installtion](#installtion)
- [running](#running)

## important note
changes applied to Database, make sure you run python database.py first before running the project

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
WebAPP Socket : 127.0.0.1:8000

```
## pushing changes

```bash
git add .
git commit -m "message"
git push
```