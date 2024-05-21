# NetPackt (vulnerabillity assesment tool)

## Table of contents
- [downloading](#downloading)
- [installtion](#installtion)
- [running](#running)

## important note (updated !!!)
changes applied to Database, you must run python manage.py makemigrations and python manage.py migrate to apply changes.

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
