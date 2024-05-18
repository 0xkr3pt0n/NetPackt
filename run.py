import os
import subprocess
import time


def runWindows():
    subprocess.Popen(["python", "manage.py", "runserver"])
    time.sleep(3)
    task = subprocess.Popen(["python", "manage.py", "process_tasks"])

def runLinux():
    subprocess.Popen(["python3", "manage.py", "runserver"])
    time.sleep(3)
    task = subprocess.Popen(["python3", "manage.py", "process_tasks"])


if __name__ == "__main__":
    os_name = os.name
    if os_name == "nt":
        runWindows()
    elif os_name == "posix":
        runLinux()