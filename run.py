import subprocess
import os
import signal
import time
import psutil


class runAPP:
    def __init__(self):
        # self.backP = None
        self.proccess = []


    def run(self):
        self.updatedb()
        time.sleep(10)
        self.run_server()
        time.sleep(5)
        self.backP = self.process_tasks()
    def updatedb(self):
        subprocess.Popen(["python", "database.py"])
    def run_server(self):
        subprocess.Popen(["python", "manage.py", "runserver"])

    def process_tasks(self):
        task = subprocess.Popen(["python", "manage.py", "process_tasks"])
        self.proccess.append(task)

    def kill_runing(self):
        print(self.proccess)
        self.proccess[0].terminate()

r = runAPP()



if __name__ == "__main__":
    r.run()

    
