import subprocess
import time


def run_server():
    subprocess.Popen(["python", "manage.py", "runserver"])

def process_tasks():
    subprocess.Popen(["python", "manage.py", "process_tasks"])

if __name__ == "__main__":
    run_server()
    # Add a delay to ensure the server starts before processing tasks
    time.sleep(5)  # Adjust delay as needed
    process_tasks()
