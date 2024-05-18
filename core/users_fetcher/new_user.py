import requests
from datetime import date

class new_user:
    def __init__(self, username, password, first_name, last_name, email, version):
        self.username = username
        self.password = password
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.version = version
    
    def sendapi(self):
        current_date = date.today()
        current_date_str = current_date.isoformat()
        url = 'http://127.0.0.1:9000/netpackt_user/'
        data = {
            "username" : self.username,
            "password" : self.password,
            "first_name" : self.first_name,
            "last_name" : self.last_name,
            "email" : self.email,
            "netpackt_version":self.version,
            "date_joined" : current_date_str
        }
        
        print('reached')
        response = requests.post(url, json=data)

        if response.status_code == 201:
            print('done')
            return 1
        else:
            return 0