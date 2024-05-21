import requests

class user_activateapi:
    def user_activate(self,username,serialkey):
            url = 'http://127.0.0.1:9000/api_activate/'
            data = {
                "username" : username,
                "serialkey" : serialkey
            }
            
            print('reached')
            response = requests.post(url, json=data)
            login_response = response.json()['result']
            return login_response