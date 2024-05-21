import requests

class userlogin:
    def login_api(self,username,password):
            url = 'http://127.0.0.1:9000/api_login/'
            data = {
                "email" : username,
                "password" : password
            }
            
            print('reached')
            response = requests.post(url, json=data)
            login_response = response.json()['result']
            return login_response