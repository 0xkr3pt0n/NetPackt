import requests
from bs4 import BeautifulSoup



def check_xss(url):



    res = requests.get(url)


    soup = BeautifulSoup(res.content, "html.parser")


    input_tags = soup.find_all("input")
    script_tags = soup.find_all("script")
    print (script_tags)

check_xss('https://fci.bu.edu.eg')