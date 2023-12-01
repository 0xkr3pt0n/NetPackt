import requests
from urllib.parse import quote
def search_nvd_cves(keyword):
    encoded_parameter = quote(keyword)
    api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded_parameter}"
    headers = {
        'apiKey': "649376a5-c64c-4e6c-b5a9-1cfa2c2d70e1",  # Include this if required by the API
    }

    response = requests.get(api_url, headers=headers)
    response.raise_for_status()  # Raise an exception for 4xx or 5xx status codes

    # Parse the JSON response
    cves_data = response.json()
    print(cves_data)

search_nvd_cves("postgres 14")

