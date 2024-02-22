import json
with open('nvdcpematch-1.0.json', 'r') as file:
    data = json.load(file)
print('uri')
print(data['matches'][0]['cpe23Uri'])
print("names")
print(data['matches'][0]['cpe_name'])