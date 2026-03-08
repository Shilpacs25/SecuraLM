import requests, json

url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

data = requests.get(url).json()

with open("data/attack.json","w") as f:
    json.dump(data,f)

print("Downloaded", len(data["objects"]), "objects")