import requests
import json
import os

os.makedirs("data", exist_ok=True)

url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000&startIndex=200000"

print("Downloading recent CVEs...")

data = requests.get(url).json()

with open("data/nvd.json", "w") as f:
    json.dump(data, f)

print("Saved", len(data["vulnerabilities"]), "recent CVEs")