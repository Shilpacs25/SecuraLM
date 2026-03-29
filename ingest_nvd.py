import json
import chromadb
from chromadb.utils import embedding_functions

print("Loading NVD data...")

with open("data/nvd.json") as f:
    data = json.load(f)

ef = embedding_functions.ONNXMiniLM_L6_V2()

client = chromadb.PersistentClient(path="./db")

# Delete old collection if exists to avoid conflicts
try:
    client.delete_collection("cve_vulnerabilities")
    print("Deleted old cve_vulnerabilities collection")
except:
    pass

collection = client.get_or_create_collection(
    name="cve_vulnerabilities",
    embedding_function=ef
)

texts = []
metadatas = []
ids = []

count = 0

for item in data["vulnerabilities"]:

    cve = item["cve"]

    cve_id = cve["id"]

    description = cve["descriptions"][0]["value"]

    text = f"""
Source: NVD
CVE ID: {cve_id}
Description: {description}
"""

    texts.append(text)

    metadatas.append({
        "type": "cve",
        "cve_id": cve_id
    })

    ids.append(f"cve_{count}")

    count += 1

print(f"Adding {count} CVE vulnerabilities to ChromaDB...")

# Add in batches to avoid memory issues
batch_size = 50

for i in range(0, len(texts), batch_size):

    batch_texts = texts[i:i+batch_size]
    batch_meta = metadatas[i:i+batch_size]
    batch_ids = ids[i:i+batch_size]

    collection.add(
        documents=batch_texts,
        metadatas=batch_meta,
        ids=batch_ids
    )

    print(f"  Added batch {i//batch_size + 1} / {(len(texts)-1)//batch_size + 1}")

print("Stored", count, "CVE vulnerabilities")