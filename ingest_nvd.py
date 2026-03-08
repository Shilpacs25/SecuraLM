import json
import chromadb
from sentence_transformers import SentenceTransformer

print("Loading NVD data...")

with open("data/nvd.json") as f:
    data = json.load(f)

model = SentenceTransformer("all-MiniLM-L6-v2")

client = chromadb.PersistentClient(path="./db")

collection = client.get_or_create_collection(
    name="cve_vulnerabilities"
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

print("Creating embeddings...")

embeddings = model.encode(
    texts,
    batch_size=32,
    show_progress_bar=True
)

print("Storing CVE vulnerabilities...")

collection.add(
    documents=texts,
    embeddings=embeddings.tolist(),
    metadatas=metadatas,
    ids=ids
)

print("Stored", count, "CVE vulnerabilities")