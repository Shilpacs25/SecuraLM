import json
import chromadb
from sentence_transformers import SentenceTransformer

print("Loading ATT&CK data...")

with open("data/attack.json") as f:
    data = json.load(f)

model = SentenceTransformer("all-MiniLM-L6-v2")

client = chromadb.PersistentClient(path="./db")

collection = client.get_or_create_collection(
    name="attack_techniques"
)

texts = []
metadatas = []
ids = []

count = 0

for obj in data["objects"]:

    if obj.get("type") != "attack-pattern":
        continue

    name = obj.get("name", "")
    description = obj.get("description", "")

    technique_id = None

    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            technique_id = ref.get("external_id")

    if technique_id is None:
        continue

    text = f"""
Source: MITRE ATT&CK
Technique ID: {technique_id}
Name: {name}
Description: {description}
"""

    texts.append(text)

    metadatas.append({
        "type": "attack",
        "technique_id": technique_id,
        "name": name
    })

    ids.append(f"attack_{count}")

    count += 1

print("Creating embeddings...")

embeddings = model.encode(
    texts,
    batch_size=32,
    show_progress_bar=True
)

print("Storing ATT&CK techniques...")

collection.add(
    documents=texts,
    embeddings=embeddings.tolist(),
    metadatas=metadatas,
    ids=ids
)

print("Stored", count, "ATT&CK techniques")