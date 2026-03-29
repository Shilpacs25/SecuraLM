import json
import chromadb
from chromadb.utils import embedding_functions

print("Loading ATT&CK data...")

with open("data/attack.json") as f:
    data = json.load(f)

ef = embedding_functions.ONNXMiniLM_L6_V2()

client = chromadb.PersistentClient(path="./db")

# Delete old collection if exists to avoid conflicts
try:
    client.delete_collection("security_knowledge")
    print("Deleted old security_knowledge collection")
except:
    pass

collection = client.get_or_create_collection(
    name="security_knowledge",
    embedding_function=ef
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

print(f"Adding {count} ATT&CK techniques to ChromaDB...")

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

print("Stored", count, "ATT&CK techniques")