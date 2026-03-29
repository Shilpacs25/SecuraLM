import chromadb
import re
from chromadb.utils import embedding_functions
from rank_bm25 import BM25Okapi


# ---------------------------
# Connect to DB
# ---------------------------
client = chromadb.PersistentClient(path="./db")

# Lightweight built-in ONNX embedder (no torch needed)
ef = embedding_functions.ONNXMiniLM_L6_V2()

attack_collection = client.get_collection("security_knowledge", embedding_function=ef)
cve_collection = client.get_collection("cve_vulnerabilities", embedding_function=ef)


# ---------------------------
# Load documents
# ---------------------------
attack_data = attack_collection.get()
cve_data = cve_collection.get()

attack_docs = attack_data["documents"]
cve_docs = cve_data["documents"]


# ---------------------------
# BM25 indexes
# ---------------------------
attack_tokens = [doc.lower().split() for doc in attack_docs]
cve_tokens = [doc.lower().split() for doc in cve_docs]

bm25_attack = BM25Okapi(attack_tokens) if attack_tokens else None
bm25_cve = BM25Okapi(cve_tokens) if cve_tokens else None


# ---------------------------
# Detect CVE ID
# ---------------------------
def detect_cve_id(query):

    pattern = r"CVE-\d{4}-\d+"
    match = re.search(pattern, query.upper())

    if match:
        return match.group(0)

    return None


# ---------------------------
# Detect ATT&CK ID
# ---------------------------
def detect_attack_id(query):

    pattern = r"T\d{4}(\.\d{3})?"
    match = re.search(pattern, query.upper())

    if match:
        return match.group(0)

    return None


# ---------------------------
# Query intent detection
# ---------------------------
def detect_query_type(query):

    q = query.lower()

    vulnerability_keywords = [
        "cve", "vulnerability", "exploit", "patch",
        "nvd", "advisory", "disclosure"
    ]

    technique_keywords = [
        "attack", "technique", "process injection",
        "phishing", "lateral movement",
        "credential dumping", "persistence",
        "mitre", "att&ck", "tactic"
    ]

    for w in vulnerability_keywords:
        if w in q:
            return "cve"

    for w in technique_keywords:
        if w in q:
            return "attack"

    return "general"


# ---------------------------
# Main Retrieval Function
# ---------------------------
def search_attack(query):

    print("\nSearching knowledge base...")

    query_type = detect_query_type(query)
    cve_id = detect_cve_id(query)
    attack_id = detect_attack_id(query)

    # --------------------------------
    # Direct CVE lookup (exact match)
    # --------------------------------
    if cve_id:

        print("Direct CVE lookup:", cve_id)

        results = cve_collection.get(where={"cve_id": cve_id})

        if results["documents"]:
            return "\n\n".join(results["documents"])

    # --------------------------------
    # Direct ATT&CK lookup (exact match)
    # --------------------------------
    if attack_id:

        print("Direct ATT&CK lookup:", attack_id)

        results = attack_collection.get(where={"technique_id": attack_id})

        if results["documents"]:
            return "\n\n".join(results["documents"])

    # --------------------------------
    # Dense retrieval
    # Only search CVE collection when query is CVE-related
    # --------------------------------
    attack_dense = attack_collection.query(
        query_texts=[query],
        n_results=5
    )["documents"][0]

    if query_type == "cve" or cve_id:
        cve_dense = cve_collection.query(
            query_texts=[query],
            n_results=5
        )["documents"][0]
    else:
        cve_dense = []

    # --------------------------------
    # BM25 retrieval
    # Only search CVE BM25 when query is CVE-related
    # --------------------------------
    tokens = query.lower().split()

    attack_keyword = []
    cve_keyword = []

    if bm25_attack:

        attack_scores = bm25_attack.get_scores(tokens)

        attack_idx = sorted(
            range(len(attack_scores)),
            key=lambda i: attack_scores[i],
            reverse=True
        )[:5]

        attack_keyword = [attack_docs[i] for i in attack_idx]

    if bm25_cve and (query_type == "cve" or cve_id):

        cve_scores = bm25_cve.get_scores(tokens)

        cve_idx = sorted(
            range(len(cve_scores)),
            key=lambda i: cve_scores[i],
            reverse=True
        )[:5]

        cve_keyword = [cve_docs[i] for i in cve_idx]

    # --------------------------------
    # Combine & deduplicate results
    # --------------------------------
    combined_docs = list(set(
        attack_dense +
        cve_dense +
        attack_keyword +
        cve_keyword
    ))

    if len(combined_docs) == 0:
        return "No relevant documents found."

    # --------------------------------
    # Top documents
    # --------------------------------
    top_docs = combined_docs[:3]

    print("\nTop Documents:\n")

    for doc in top_docs:
        print("-", doc[:120])

    context = "\n\n".join(top_docs)

    return context