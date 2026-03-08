import chromadb
import re
from sentence_transformers import SentenceTransformer, CrossEncoder
from rank_bm25 import BM25Okapi


# ---------------------------
# Connect to DB
# ---------------------------
client = chromadb.PersistentClient(path="./db")

attack_collection = client.get_collection("security_knowledge")
cve_collection = client.get_collection("cve_vulnerabilities")


# ---------------------------
# Models
# ---------------------------
embed_model = SentenceTransformer("all-MiniLM-L6-v2")
reranker = CrossEncoder("cross-encoder/ms-marco-MiniLM-L-6-v2")


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

    technique_keywords = [
        "attack", "technique", "process injection",
        "phishing", "lateral movement",
        "credential dumping", "persistence"
    ]

    vulnerability_keywords = [
        "cve", "vulnerability", "exploit", "patch"
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

    # --------------------------------
    # Direct CVE lookup
    # --------------------------------
    cve_id = detect_cve_id(query)

    if cve_id:

        print("Direct CVE lookup:", cve_id)

        results = cve_collection.get(where={"cve_id": cve_id})

        if results["documents"]:
            return "\n\n".join(results["documents"])


    # --------------------------------
    # Direct ATT&CK lookup
    # --------------------------------
    attack_id = detect_attack_id(query)

    if attack_id:

        print("Direct ATT&CK lookup:", attack_id)

        results = attack_collection.get(where={"technique_id": attack_id})

        if results["documents"]:
            return "\n\n".join(results["documents"])


    query_type = detect_query_type(query)

    embedding = embed_model.encode(query).tolist()


    # --------------------------------
    # Dense retrieval
    # --------------------------------
    attack_dense = attack_collection.query(
        query_embeddings=[embedding],
        n_results=5
    )["documents"][0]

    cve_dense = cve_collection.query(
        query_embeddings=[embedding],
        n_results=5
    )["documents"][0]


    # --------------------------------
    # BM25 retrieval
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


    if bm25_cve:

        cve_scores = bm25_cve.get_scores(tokens)

        cve_idx = sorted(
            range(len(cve_scores)),
            key=lambda i: cve_scores[i],
            reverse=True
        )[:5]

        cve_keyword = [cve_docs[i] for i in cve_idx]


    # --------------------------------
    # Combine results
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
    # Reranking
    # --------------------------------
    pairs = [(query, doc) for doc in combined_docs]

    scores = reranker.predict(pairs)

    ranked_docs = [
        doc for _, doc in sorted(
            zip(scores, combined_docs),
            reverse=True
        )
    ]


    # --------------------------------
    # Top documents
    # --------------------------------
    top_docs = ranked_docs[:3]

    print("\nTop Ranked Documents:\n")

    for doc in top_docs:
        print("-", doc[:120])


    context = "\n\n".join(top_docs)

    return context