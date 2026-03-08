import streamlit as st
import requests
import json
import os
from retriever import search_attack
from log_analyzer import analyze_log


# -------------------------
# FILE FOR CHAT STORAGE
# -------------------------

CHAT_FILE = "chat_history.json"


def load_chat():
    if os.path.exists(CHAT_FILE):
        with open(CHAT_FILE, "r") as f:
            return json.load(f)
    return []


def save_chat(messages):
    with open(CHAT_FILE, "w") as f:
        json.dump(messages, f)


# -------------------------
# PAGE CONFIG
# -------------------------

st.set_page_config(
    page_title="SecuraLM SOC Copilot",
    layout="wide",
    page_icon="🛡️"
)


# -------------------------
# SESSION STATE
# -------------------------

if "messages" not in st.session_state:
    st.session_state.messages = load_chat()

if "query" not in st.session_state:
    st.session_state.query = ""


# -------------------------
# SIDEBAR
# -------------------------

st.sidebar.title("🛡️ SecuraLM")

st.sidebar.markdown("### SOC Copilot")

st.sidebar.markdown("""
AI assistant trained on MITRE ATT&CK intelligence.

Use it to:
- analyze SIEM logs
- investigate threats
- understand attacker behavior
""")

st.sidebar.markdown("### Example Queries")

examples = [
    "credential dumping attack",
    "process injection",
    "privilege escalation",
    "phishing attack"
]

for q in examples:
    if st.sidebar.button(q):
        st.session_state.query = q

st.sidebar.markdown("---")
st.sidebar.markdown("Threat Intelligence System")


# -------------------------
# HEADER
# -------------------------

st.title("🛡️ SecuraLM SOC Analyst Copilot")

st.markdown("""
Paste **SIEM logs** or ask a **cybersecurity investigation question**.

SecuraLM analyzes threats using MITRE ATT&CK intelligence.
""")


# -------------------------
# DISPLAY CHAT HISTORY
# -------------------------

for msg in st.session_state.messages:

    with st.chat_message(msg["role"]):

        st.markdown(msg["content"])

        if msg.get("severity"):
            st.markdown(f"### ⚠ Threat Severity: {msg['severity']}")

        if msg.get("actions"):
            st.markdown("### 🛠 Recommended SOC Actions")

            for a in msg["actions"]:
                st.markdown(f"- {a}")

        if msg.get("source"):
            with st.expander("Threat Intelligence Source"):
                st.code(msg["source"])


# -------------------------
# USER INPUT
# -------------------------

query = st.chat_input("Paste SIEM log or ask security question")

if st.session_state.query and not query:
    query = st.session_state.query
    st.session_state.query = ""


# -------------------------
# MAIN QUERY PROCESS
# -------------------------

if query:

    st.chat_message("user").markdown(query)

    st.session_state.messages.append({
        "role": "user",
        "content": query
    })

    save_chat(st.session_state.messages)

    with st.spinner("🔎 Investigating threat..."):

        # Log analysis
        processed_query = analyze_log(query)

        # RAG retrieval
        context = search_attack(processed_query)

        # Prompt
        prompt = f"""
You are a professional SOC cybersecurity analyst.

Analyze the security event using ONLY the provided threat intelligence context.

Rules:
- Do NOT add external knowledge
- Mention ATT&CK technique IDs if present
- Provide a short investigation summary

Context:
{context}

Security Event:
{query}

SOC Investigation Result:
"""

        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "phi3",
                "prompt": prompt,
                "stream": False
            },
            timeout=300
        )

        answer = response.json()["response"]

        source_doc = context.split("\n\n")[0]


    # -------------------------
    # THREAT SEVERITY
    # -------------------------

    severity = "LOW"
    text = query.lower()

    if "downloadstring" in text and "powershell" in text:
        severity = "HIGH"

    if "mimikatz" in text or "lsass" in text:
        severity = "CRITICAL"

    if "powershell" in text:
        severity = "MEDIUM"


    # -------------------------
    # SOC ACTIONS
    # -------------------------

    actions = []

    if "powershell" in text:
        actions.append("Review PowerShell execution logs")

    if "downloadstring" in text:
        actions.append("Block suspicious domain")

    if "winword.exe" in text:
        actions.append("Investigate Office macro infection")

    if "mimikatz" in text or "lsass" in text:
        actions.append("Check for credential compromise")

    if "powershell" in text and "downloadstring" in text:
        actions.append("Isolate affected endpoint")


    # -------------------------
    # DISPLAY RESPONSE
    # -------------------------

    with st.chat_message("assistant"):

        st.markdown(answer)

        st.markdown(f"### ⚠ Threat Severity: {severity}")

        if actions:
            st.markdown("### 🛠 Recommended SOC Actions")

            for a in actions:
                st.markdown(f"- {a}")

        with st.expander("Threat Intelligence Source"):
            st.code(source_doc)


    # Save message

    st.session_state.messages.append({
        "role": "assistant",
        "content": answer,
        "severity": severity,
        "actions": actions,
        "source": source_doc
    })

    save_chat(st.session_state.messages)


# -------------------------
# FOOTER
# -------------------------

st.markdown("---")
st.markdown("SecuraLM — AI SOC Copilot for Threat Investigation")