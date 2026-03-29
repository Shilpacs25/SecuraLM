import streamlit as st
import requests
import sqlite3
import hashlib
import json
import os
from groq import Groq
from retriever import search_attack
from log_analyzer import analyze_log

# -----------------------------
# DATABASE
# -----------------------------

def connect_db():
    return sqlite3.connect("securalm.db", check_same_thread=False)


def create_tables():

    conn = connect_db()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY,
        password TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS chats(
        username TEXT,
        question TEXT,
        answer TEXT
    )
    """)

    conn.commit()

    columns = [col[1] for col in c.execute("PRAGMA table_info(chats)").fetchall()]

    if "severity" not in columns:
        c.execute("ALTER TABLE chats ADD COLUMN severity TEXT")

    if "actions" not in columns:
        c.execute("ALTER TABLE chats ADD COLUMN actions TEXT")

    if "source" not in columns:
        c.execute("ALTER TABLE chats ADD COLUMN source TEXT")

    conn.commit()
    conn.close()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# -----------------------------
# AUTH
# -----------------------------

def signup(username, password):

    conn = connect_db()
    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE username=?", (username,))
    existing = c.fetchone()

    if existing:
        conn.close()
        return False

    c.execute(
        "INSERT INTO users VALUES (?,?)",
        (username, hash_password(password))
    )

    conn.commit()
    conn.close()

    return True


def login(username, password):

    conn = connect_db()
    c = conn.cursor()

    c.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, hash_password(password))
    )

    result = c.fetchone()
    conn.close()

    return result is not None


# -----------------------------
# CHAT STORAGE
# -----------------------------

def save_chat(username, question, answer, severity, actions, source):

    conn = connect_db()
    c = conn.cursor()

    actions_text = json.dumps(actions)

    c.execute(
        "INSERT INTO chats VALUES (?,?,?,?,?,?)",
        (username, question, answer, severity, actions_text, source)
    )

    conn.commit()
    conn.close()


def load_chats(username):

    conn = connect_db()
    c = conn.cursor()

    c.execute(
        "SELECT question, answer, severity, actions, source FROM chats WHERE username=?",
        (username,)
    )

    rows = c.fetchall()
    conn.close()

    chats = []

    for q, a, s, act, src in rows:

        actions = json.loads(act) if act else []

        chats.append({
            "question": q,
            "answer": a,
            "severity": s,
            "actions": actions,
            "source": src
        })

    return chats


# -----------------------------
# INIT
# -----------------------------

create_tables()

st.set_page_config(
    page_title="SecuraLM SOC Copilot",
    layout="wide",
    page_icon="🛡️"
)


# -----------------------------
# SESSION STATE
# -----------------------------

query_params = st.query_params

if "user" in query_params:
    st.session_state.logged_in = True
    st.session_state.username = query_params["user"]

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "messages" not in st.session_state:
    st.session_state.messages = []

if "query" not in st.session_state:
    st.session_state.query = ""


# -----------------------------
# LOGIN PAGE
# -----------------------------

if not st.session_state.logged_in:

    st.markdown("<h1 style='text-align:center;'>🛡️ SecuraLM</h1>", unsafe_allow_html=True)
    st.markdown("<h4 style='text-align:center;'>AI SOC Security Copilot</h4>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1,2,1])

    with col2:

        tab1, tab2 = st.tabs(["Login", "Signup"])

        with tab1:

            with st.form("login_form"):

                username = st.text_input("Username")
                password = st.text_input("Password", type="password")

                submit = st.form_submit_button("Login")

                if submit:

                    if login(username, password):

                        st.session_state.logged_in = True
                        st.session_state.username = username

                        st.query_params["user"] = username

                        st.rerun()

                    else:
                        st.error("Invalid username or password")

        with tab2:

            with st.form("signup_form"):

                username = st.text_input("Create Username")
                password = st.text_input("Create Password", type="password")

                submit = st.form_submit_button("Signup")

                if submit:

                    success = signup(username, password)

                    if success:
                        st.success("Account created. Please login.")
                    else:
                        st.error("Username already exists")

    st.stop()


# -----------------------------
# SIDEBAR
# -----------------------------

st.sidebar.title("🛡️ SecuraLM")
st.sidebar.markdown(f"👤 {st.session_state.username}")

if st.sidebar.button("Logout"):

    st.session_state.logged_in = False
    st.session_state.messages = []

    st.query_params.clear()

    st.rerun()


st.sidebar.markdown("---")

# NEW CHAT
st.sidebar.markdown("### 🆕 Investigation")

if st.sidebar.button("➕ New Chat", key="new_chat"):

    st.session_state.messages = []
    st.session_state.query = ""

    st.rerun()


# EXAMPLE QUERIES
st.sidebar.markdown("### Example Queries")

examples = [
    "credential dumping attack",
    "process injection",
    "privilege escalation",
    "phishing attack"
]

for i, q in enumerate(examples):

    if st.sidebar.button(q, key=f"example_{i}"):

        st.session_state.query = q


# PREVIOUS CHATS
st.sidebar.markdown("---")
st.sidebar.markdown("### 🕘 Previous Investigations")

history = load_chats(st.session_state.username)

for i, chat in enumerate(history[::-1]):

    title = chat["question"][:35] + "..."

    if st.sidebar.button(title, key=f"history_{i}"):

        st.session_state.messages = [
            {"role": "user", "content": chat["question"]},
            {
                "role": "assistant",
                "content": chat["answer"],
                "severity": chat["severity"],
                "actions": chat["actions"],
                "source": chat["source"]
            }
        ]


# -----------------------------
# HEADER
# -----------------------------

st.title("🛡️ SecuraLM SOC Analyst Copilot")

st.markdown("Paste **SIEM logs** or ask a **cybersecurity investigation question**.")


# -----------------------------
# CHAT DISPLAY
# -----------------------------

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


# -----------------------------
# USER INPUT
# -----------------------------

query = st.chat_input("Paste SIEM log or ask security question")

if st.session_state.query and not query:
    query = st.session_state.query
    st.session_state.query = ""


# -----------------------------
# PROCESS QUERY
# -----------------------------

if query:

    st.chat_message("user").markdown(query)

    st.session_state.messages.append({
        "role": "user",
        "content": query
    })

    with st.spinner("🔎 Investigating threat..."):

        processed_query = analyze_log(query)

        context = search_attack(processed_query)

        prompt = f"""
You are a professional SOC cybersecurity analyst.

Context:
{context}

Security Event:
{query}

Provide investigation summary.
"""

        # -----------------------------
        # GROQ API CALL (replaces Ollama)
        # -----------------------------
        groq_client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

        completion = groq_client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1000
        )

        answer = completion.choices[0].message.content

        source_doc = context.split("\n\n")[0]


    severity = "LOW"

    text = query.lower()

    if "downloadstring" in text and "powershell" in text:
        severity = "HIGH"

    if "mimikatz" in text or "lsass" in text:
        severity = "CRITICAL"

    if "powershell" in text:
        severity = "MEDIUM"


    actions = []

    if "powershell" in text:
        actions.append("Review PowerShell execution logs")

    if "downloadstring" in text:
        actions.append("Block suspicious domain")

    if "winword.exe" in text:
        actions.append("Investigate Office macro infection")

    if "mimikatz" in text or "lsass" in text:
        actions.append("Check credential compromise")

    if "powershell" in text and "downloadstring" in text:
        actions.append("Isolate affected endpoint")


    with st.chat_message("assistant"):

        st.markdown(answer)

        st.markdown(f"### ⚠ Threat Severity: {severity}")

        if actions:

            st.markdown("### 🛠 Recommended SOC Actions")

            for a in actions:
                st.markdown(f"- {a}")

        with st.expander("Threat Intelligence Source"):
            st.code(source_doc)


    st.session_state.messages.append({
        "role": "assistant",
        "content": answer,
        "severity": severity,
        "actions": actions,
        "source": source_doc
    })

    save_chat(
        st.session_state.username,
        query,
        answer,
        severity,
        actions,
        source_doc
    )


# -----------------------------
# FOOTER
# -----------------------------

st.markdown("---")
st.markdown("SecuraLM — AI SOC Copilot for Threat Investigation")