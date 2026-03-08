import requests
from retriever import search_attack
from log_analyzer import analyze_log


print("🛡️  SecuraLM — AI Security Copilot")
print("Type 'exit' to quit\n")


OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "phi3"


# ---------------------------------
# Threat Severity Calculation
# ---------------------------------

def calculate_severity(log_text):

    text = log_text.lower()

    if "downloadstring" in text and "powershell" in text:
        return "HIGH"

    if "mimikatz" in text or "lsass" in text:
        return "CRITICAL"

    if "powershell" in text:
        return "MEDIUM"

    return "LOW"


# ---------------------------------
# SOC Recommended Actions
# ---------------------------------

def recommend_actions(log_text):

    actions = []
    text = log_text.lower()

    if "powershell" in text:
        actions.append("Review PowerShell event logs")

    if "downloadstring" in text:
        actions.append("Block suspicious domain or IP")

    if "winword.exe" in text:
        actions.append("Investigate suspicious Office document")

    if "powershell" in text and "downloadstring" in text:
        actions.append("Isolate affected host from network")

    return actions


# ---------------------------------
# Main Loop
# ---------------------------------

while True:

    question = input("🔎 Ask a security question: ")

    if question.lower() == "exit":
        print("Exiting SecuraLM...")
        break


    # ---------------------------------
    # Analyze Log / Extract Indicators
    # ---------------------------------

    processed_query = analyze_log(question)


    # ---------------------------------
    # Retrieve Context (RAG)
    # ---------------------------------

    processed_query = analyze_log(question)

    context = search_attack(processed_query)

    if not context:
        print("\n⚠️ No relevant intelligence found.\n")
        continue


    # ---------------------------------
    # Prompt
    # ---------------------------------

    prompt = f"""
You are a professional SOC cybersecurity analyst.

You MUST answer only using the provided threat intelligence context.

STRICT RULES:
- Use ONLY the information inside the context
- Do NOT add external knowledge
- If the answer is not present say exactly:
  "Information not found in retrieved sources."
- Mention ATT&CK technique IDs or CVE IDs when present.

Context:
{context}

Security Event / Question:
{question}

SOC Analysis:
"""


    # ---------------------------------
    # Call LLM
    # ---------------------------------

    try:

        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False
            },
            timeout=300
        )

        if response.status_code != 200:
            print("❌ Ollama Error:", response.text)
            continue

        data = response.json()
        answer = data.get("response", "No response generated.")

    except requests.exceptions.RequestException as e:

        print("\n❌ Error communicating with Ollama:")
        print(e)
        continue


    # ---------------------------------
    # Output Analysis
    # ---------------------------------

    print("\n🧠 SOC Analysis:\n")
    print(answer.strip())


    # ---------------------------------
    # Threat Severity
    # ---------------------------------

    severity = calculate_severity(question)

    print("\n⚠ Threat Severity:", severity)


    # ---------------------------------
    # Recommended SOC Actions
    # ---------------------------------

    actions = recommend_actions(question)

    if actions:

        print("\n🛠 Recommended SOC Actions:\n")

        for a in actions:
            print("•", a)


    # ---------------------------------
    # Sources
    # ---------------------------------

    print("\n🔎 Sources Used:\n")

    sources = context.split("\n\n")

    for src in sources[:3]:
        print(src[:300])
        print()

    print("------------------------------------\n")