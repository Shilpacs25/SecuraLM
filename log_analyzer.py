import re


def extract_indicators(log_text):

    indicators = []

    text = log_text.lower()

    # --------------------------------
    # Execution Techniques
    # --------------------------------

    if "powershell" in text:
        indicators.append("powershell execution")

    if "cmd.exe" in text:
        indicators.append("command shell execution")

    if "iex(" in text:
        indicators.append("in memory script execution")

    if "downloadstring" in text:
        indicators.append("remote script download")

    if "executionpolicy bypass" in text:
        indicators.append("execution policy bypass")

    # --------------------------------
    # Credential Dumping
    # --------------------------------

    if "lsass" in text or "sekurlsa" in text:
        indicators.append("credential dumping")

    # --------------------------------
    # Office Macro Attack
    # --------------------------------

    if "winword.exe" in text and "powershell" in text:
        indicators.append("office macro execution")

    # --------------------------------
    # Scheduled Task Persistence
    # --------------------------------

    if "eventid:4698" in text or "schtasks" in text:
        indicators.append("scheduled task persistence")

    # --------------------------------
    # RDP / Lateral Movement
    # --------------------------------

    if "eventid:4624" in text and "logontype:10" in text:
        indicators.append("remote desktop login")

    # --------------------------------
    # Data Exfiltration
    # --------------------------------

    if "bytessent" in text:
        indicators.append("large outbound data transfer")

    return indicators


def analyze_log(log_text):

    indicators = extract_indicators(log_text)

    if not indicators:
        return log_text

    print("\n🧾 SOC Log Indicators Detected:\n")

    for i in indicators:
        print("-", i)

    query = " ".join(indicators)

    print("\n🔍 Converted Investigation Query:")
    print(query)

    return query