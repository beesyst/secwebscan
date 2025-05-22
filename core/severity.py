import re

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]

SEVERITY_KEYWORDS = {
    "critical": [
        r"\bcve-\d{4}-\d{4,7}\b.{0,32}\b(9\.\d|10\.0|critical|exploit|remote code execution|rce|unauthenticated)\b",
        r"\bexploit\b",
        r"\bremote code execution\b",
        r"\bprivilege escalation\b",
        r"\boutdated\b.{0,32}\bexploit\b",
    ],
    "high": [
        r"\bcve-\d{4}-\d{4,7}\b",
        r"\bexploit\b",
        r"\banonymous\b",
        r"\bbackdoor\b",
        r"\bdefault credentials\b",
        r"\bunauthenticated\b",
        r"\bdeserialization\b",
        r"\bunsafe\b",
        r"\boutdated\b",
        r"\bpassword reuse\b",
    ],
    "medium": [
        r"\bvulnerab(le|ility|ilities)\b",
        r"\binsecure\b",
        r"\bopen\b",
        r"\bdeprecated\b",
        r"\bmisconfiguration\b",
    ],
    "low": [
        r"\bfiltered\b",
        r"\bopen\|filtered\b",
        r"\bno-response\b",
        r"\btimeout\b",
        r"\binfo\b",
        r"\bpotential\b",
        r"\bwaf\b",
        r"\bfirewall\b",
    ],
}


def classify_severity(entry, custom_keywords=None):
    """
    Универсальная функция для классификации severity.
    entry: dict (любой результат плагина)
    custom_keywords: dict, если нужно добавить или переопределить ключевые слова
    """

    fields = [
        "script_output",
        "output",
        "msg",
        "message",
        "description",
        "reason",
        "state",
        "detail",
    ]
    data = []
    for k in fields:
        v = entry.get(k)
        if v:
            data.append(str(v).lower())
    text = " ".join(data)

    state = entry.get("state", "").lower()
    if state in ["open|filtered", "filtered"]:
        return "low"
    if state == "open":
        pass

    keywords = SEVERITY_KEYWORDS.copy()
    if custom_keywords:
        for sev, patterns in custom_keywords.items():
            if sev not in keywords:
                keywords[sev] = []
            keywords[sev].extend(patterns)

    for severity in SEVERITY_LEVELS:
        patterns = keywords.get(severity, [])
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return severity

    if state == "open":
        return "medium"

    return "info"


if __name__ == "__main__":
    sample = {
        "script_output": "Anonymous FTP login allowed. CVE-2021-12345 exploit.",
        "state": "open",
    }
    print(classify_severity(sample))
