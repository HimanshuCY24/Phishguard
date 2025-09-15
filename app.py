from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import re
import time
import os

app = Flask(__name__)

RECENT_CHECKS = []
MAX_HISTORY = 10

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "secure", "account", "update", "verify",
    "bank", "confirm", "webscr", "ebayisapi", "wp-login", "admin"
]

IP_REGEX = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
AT_SYMBOL_REGEX = re.compile(r"@")
HEX_ENCODING_REGEX = re.compile(r"%[0-9a-fA-F]{2}")

def normalize_url(raw):
    if not raw:
        return ""
    raw = raw.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", raw):
        raw = "http://" + raw
    return raw

def extract_domain(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        return hostname.lower() if hostname else None
    except Exception:
        return None

def count_subdomains(hostname):
    if not hostname:
        return 0
    hostname = hostname.rstrip('.')
    return max(0, len(hostname.split('.')) - 2)

def heuristic_score(url):
    reasons, score = [], 0
    if not url:
        return False, score, ["⚠️ Empty input"], {"normalized": "", "domain": None}

    normalized = normalize_url(url)
    domain = extract_domain(normalized)
    lower = normalized.lower()

    if AT_SYMBOL_REGEX.search(lower):
        reasons.append("Contains '@' which can hide the real domain")
        score += 3
    if IP_REGEX.search(lower):
        reasons.append("URL contains an IP address instead of domain")
        score += 3
    if any(kw in lower for kw in SUSPICIOUS_KEYWORDS):
        reasons.append("Suspicious keyword found in URL")
        score += 2
    if len(HEX_ENCODING_REGEX.findall(lower)) >= 4:
        reasons.append("Multiple encoded characters (possible obfuscation)")
        score += 2
    if len(lower) > 120:
        reasons.append("Very long URL (length > 120)")
        score += 1
    if domain and domain.count('-') >= 3:
        reasons.append("Domain contains many hyphens")
        score += 1
    if len(re.findall(r"\d", lower)) >= 6:
        reasons.append("URL contains many digits")
        score += 1
    if count_subdomains(domain) >= 3:
        reasons.append("Too many subdomains")
        score += 1
    if domain and domain.endswith((".xyz", ".ru", ".tk", ".cf", ".ga")):
        reasons.append("Suspicious domain extension")
        score += 2

    if not reasons:
        reasons.append("No obvious suspicious patterns found")

    is_suspicious = score >= 3
    meta = {"normalized": normalized, "domain": domain, "length": len(lower)}

    return is_suspicious, score, reasons, meta

def save_check(entry):
    RECENT_CHECKS.insert(0, entry)
    if len(RECENT_CHECKS) > MAX_HISTORY:
        RECENT_CHECKS.pop()

@app.route("/", methods=["GET", "POST"])
def home():
    result, url, reasons, risk_level = None, "", [], "Low"
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        is_suspicious, score, reasons, meta = heuristic_score(url)
        label = "Suspicious" if is_suspicious else "Safe"
        risk_level = "High" if score >= 6 else ("Medium" if score >= 3 else "Low")
        result = {
            "label": label,
            "message": f"{'⚠️ Suspicious' if is_suspicious else '✅ Safe'} URL: {meta['normalized']}",
            "score": score,
            "risk_level": risk_level
        }
        entry = {
            "url": meta["normalized"],
            "domain": meta["domain"],
            "label": label,
            "score": score,
            "risk_level": risk_level,
            "time": time.strftime("%H:%M:%S")
        }
        save_check(entry)
    return render_template("index.html", result=result, url=url, reasons=reasons, history=RECENT_CHECKS)

@app.route("/history", methods=["GET"])
def history():
    return jsonify({"history": RECENT_CHECKS})

if __name__ == "__main__":
    host = os.environ.get("PHISH_HOST", "0.0.0.0")
    port = int(os.environ.get("PHISH_PORT", 5000))
    print(f"🚀 Running on http://{host}:{port}")
    app.run(host=host, port=port, debug=True)
