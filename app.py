from flask import Flask, render_template_string, request, send_file
from urllib.parse import urlparse
from datetime import datetime
from pathlib import Path
import requests, json, io, hashlib

app = Flask(__name__)
BASE = Path(__file__).resolve().parent
DATA = BASE / "evidence"
DATA.mkdir(exist_ok=True)
history = []

HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VulnScope AI</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#0b1120;color:#e5edf8;font:15px Arial,sans-serif}
header{padding:24px 5%;background:#111b2e;border-bottom:1px solid #293750}
h1{margin:0;color:#72e5c1}header p,.muted{color:#9aacc5}
main{max-width:1150px;margin:28px auto;padding:0 18px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:15px}
.card{background:#131f33;border:1px solid #293750;border-radius:12px;padding:20px;margin-bottom:16px}
.num{font-size:30px;font-weight:bold;margin-top:12px}
input,button{padding:12px;border-radius:7px;border:1px solid #354763}
input{background:#0b1120;color:white;width:min(100%,420px)}
button{background:#72e5c1;color:#081620;font-weight:bold;cursor:pointer}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:12px 8px;border-bottom:1px solid #293750}
th{color:#9aacc5}
a{color:#72e5c1}
.badge{font-weight:bold}
.CRITICAL,.HIGH{color:#ff7777}.MEDIUM{color:#f3cb6a}
.LOW,.INFO{color:#72e5c1}
form{display:flex;gap:10px;flex-wrap:wrap}
small{color:#9aacc5}
</style></head>
<body>
<header><h1>🛡 VulnScope AI</h1>
<p>Web Application Security Assessment Platform · Local Lab Mode</p></header>
<main>
<div class="card">
<h2>New Security Assessment</h2>
<p class="muted">Only localhost targets are permitted. Start Juice Shop first.</p>
<form method="post" action="/scan">
<input name="target" value="http://127.0.0.1:3000"
placeholder="http://127.0.0.1:3000" required>
<button type="submit">Run Assessment</button>
</form>
{% if message %}<p>{{message}}</p>{% endif %}
</div>
<div class="grid">
{% for label,value in cards %}
<div class="card"><div class="muted">{{label}}</div><div class="num">{{value}}</div></div>
{% endfor %}
</div>
<div class="card">
<h2>Findings</h2>
{% if findings %}
<table><tr><th>ID / Finding</th><th>Severity</th><th>Evidence</th></tr>
{% for f in findings %}
<tr><td>{{f.id}} · {{f.title}}<br><small>{{f.url}}</small></td>
<td class="badge {{f.severity}}">{{f.severity}}</td>
<td>{{f.evidence}}</td></tr>
{% endfor %}</table>
{% else %}<p class="muted">No assessment results yet. Run a local lab assessment.</p>{% endif %}
</div>
<div class="card">
<h2>Reports & Evidence</h2>
{% if findings %}
<p>Last assessment: {{scanned_at}}</p>
<p><a href="/report">Download VAPT PDF report</a></p>
<p><a href="/evidence">View evidence JSON</a></p>
{% else %}<p class="muted">Run an assessment to generate a report.</p>{% endif %}
</div>
<div class="card"><h2>Methodology</h2>
<p>Checks: HTTP reachability, HTTPS availability, common security headers and cookie security flags.</p>
<p class="muted">This MVP performs limited passive checks only. It is not a full penetration test.
Findings require manual validation. Sample findings are not presented as confirmed exploits.</p>
</div>
</main></body></html>
"""

def make_finding(title, severity, evidence, url):
    return {
        "id": "VS-" + hashlib.sha1(title.encode()).hexdigest()[:6].upper(),
        "title": title, "severity": severity,
        "evidence": evidence, "url": url,
        "status": "Needs Review"
    }

def safe_local_url(raw):
    u = urlparse(raw.strip())
    if u.scheme not in ("http", "https"):
        raise ValueError("Use an http:// or https:// URL.")
    if u.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("Scope blocked: only localhost targets are allowed.")
    if u.username or u.password:
        raise ValueError("URLs containing credentials are not allowed.")
    if u.port not in (None, 3000, 5000, 8080, 8443):
        raise ValueError("Port not allowed by the local lab policy.")
    return u.geturl().rstrip("/")

@app.route("/")
def dashboard():
    findings = history[-1]["findings"] if history else []
    counts = {s: sum(f["severity"] == s for f in findings)
              for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    cards = [
        ("Total Findings", len(findings)),
        ("High / Critical", counts["HIGH"] + counts["CRITICAL"]),
        ("Medium", counts["MEDIUM"]),
        ("Assessments", len(history))
    ]
    return render_template_string(
        HTML, findings=findings, cards=cards,
        message=request.args.get("message", ""),
        scanned_at=history[-1]["time"] if history else ""
    )

@app.route("/scan", methods=["POST"])
def scan():
    try:
        target = safe_local_url(request.form.get("target", ""))
        response = requests.get(target, timeout=8, allow_redirects=False)
    except (ValueError, requests.RequestException) as e:
        return render_template_string(
            HTML, findings=[], cards=[
                ("Total Findings", 0), ("High / Critical", 0),
                ("Medium", 0), ("Assessments", len(history))
            ], message=f"Assessment stopped: {e}", scanned_at=""
        ), 400

    findings = []
    headers = response.headers
    checks = [
        ("Content-Security-Policy", "Missing Content-Security-Policy", "MEDIUM"),
        ("X-Content-Type-Options", "Missing X-Content-Type-Options", "LOW"),
        ("X-Frame-Options", "Missing X-Frame-Options", "LOW"),
        ("Referrer-Policy", "Missing Referrer-Policy", "LOW"),
    ]
    for header, title, severity in checks:
        if not headers.get(header):
            findings.append(make_finding(
                title, severity, f"{header} header absent in response",
                target
            ))

    if target.startswith("http://"):
        findings.append(make_finding(
            "HTTP used instead of HTTPS", "MEDIUM",
            "The local target was accessed over HTTP; assess TLS in an appropriate environment.",
            target
        ))

    cookies = headers.get("Set-Cookie", "")
    if cookies:
        if "httponly" not in cookies.lower():
            findings.append(make_finding(
                "Cookie missing HttpOnly flag", "LOW",
                "Set-Cookie response did not show the HttpOnly flag.",
                target
            ))
        if target.startswith("https://") and "secure" not in cookies.lower():
            findings.append(make_finding(
                "Cookie missing Secure flag", "LOW",
                "Set-Cookie response did not show the Secure flag.",
                target
            ))

    record = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": target,
        "http_status": response.status_code,
        "findings": findings
    }
    history.append(record)
    (DATA / "latest.json").write_text(
        json.dumps(record, indent=2), encoding="utf-8"
    )
    return __import__("flask").redirect("/")

@app.route("/evidence")
def evidence():
    p = DATA / "latest.json"
    if not p.exists():
        return "No assessment evidence yet.", 404
    return send_file(p, as_attachment=True, download_name="vulnscope-evidence.json")

@app.route("/report")
def report():
    if not history:
        return "Run an assessment first.", 404
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors

    rec = history[-1]
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("VulnScope AI — Security Assessment Report", styles["Title"]),
        Spacer(1, 12),
        Paragraph("Target: " + rec["target"], styles["Normal"]),
        Paragraph("Assessment date: " + rec["time"], styles["Normal"]),
        Paragraph("HTTP status: " + str(rec["http_status"]), styles["Normal"]),
        Spacer(1, 16),
        Paragraph("Scope and limitations", styles["Heading2"]),
        Paragraph("Limited passive checks against a localhost lab. Findings are unverified indicators, not proof of exploitability. This is not a full penetration test.", styles["BodyText"]),
        Spacer(1, 16),
        Paragraph("Findings", styles["Heading2"])
    ]
    rows = [["ID", "Finding", "Severity", "Evidence"]]
    for f in rec["findings"]:
        rows.append([f["id"], f["title"], f["severity"], f["evidence"]])
        story.extend([
            Paragraph(f["id"] + " — " + f["title"], styles["Heading3"]),
            Paragraph("Severity: " + f["severity"], styles["Normal"]),
            Paragraph("Evidence: " + f["evidence"], styles["BodyText"]),
            Paragraph("Recommended action: review the relevant web-server or application configuration, apply an appropriate fix, then retest.", styles["BodyText"]),
            Spacer(1, 8)
        ])
    if not rec["findings"]:
        story.append(Paragraph("No issues detected by these limited checks. This does not prove the application is secure.", styles["BodyText"]))
    story.extend([
        Spacer(1, 16),
        Paragraph("Supplementary Manual Observation: CORS", styles["Heading2"]),
        Paragraph(
            "During a separate manual check of the local Juice Shop homepage and "
            "robots.txt, responses included Access-Control-Allow-Origin: *. "
            "Access-Control-Allow-Credentials was not observed in the saved evidence.",
            styles["BodyText"]
        ),
        Spacer(1, 6),
        Paragraph("Assessment status: Observed configuration; security impact not established.",
                  styles["Normal"]),
        Paragraph(
            "A wildcard CORS header alone does not prove a vulnerability. "
            "Only two endpoints were checked. Sensitive-data exposure, authenticated "
            "cross-origin access, and application-wide CORS behavior were not established. "
            "Review whether wildcard access is intentional and retest affected resources.",
            styles["BodyText"]
        ),
        Paragraph("Evidence file: evidence/cors-verification.txt",
                  styles["BodyText"]),
    ])

    doc.build(story)
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name="VulnScope-VAPT-Report.pdf", mimetype="application/pdf")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
