# VulnScope-AI
### Beginner Web Application Security Assessment Portfolio

## Project Overview
VulnScope-AI is a beginner-friendly Python and Flask dashboard
for performing limited passive security checks against a local
web application in an authorized lab environment.

## Objectives
- Learn the basic VAPT assessment workflow.
- Identify selected web security configuration issues.
- Record findings as JSON evidence.
- Generate a PDF assessment report.
- Practice documenting findings and remediation.

## Lab Environment
- Operating System: Kali Linux
- Programming Language: Python
- Web Framework: Flask
- Practice Target: OWASP Juice Shop
- Local Target URL: http://127.0.0.1:3000
- Dashboard URL: http://127.0.0.1:5000

## Implemented Features
- HTTP response status check
- Selected security response-header checks
- Basic cookie flag checks
- JSON evidence storage
- PDF report generation
- Simple web dashboard

## Sample Assessment Observations
The local lab review recorded these observations:
- Content-Security-Policy was not observed in one homepage response.
- Referrer-Policy was not observed in one homepage response.
- The local target was accessed over HTTP rather than HTTPS.
- `Access-Control-Allow-Origin: *` was observed on the homepage and
  `robots.txt` responses during a separate CORS check.

These observations are limited in scope and do not prove exploitability.
The CORS observation does not by itself establish access to sensitive data
or authenticated resources. See `reports/CORS-Finding.md` and the saved
evidence files for details and limitations.

## Project Structure
- app.py: Flask dashboard and assessment logic
- evidence/latest.json: Latest saved assessment evidence
- evidence/cors-verification.txt: CORS response evidence
- evidence/fresh-homepage-headers.txt: Fresh homepage header capture
- reports/VulnScope-VAPT-Report.pdf: Sample PDF report
- reports/VulnScope-Detailed-VAPT-Report.pdf: Detailed lab report
- reports/CSP-Finding.md: CSP observation and notes
- reports/CORS-Finding.md: CORS observation and limitations
- reports/Remediation-Plan.md: Suggested remediation plan
- README.md: Project documentation
- .gitignore: Excluded development files

## How to Run
1. Start the OWASP Juice Shop lab separately.
2. Open a terminal in this project directory.
3. Activate the Python virtual environment:

   source .venv/bin/activate

4. Start the dashboard:

   python app.py

5. Open http://127.0.0.1:5000 in your browser.
6. Use the dashboard to run the limited assessment against
   the local lab target.

## Limitations
This project currently performs limited checks. It is not a
complete penetration-testing framework and does not establish
exploitability. Findings must be manually validated. HTTPS,
authentication, access control, and deeper vulnerability testing
require additional assessment methods.

## Safety and Authorization
Use this project only against applications you own or have
explicit permission to assess. Keep testing within the authorized
scope and use the local OWASP Juice Shop lab for practice.

## Author
MD Alauddin
