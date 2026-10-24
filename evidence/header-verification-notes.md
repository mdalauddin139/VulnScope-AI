# Security Header Verification

## Target
http://127.0.0.1:3000

## Method
Used curl to inspect the HTTP response headers from the local OWASP Juice Shop lab.

## Observed Results
- HTTP status: 200 OK
- X-Content-Type-Options: nosniff — present
- X-Frame-Options: SAMEORIGIN — present
- Content-Security-Policy — not observed in this response
- Referrer-Policy — not observed in this response

## Limitations
This verification covers the captured response only. It does not prove
that a finding is exploitable or that all routes have the same headers.
The HTTP observation applies to this local lab setup.

## Recommendation
Review the application's security-header configuration and determine
appropriate policies for the application before deploying it.
