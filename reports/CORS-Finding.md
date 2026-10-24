# VS-CORS-001 — Wildcard CORS Header Observed

## Status
Observed configuration; security impact not established.

## Scope
Local OWASP Juice Shop lab:
- `http://127.0.0.1:3000/`
- `http://127.0.0.1:3000/robots.txt`

## Observation
Requests sent with the Origin header `https://example.com` returned:
- HTTP 200 OK
- `Access-Control-Allow-Origin: *`
- `Vary: Accept-Encoding`

The `Access-Control-Allow-Credentials` header was not observed in these responses.

## Evidence
- `evidence/cors-verification.txt`

## Security Context
A wildcard CORS policy permits browser scripts from arbitrary origins to read responses when the resource and browser's CORS checks allow it. This is not automatically a vulnerability. The tested responses alone do not establish access to sensitive data or authenticated resources.

## Recommendation
Review whether wildcard cross-origin access is intentional for each affected resource. If resources contain non-public information, restrict allowed origins according to application requirements and test the policy in the browser.

## Limitations
Only two endpoints were tested. Sensitive-data exposure, authenticated cross-origin access, and application-wide CORS behavior were not established.

## Retest
Not performed. No configuration changes were made.
