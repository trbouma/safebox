# CORS Browser-Agent Incident Postmortem (2026-02-25)

## Summary
- Browser-based agent calls from `https://www.openbrowserclaw.com` to `https://safebox.dev` failed even when command-line `curl` tests worked.
- Primary impact was blocked Agent API calls in browser environments (`/agent/*`, legacy `/api/v1/*`, and some `/.well-known/*` flows).

## User-Visible Symptoms
- Browser console errors:
  - `No 'Access-Control-Allow-Origin' header is present on the requested resource.`
  - `Access-Control-Allow-Origin contains multiple values ... but only one is allowed.`
- Agent reported `Failed to fetch` despite server availability.

## Root Causes
1. **Path mismatch**
- Browser agent called legacy endpoints such as `/api/v1/balance` while primary implementation was `/agent/*`.
- CORS testing initially validated one path family while failures occurred on another.

2. **Duplicate CORS header injection**
- CORS headers were added in multiple layers:
  - FastAPI `CORSMiddleware`
  - custom FastAPI HTTP middleware
  - nginx `add_header` directives
- Result: duplicate `Access-Control-Allow-Origin` header values, which browsers reject.

3. **Preflight intercepted by reverse proxy**
- nginx handled `OPTIONS` preflight directly in some cases and returned responses without required CORS headers after header changes.
- This blocked browser preflight before app middleware could respond.

## Corrective Actions Implemented
- Added explicit allowed origins in app config:
  - `https://openbrowserclaw.com`
  - `https://www.openbrowserclaw.com`
- Added legacy compatibility route mapping:
  - `/api/v1/*` -> Agent router (same handlers as `/agent/*`).
- Removed custom app-level CORS header middleware to avoid double injection.
- Kept a single CORS authority in app (`CORSMiddleware`).
- Removed nginx CORS `add_header` directives that duplicated app headers.
- Removed/disabled nginx `OPTIONS` short-circuit logic so preflight is proxied to app.

## Verification Performed
- `OPTIONS` and `GET` tested for both `/agent/*` and `/api/v1/*`.
- Confirmed single `Access-Control-Allow-Origin` header in responses.
- Confirmed reflected origin behavior for `https://www.openbrowserclaw.com`.
- Confirmed browser-agent access path now succeeds.

## Preventive Controls
- Maintain one CORS authority (application layer preferred).
- Do not mix app CORS middleware with proxy `add_header` CORS unless fully intentional.
- Include both preflight and real-request checks in deployment validation:
  - `OPTIONS` with `Origin`, `Access-Control-Request-Method`, `Access-Control-Request-Headers`
  - real `GET/POST` with `Origin` and auth headers.
- Validate all supported path families (`/agent/*`, `/api/v1/*`, `/.well-known/*`) in regression tests.
- Keep a reverse-proxy lint checklist item: no CORS `add_header` duplication and no preflight interception.

## Quick Diagnostic Commands
```bash
# Preflight
curl -i -X OPTIONS "https://safebox.dev/agent/info" \
  -H "Origin: https://www.openbrowserclaw.com" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: Content-Type, X-Access-Key, Authorization"

# Real request
curl -i "https://safebox.dev/agent/info" \
  -H "Origin: https://www.openbrowserclaw.com" \
  -H "X-Access-Key: <valid_key>"

# Detect duplicate CORS headers
curl -i "https://safebox.dev/agent/info" \
  -H "Origin: https://www.openbrowserclaw.com" \
  -H "X-Access-Key: <valid_key>" | grep -i access-control-allow-origin
```

