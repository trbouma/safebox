# Agent API

## Overview

The Agent API provides non-browser access to Safebox wallet operations for automation clients (for example OpenClaw agents).  
Unlike browser routes, Agent API authentication is header-based and does not rely on cookies or session redirects.

This API is additive and isolated from existing web routes, allowing machine clients to integrate without changing current browser UX flows.

## Scope

Current scope (initial release):

- Wallet identity/status lookup
- Balance lookup
- Invite-based wallet onboarding
- Invoice creation
- Invoice payment
- Ecash token issuance
- Ecash token acceptance

Out of scope (current release):

- Full record offer/request API parity
- Policy-scoped API permissions
- Signed request replay protection

## Authentication Model

Agent routes use:

- Header: `X-Access-Key: <wallet_access_key>`

Behavior:

1. Resolve wallet from `RegisteredSafebox.access_key`
2. Support hyphenless key compatibility matching
3. Instantiate wallet context and load state before executing request

If key resolution fails, API returns `401`.

## Endpoints

Base prefix:

- `/agent`

## Curl Quickstart

```bash
BASE_URL="https://skills.example.com"
API_KEY="your-wallet-access-key"
```

### `GET /agent/info`

Returns wallet metadata and current balance.

Response (example):

```json
{
  "status": "OK",
  "handle": "example-handle",
  "npub": "npub1...",
  "balance": 12345,
  "home_relay": "wss://relay.example",
  "timestamp": 1770000000
}
```

Curl:

```bash
curl -sS \
  -H "X-Access-Key: ${API_KEY}" \
  "${BASE_URL}/agent/info"
```

### `GET /agent/balance`

Returns current wallet balance in sats.

Response (example):

```json
{
  "status": "OK",
  "balance": 12345,
  "unit": "sat",
  "timestamp": 1770000000
}
```

Curl:

```bash
curl -sS \
  -H "X-Access-Key: ${API_KEY}" \
  "${BASE_URL}/agent/balance"
```

### `POST /agent/onboard`

Creates a new wallet from a valid invite code and returns operational plus recovery material.

Request:

```json
{
  "invite_code": "alpha"
}
```

Curl:

```bash
curl -sS -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "invite_code": "alpha"
  }' \
  "${BASE_URL}/agent/onboard"
```

Response (example):

```json
{
  "status": "OK",
  "wallet": {
    "handle": "example-handle",
    "npub": "npub1...",
    "nsec": "nsec1...",
    "access_key": "1234-word-word",
    "home_relay": "wss://relay.example",
    "balance": 0,
    "seed_phrase": "word1 word2 ... word12",
    "emergency_code": "ABC123"
  },
  "session": {
    "access_token": "<jwt>",
    "token_type": "bearer"
  },
  "timestamp": 1770000000
}
```

### `POST /agent/create_invoice`

Creates a Lightning invoice for a SAT amount and starts async settlement monitoring.

Request:

```json
{
  "amount": 1000,
  "comment": "Please Pay!"
}
```

Curl:

```bash
curl -sS -X POST \
  -H "X-Access-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 1000,
    "comment": "Please Pay!"
  }' \
  "${BASE_URL}/agent/create_invoice"
```

Response (example):

```json
{
  "status": "OK",
  "invoice": "lnbc...",
  "quote": "abc123...",
  "amount": 1000,
  "unit": "sat"
}
```

### `POST /agent/pay_invoice`

Pays a provided invoice from the authenticated wallet.

Request:

```json
{
  "invoice": "lnbc...",
  "comment": "Paid by agent",
  "tendered_amount": 1000.0,
  "tendered_currency": "SAT"
}
```

Curl:

```bash
curl -sS -X POST \
  -H "X-Access-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "invoice": "lnbc...",
    "comment": "Paid by agent",
    "tendered_amount": 1000.0,
    "tendered_currency": "SAT"
  }' \
  "${BASE_URL}/agent/pay_invoice"
```

### `POST /agent/issue_ecash`

Issues a Cashu ecash token for a SAT amount from the authenticated wallet.

Request:

```json
{
  "amount": 1000,
  "comment": "ecash withdrawal"
}
```

Curl:

```bash
curl -sS -X POST \
  -H "X-Access-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 1000,
    "comment": "ecash withdrawal"
  }' \
  "${BASE_URL}/agent/issue_ecash"
```

Response (example):

```json
{
  "status": "OK",
  "ecash_token": "cashuA...",
  "amount": 1000,
  "unit": "sat",
  "balance": 10343,
  "timestamp": 1770000000
}
```

### `POST /agent/accept_ecash`

Accepts and redeems a Cashu ecash token into the authenticated wallet.

Request:

```json
{
  "ecash_token": "cashuA...",
  "comment": "ecash deposit",
  "tendered_amount": 1000.0,
  "tendered_currency": "SAT"
}
```

Curl:

```bash
curl -sS -X POST \
  -H "X-Access-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "ecash_token": "cashuA...",
    "comment": "ecash deposit",
    "tendered_amount": 1000.0,
    "tendered_currency": "SAT"
  }' \
  "${BASE_URL}/agent/accept_ecash"
```

Response (example):

```json
{
  "status": "OK",
  "message": "Successfully accepted 1000 sats!",
  "accepted_amount": 1000,
  "unit": "sat",
  "balance": 11343,
  "timestamp": 1770000000
}
```

Response (example):

```json
{
  "status": "OK",
  "message": "Payment OK",
  "fees_paid": 2,
  "payment_hash": "abc...",
  "payment_preimage": "def...",
  "description_hash": null,
  "balance": 11343,
  "timestamp": 1770000000
}
```

## Error Semantics

- `401` - Missing/invalid API key
- `403` - Invalid invite code (onboarding)
- `409` - Wallet registration conflict during onboarding
- `429` - Rate limit exceeded (`Retry-After` header included)
- `400` - Invalid payload or payment failure
- `500` - Wallet load failure or internal processing error

Responses include a `detail` field for actionable errors where available.

## Rate Limiting

Agent routes support built-in in-memory rate limiting controlled by `Settings`:

- `AGENT_RATE_LIMIT_ENABLED` (default: `true`)
- `AGENT_RPM` (default: `60`)
- `AGENT_BURST` (default: `20`)
- `AGENT_ONBOARD_RPM` (default: `10`)
- `AGENT_ONBOARD_BURST` (default: `5`)

Enforcement model:

- Authenticated `/agent/*` calls: limited by `X-Access-Key` (falls back to client IP when key missing).
- `/agent/onboard`: separately limited by client IP to reduce invite abuse.

When limit is exceeded:

- API returns `429`
- `Retry-After` response header indicates when to retry

## Security Considerations

- Treat `X-Access-Key` as a bearer credential.
- Always use HTTPS/TLS in production.
- Do not log raw API keys in request logs.
- Apply route-level rate limiting and abuse controls for `/agent/*`.
- Prefer key rotation operational policy for compromised keys.

## Operational Guidance

- Keep browser and agent paths separate; do not mix cookie/session assumptions into machine routes.
- Monitor `/agent/*` independently for automation abuse and integration failures.
- Add structured audit logs (operation, wallet handle/npub, outcome, timestamp) without secret leakage.

## Implementation References

- `app/routers/agent.py`
- `app/main.py`
- `app/appmodels.py`
- `skills/agent-api/SKILL.md`
