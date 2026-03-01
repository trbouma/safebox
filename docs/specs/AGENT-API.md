# Agent API

## Overview

The Agent API provides non-browser access to Safebox wallet operations for automation clients (for example OpenClaw agents).  
Unlike browser routes, Agent API authentication is header-based and does not rely on cookies or session redirects.

This API is additive and isolated from existing web routes, allowing machine clients to integrate without changing current browser UX flows.

## Scope

Current scope (initial release):

- Wallet identity/status lookup
- Custom handle management
- Balance lookup
- Supported-currency lookup
- Private-message read
- Invite-based wallet onboarding
- Invoice creation
- Invoice payment
- Lightning-address payment
- Secure direct messaging
- Ecash token issuance
- Ecash token acceptance
- Offer/grant dispatch lifecycle for agent-driven record sends

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
  "lightning_address": "example-handle@skills.example.com",
  "npub": "npub1...",
  "balance": 12345,
  "home_relay": "wss://relay.example",
  "timestamp": 1770000000
}
```

Notes:

- `lightning_address` is derived from the request host.
- If a wallet `custom_handle` exists, that handle is used; otherwise the default `handle` is used.

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

### `POST /agent/set_custom_handle`

Sets a wallet-specific `custom_handle` for agent operations.

Request:

```json
{
  "custom_handle": "myagent"
}
```

Curl:

```bash
curl -sS -X POST \
  -H "X-Access-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "custom_handle": "myagent"
  }' \
  "${BASE_URL}/agent/set_custom_handle"
```

Response (example):

```json
{
  "status": "OK",
  "custom_handle": "myagent",
  "lightning_address": "myagent@skills.example.com",
  "detail": "Custom handle set to myagent",
  "timestamp": 1770000000
}
```

Validation and errors:

- `400` if `custom_handle` is missing or invalid.
- `409` if the handle is already taken.

### `GET /agent/tx_history`

Returns wallet transaction history for the authenticated agent wallet.

Query params:

- `limit` (optional, default `50`, max `500`)

Response (example):

```json
{
  "status": "OK",
  "count": 2,
  "transactions": [
    {
      "create_time": "2026-02-23 12:45:01",
      "tx_type": "C",
      "amount": 1000,
      "comment": "Please Pay!"
    },
    {
      "create_time": "2026-02-23 12:44:12",
      "tx_type": "D",
      "amount": 1000,
      "comment": "Paid by agent"
    }
  ],
  "timestamp": 1770000000
}
```

Curl:

```bash
curl -sS \
  -H "X-Access-Key: ${API_KEY}" \
  "${BASE_URL}/agent/tx_history?limit=50"
```

### `GET /agent/supported_currencies`

Returns supported currency codes and currently available rate metadata for preflight payment validation.

Response (example):

```json
{
  "status": "OK",
  "currencies": [
    {
      "currency_code": "SAT",
      "currency_symbol": "s",
      "currency_rate": 100000000.0,
      "fractional_unit": "sats",
      "number_to_base": 100000000,
      "refresh_time": 1770000000,
      "available": true
    },
    {
      "currency_code": "USD",
      "currency_symbol": "$",
      "currency_rate": 106500.0,
      "fractional_unit": "cents",
      "number_to_base": 100,
      "refresh_time": 1770000000,
      "available": true
    }
  ],
  "timestamp": 1770000000
}
```

Curl:

```bash
curl -sS \
  -H "X-Access-Key: ${API_KEY}" \
  "${BASE_URL}/agent/supported_currencies"
```

### `GET /agent/read_dms`

Reads private messages for the authenticated wallet using gift-wrapped message records.

Query params:

- `limit` (optional, default `50`, max `200`)
- `kind` (optional, default `1059`)
- `relays` (optional): comma-separated relay list override

Curl:

```bash
curl -sS \
  -H "X-Access-Key: ${API_KEY}" \
  "${BASE_URL}/agent/read_dms?limit=20&kind=1059"
```

Response (example):

```json
{
  "status": "OK",
  "kind": 1059,
  "count": 2,
  "messages": [
    {
      "tag": ["message"],
      "type": "dm",
      "created_at": "2026-03-01 12:34:56",
      "payload": "hello",
      "id": "abc123...",
      "timestamp": 1772368496,
      "presenter": "....",
      "sender": "....",
      "social_name": "Example"
    }
  ],
  "timestamp": 1772368500
}
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
  "unit": "sat",
  "invoice_status": "PENDING",
  "status_path": "/agent/invoice_status/abc123..."
}
```

### `GET /agent/invoice_status/{quote}`

Returns settlement status for a previously created invoice quote.

Response (example):

```json
{
  "status": "OK",
  "quote": "abc123...",
  "quote_status": "PAID",
  "amount": 1000,
  "mint": "https://mint.getsafebox.app"
}
```

Curl:

```bash
curl -sS \
  -H "X-Access-Key: ${API_KEY}" \
  "${BASE_URL}/agent/invoice_status/abc123..."
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

### `POST /agent/pay_lightning_address`

Pays a Lightning address directly (server-side LNURL resolution and invoice/payment handling).

Accepted amount modes:

- `amount_sats` (integer sats), or
- `amount` (floating-point) with `currency` (for example `USD`, `EUR`, `SAT`)

Request:

```json
{
  "lightning_address": "alice@example.com",
  "amount_sats": 1000,
  "comment": "Paid by agent",
  "tendered_amount": 1000.0,
  "tendered_currency": "SAT"
}
```

Alternative request (fiat input):

```json
{
  "lightning_address": "alice@example.com",
  "amount": 1.50,
  "currency": "USD",
  "comment": "Paid by agent"
}
```

Curl:

```bash
curl -sS -X POST \
  -H "X-Access-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "lightning_address": "alice@example.com",
    "amount_sats": 1000,
    "comment": "Paid by agent",
    "tendered_amount": 1000.0,
    "tendered_currency": "SAT"
  }' \
  "${BASE_URL}/agent/pay_lightning_address"
```

Response (example):

```json
{
  "status": "OK",
  "message": "Payment of 1000 sats with fee 2 sats to alice@example.com successful!",
  "lightning_address": "alice@example.com",
  "amount_sats": 1000,
  "converted_from_currency": false,
  "fees_paid": 2,
  "balance": 9341,
  "timestamp": 1770000000
}
```

### `POST /agent/secure_dm`

Sends a secure direct message from the authenticated Safebox wallet to a recipient.

Request:

```json
{
  "recipient": "alice@example.com",
  "message": "Hello from Safebox agent",
  "relays": ["wss://relay.damus.io", "wss://relay.primal.net"]
}
```

Request fields:

- `recipient` (required): NIP-05 (`name@domain`), `npub1...`, or 64-char pubhex
- `message` (required): plaintext message payload before encryption
- `relays` (optional): DM relay override; if omitted, server uses configured `PUBLIC_RELAYS`

Curl:

```bash
curl -sS -X POST \
  -H "X-Access-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "recipient": "alice@example.com",
    "message": "Hello from Safebox agent"
  }' \
  "${BASE_URL}/agent/secure_dm"
```

Response (example):

```json
{
  "status": "OK",
  "message": "message sent",
  "recipient": "alice@example.com",
  "relays": ["wss://relay.damus.io", "wss://relay.primal.net"],
  "timestamp": 1770000000
}
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

### Offer/Grant Agent Flow

These endpoints let an agent coordinate offer/grant transmission using the same sender-side record flow used by web UI routes.

#### `POST /agent/offers/create`

Create a sender-side offer intent and QR (`nauth`) for recipient authentication.

Request:

```json
{
  "grant_kind": 34104,
  "grant_name": "Passport",
  "compact": true
}
```

Curl:

```bash
curl -sS -X POST \
  -H "X-Access-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "grant_kind": 34104,
    "grant_name": "Passport",
    "compact": true
  }' \
  "${BASE_URL}/agent/offers/create"
```

#### `GET /agent/offers/{offer_id}/status`

Get current offer state. Optional `wait_seconds` waits for recipient auth capture when status is `WAITING_RECIPIENT`.

Curl:

```bash
curl -sS \
  -H "X-Access-Key: ${API_KEY}" \
  "${BASE_URL}/agent/offers/${OFFER_ID}/status?wait_seconds=30"
```

#### `POST /agent/offers/{offer_id}/capture`

Capture a scanned recipient nauth directly.

Request:

```json
{
  "recipient_nauth": "nauth1..."
}
```

Curl:

```bash
curl -sS -X POST \
  -H "X-Access-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "recipient_nauth": "nauth1..."
  }' \
  "${BASE_URL}/agent/offers/${OFFER_ID}/capture"
```

#### `POST /agent/offers/{offer_id}/send`

Dispatch the configured grant to the captured recipient.

Curl:

```bash
curl -sS -X POST \
  -H "X-Access-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{}' \
  "${BASE_URL}/agent/offers/${OFFER_ID}/send"
```

#### `GET /agent/offers/{offer_id}/delivery`

Returns dispatch lifecycle state after send attempts.  
This endpoint confirms sender-side dispatch result (`DISPATCHED`/`FAILED`), not recipient-side attestation.

Curl:

```bash
curl -sS \
  -H "X-Access-Key: ${API_KEY}" \
  "${BASE_URL}/agent/offers/${OFFER_ID}/delivery?wait_seconds=10"
```

Response fields (important):

- `offer_status`: `WAITING_RECIPIENT`, `RECIPIENT_READY`, `SENDING`, `SENT`, or `FAILED`
- `delivery_status`: `PENDING`, `DISPATCHED`, or `FAILED`
- `dispatch_detail`: sender-side completion detail
- `last_error`: populated when dispatch fails

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
