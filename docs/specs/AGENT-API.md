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
- Nostr social actions and lookup
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

## Execution Surfaces

Agent API supports multiple execution surfaces over the same `/agent/*` contracts:

- API execution surface: direct HTTP clients (curl, SDKs, service-to-service callers).
- Console execution surface: shell commands via `agent` CLI (`safebox/cli_agent.py`).

Execution-surface rule:

- Console/shell flows are an operator interface layer and do not define a separate protocol.
- Wire behavior, auth model, and endpoint semantics remain those defined in this Agent API spec.

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

### `GET /agent/proof_safety_audit`

Runs proof integrity preflight checks for destructive proof mutation safety.

Query params:

- `check_relay` (optional, default `false`): when `true`, includes a relay state check (slower)

Curl:

```bash
curl -sS \
  -H "X-Access-Key: ${API_KEY}" \
  "${BASE_URL}/agent/proof_safety_audit?check_relay=true"
```

Response (example):

```json
{
  "status": "OK",
  "audit": {
    "safe_to_swap": true,
    "reason": "ok",
    "proof_count": 42,
    "proof_amount": 12345,
    "keyset_count": 2,
    "unknown_keysets": [],
    "invalid_proofs": 0,
    "duplicate_proofs": 0,
    "relay_check": {
      "ok": true,
      "proof_count": 42,
      "proof_amount": 12345,
      "error": null
    }
  },
  "timestamp": 1770000000
}
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

### `WS /agent/ws/read_dms`

Streams private messages for the authenticated wallet using gift-wrapped message records.

Query params:

- `limit` (optional, default `50`, max `200`)
- `kind` (optional, default `1059`)
- `relays` (optional): comma-separated relay list override
- `poll_seconds` (optional, default `5`, clamped to `1..60`)
- `access_key` (optional fallback): wallet access key if websocket headers are unavailable

Auth:

- Preferred: `X-Access-Key` websocket handshake header
- Fallback: `access_key` query parameter

Message envelope:

- `type=connected`: stream initialized
- `type=messages`: changed inbox detected (includes `messages[]`)
- `type=heartbeat`: no change in current poll interval

### `GET /agent/nostr/my_latest_kind1`

Returns latest kind-1 posts authored by the authenticated wallet.

Query params:

- `limit` (optional, default `10`, max `100`)
- `relays` (optional): comma-separated relay list override

Curl:

```bash
curl -sS \
  -H "X-Access-Key: ${API_KEY}" \
  "${BASE_URL}/agent/nostr/my_latest_kind1?limit=10"
```

Response (example):

```json
{
  "status": "OK",
  "pubkey": "bbdfe7ea6a7becbfe6e26c0dccdfd5d01f97972c8600b35acbef9b28aaf63b2a",
  "count": 2,
  "events": [
    {
      "id": "49cc097a631832b812cbbda627d9d96823efbdf85a4dfa49b4c6c3a5671d73f4",
      "event_id": "49cc097a631832b812cbbda627d9d96823efbdf85a4dfa49b4c6c3a5671d73f4",
      "event_id_hex": "49cc097a631832b812cbbda627d9d96823efbdf85a4dfa49b4c6c3a5671d73f4",
      "pubkey": "bbdfe7ea6a7becbfe6e26c0dccdfd5d01f97972c8600b35acbef9b28aaf63b2a",
      "created_at": 1772318043,
      "content": "hello world"
    }
  ],
  "timestamp": 1770000000
}
```

### `GET /agent/nostr/followers`

Returns followers for a target identity by inspecting kind-3 contact lists.

Query params:

- `identifier` (optional): `nip05`, `npub`, or `pubhex`; defaults to the authenticated wallet
- `limit` (optional, default `100`, max `500`)
- `strict` (optional, default `true`): verify against each follower candidate's latest known kind-3 event
- `relays` (optional): comma-separated relay override

Curl:

```bash
curl -sS \
  -H "X-Access-Key: ${API_KEY}" \
  "${BASE_URL}/agent/nostr/followers?limit=50&strict=true"
```

Response (example):

```json
{
  "status": "OK",
  "target_identifier": "npub1...",
  "target_pubkey": "bbdfe7ea6a7becbfe6e26c0dccdfd5d01f97972c8600b35acbef9b28aaf63b2a",
  "strict": true,
  "count": 1,
  "followers": [
    {
      "follower_pubkey": "9170548b2908025e07b33e73dc5f419f2a3d3e83d939a4d312c790b0ff283a7f",
      "follower_npub": "npub1...",
      "event_id": "abcd1234...",
      "created_at": 1770000000,
      "relay_hint": "wss://relay.getsafebox.app",
      "verified_latest_contacts": true
    }
  ],
  "timestamp": 1770000000
}
```

### `GET /agent/nostr/replies`

Returns kind-1 replies referencing a target event.

Query params:

- `event_id` (required)
- `limit` (optional, default `100`, max `200`)
- `relays` (optional): comma-separated relay override

### `GET /agent/nostr/zap_receipts`

Returns zap receipts for a target event.

Query params:

- `event_id` (required)
- `limit` (optional, default `100`, max `200`)
- `strict` (optional, default `false`)
- `relays` (optional): comma-separated relay override

### `GET /agent/nostr/following/latest_kind1`

Returns recent kind-1 posts from authors in the wallet's latest kind-3 follow list.

Query params:

- `limit` (optional, default `20`, max `200`)
- `relays` (optional): comma-separated relay override

### `WS /agent/ws/nostr/latest_kind1`

Streams latest kind-1 events for a target NIP-05 identity.
Target identity must be present in the authenticated wallet's latest kind-3 follow list.
If not followed, connection is closed with policy error (`1008`) after an error payload.

Query params:

- `nip05` (required): NIP-05 identity (`name@domain`)
- `limit` (optional, default `10`, max `100`)
- `relays` (optional): comma-separated relay list override
- `poll_seconds` (optional, default `5`, clamped to `1..60`)
- `access_key` (optional fallback): wallet access key if websocket headers are unavailable

Auth:

- Preferred: `X-Access-Key` websocket handshake header
- Fallback: `access_key` query parameter

Message envelope:

- `type=connected`: stream initialized
- `type=events`: changed event set detected (includes `events[]`)
- `type=heartbeat`: no change in current poll interval

### `GET /agent/nostr/discovery/latest_kind1`

Returns latest kind-1 posts for a target NIP-05 identity without follow-list restriction.

Query params:

- `nip05` (required): NIP-05 identity (`name@domain`)
- `limit` (optional, default `10`, max `100`)
- `relays` (optional): comma-separated relay list override

### `WS /agent/ws/nostr/discovery/latest_kind1`

Streams latest kind-1 events for a target NIP-05 identity without follow-list restriction.

Query params:

- `nip05` (required): NIP-05 identity (`name@domain`)
- `limit` (optional, default `10`, max `100`)
- `relays` (optional): comma-separated relay list override
- `poll_seconds` (optional, default `5`, clamped to `1..60`)
- `access_key` (optional fallback): wallet access key if websocket headers are unavailable

### `WS /agent/ws/nostr/my_latest_kind1`

Streams latest kind-1 events authored by the authenticated wallet.

Query params:

- `limit` (optional, default `10`, max `100`)
- `relays` (optional): comma-separated relay list override
- `poll_seconds` (optional, default `5`, clamped to `1..60`)
- `access_key` (optional fallback): wallet access key if websocket headers are unavailable

### `WS /agent/ws/nostr/following/latest_kind1`

Streams latest kind-1 events from accounts in the wallet follow list.

Query params:

- `limit` (optional, default `20`, max `200`)
- `relays` (optional): comma-separated relay list override
- `poll_seconds` (optional, default `5`, clamped to `1..60`)
- `access_key` (optional fallback): wallet access key if websocket headers are unavailable

## WebSocket Conformance Smoke Tests

Use these checks to validate WS behavior after deploy:

Canonical runnable guide:

- `docs/specs/WS-CONFORMANCE.md`

### WS-CONN-001 (Auth + Connected Frame)

For each WS endpoint:

- connect with valid auth (`X-Access-Key` header preferred; `access_key` query fallback)
- expect first frame with:
  - `status: "OK"`
  - `type: "connected"`

### WS-DATA-002 (Change Frame)

For each WS endpoint:

- cause a relevant state change (new DM or new kind-1 post)
- expect subsequent frame with:
  - `status: "OK"`
  - `type: "messages"` for `/agent/ws/read_dms`, or `type: "events"` for `/agent/ws/nostr/*`
  - non-empty `messages[]` or `events[]` when data exists

### WS-HEARTBEAT-003 (No-Change Frame)

With no new data during one poll interval:

- expect:
  - `status: "OK"`
  - `type: "heartbeat"`

### WS-POLICY-004 (Follow Scope Guard)

For `/agent/ws/nostr/latest_kind1` with an unfollowed `nip05`:

- expect error payload
- expect socket close with policy code `1008`

### WS-FALLBACK-005 (GET Equivalence)

If WS transport is unavailable in runtime:

- use equivalent `GET` path and confirm same logical result set:
  - `/agent/ws/read_dms` -> `/agent/read_dms`
  - `/agent/ws/nostr/latest_kind1` -> `/agent/nostr/latest_kind1`
  - `/agent/ws/nostr/discovery/latest_kind1` -> `/agent/nostr/discovery/latest_kind1`
  - `/agent/ws/nostr/my_latest_kind1` -> `/agent/nostr/my_latest_kind1`
  - `/agent/ws/nostr/following/latest_kind1` -> `/agent/nostr/following/latest_kind1`

### `GET /agent/nostr/zap_receipts`

Returns NIP-57 zap receipts (kind `9735`) for a target event and exposes parsed zapper identity claims.

Query params:

- `event_id` (required): target event id (`hex` or `note1...`)
- `limit` (optional, default `100`, max `200`)
- `relays` (optional): comma-separated relay list override

Curl:

```bash
curl -sS \
  -H "X-Access-Key: ${API_KEY}" \
  "${BASE_URL}/agent/nostr/zap_receipts?event_id=<hex_or_note_id>&limit=50"
```

Response (example):

```json
{
  "status": "OK",
  "event_id": "49cc097a631832b812cbbda627d9d96823efbdf85a4dfa49b4c6c3a5671d73f4",
  "count": 1,
  "receipts": [
    {
      "receipt_id": "67b48a14fb66c60c8f9070bdeb37afdfcc3d08ad01989460448e4081eddda446",
      "created_at": 1674164545,
      "lnurl_provider_pubkey": "9630f464cca6a5147aa8a35f0bcdd3ce485324e732fd39e09233b1d848238f31",
      "lnurl_provider_npub": "npub1...",
      "recipient_pubkey": "32e1827635450ebb3c5a7d12c1f8e7b2b514439ac10a67eef3d9fd9c5c68e245",
      "zapper_pubkey": "97c70a44366a6535c145b333f973ea86dfdc2d7a99da618c40c64705ad98e322",
      "zapper_npub": "npub1...",
      "zapper_identity_source": "description_pubkey",
      "zap_request_raw": "{\"kind\":9734,...}",
      "zap_request": {
        "kind": 9734,
        "pubkey": "97c70a44366a6535c145b333f973ea86dfdc2d7a99da618c40c64705ad98e322",
        "tags": [["e","49cc..."],["p","32e1..."],["amount","21000"]]
      },
      "zap_comment": "",
      "zap_amount_msat": 21000,
      "invoice_amount_msat": 21000,
      "amount_matches": true,
      "matches_target_event": true,
      "description_hash_matches": true,
      "bolt11": "lnbc...",
      "raw_tags": [["p", "..."], ["e", "..."], ["description", "{...}"]]
    }
  ],
  "timestamp": 1770000000
}
```

Identity and validation notes:

- `zapper_pubkey` is parsed from embedded zap request `description.pubkey` (fallback to receipt `P` tag).
- `zapper_identity_source` indicates whether identity came from `description_pubkey`, `P_tag`, or `none`.
- Receipt `pubkey` (`lnurl_provider_pubkey`) is the LNURL provider signer, not the zapper.
- Use `amount_matches` and `description_hash_matches` as guardrails before taking trust-sensitive actions.
- `zap_request_raw` and `zap_request` expose the embedded kind-`9734` request directly for agent-side policy checks.

### `GET /agent/market/orders`

Returns market orders from followed npubs using a dedicated query path.

Query params:

- `limit` (optional, default `50`, max `200`)
- `kind` (optional, default `1`)
- `market` (optional, default `safebox-v1`)
- `side` (optional): `bid|ask|buy|sell`
- `asset` (optional): exact asset label filter
- `relays` (optional): comma-separated relay list override

Curl:

```bash
curl -sS \
  -H "X-Access-Key: ${API_KEY}" \
  "${BASE_URL}/agent/market/orders?limit=50&kind=1&market=safebox-v1"
```

Response (example):

```json
{
  "status": "OK",
  "count": 1,
  "kind": 1,
  "market": "safebox-v1",
  "side": null,
  "asset": null,
  "orders": [
    {
      "event_id": "f4b27...",
      "pubkey": "bbdfe7...",
      "created_at": 1770000000,
      "kind": 1,
      "side": "bid",
      "asset": "riddle.answer",
      "price_sats": "21",
      "quantity": "1",
      "order_id": "a1b2c3d4e5f6a7b8",
      "flow": "bid-first",
      "content": "BUY 1 riddle.answer @ 21 sats",
      "tags": [["mkt","safebox-v1"],["side","bid"],["px","21"]]
    }
  ],
  "timestamp": 1770000000
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

### `POST /agent/react`

Publishes a reaction event.

Mode A: Nostr event reaction (`kind 7`)

```json
{
  "event_id": "49cc097a631832b812cbbda627d9d96823efbdf85a4dfa49b4c6c3a5671d73f4",
  "content": "+",
  "reacted_pubkey": "bbdfe7ea6a7becbfe6e26c0dccdfd5d01f97972c8600b35acbef9b28aaf63b2a",
  "reacted_kind": 1,
  "relay_hint": "wss://relay.getsafebox.app"
}
```

Mode B: external content reaction (`kind 17`)

```json
{
  "content": "⭐",
  "external_tags": [
    ["k", "web"],
    ["i", "https://example.com"]
  ]
}
```

Notes:

- If `event_id` is provided, API publishes `kind 7`.
- If `event_id` is omitted and `external_tags` are provided, API publishes `kind 17`.
- `extra_tags` MAY be included in either mode.

### `POST /agent/reply`

Publishes a kind-1 reply to a target event with NIP-10-compatible `e`/`p`/`k` tags.

### `POST /agent/follow`

Updates the wallet's kind-3 contact list to follow a target identity.

Request fields:

- `identifier` (required): `nip05`, `npub`, or `pubhex`
- `relay_hint` (optional)
- `relays` (optional)

### `POST /agent/unfollow`

Updates the wallet's kind-3 contact list to remove a followed identity.

Request fields:

- `identifier` (required): `nip05`, `npub`, or `pubhex`
- `relays` (optional)

### `POST /agent/delete_request`

Publishes a NIP-09 deletion request (`kind 5`).

Request:

```json
{
  "event_ids": ["49cc097a631832b812cbbda627d9d96823efbdf85a4dfa49b4c6c3a5671d73f4"],
  "kinds": [1],
  "reason": "published by accident"
}
```

Request fields:

- `event_ids` (optional): list of `note1...` or 64-char hex ids
- `a_tags` (optional): list of `<kind>:<pubkey>:<d-identifier>`
- `kinds` (optional): list of integer kind tags
- `reason` (optional): deletion reason placed in `content`
- `relays` (optional): relay override list

### `POST /agent/market/order`

Creates a market order intent (buy/sell) and publishes it as a kind-1 event with structured tags.

Request:

```json
{
  "side": "buy",
  "asset": "riddle.answer",
  "market": "MS-02",
  "price_sats": 21,
  "quantity": "1",
  "flow": "bid-first"
}
```

Request fields:

- `side` (required): `buy`/`sell` (aliases: `bid`/`ask`)
- `asset` (required): asset label or identifier
- `market` (optional): market namespace tag value (`mkt`); default `safebox-v1`
- `price_sats` (required): integer sats
- `quantity` (optional, default `"1"`)
- `order_id` (optional): client-supplied id; autogenerated if omitted
- `content` (optional): custom post text; autogenerated if omitted
- `flow` (optional): strategy label (for example `bid-first`)
- `relays` (optional): relay override list

Curl:

```bash
curl -sS -X POST \
  -H "X-Access-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "side": "buy",
    "asset": "riddle.answer",
    "market": "MS-02",
    "price_sats": 21,
    "quantity": "1",
    "flow": "bid-first"
  }' \
  "${BASE_URL}/agent/market/order"
```

Response (example):

```json
{
  "status": "OK",
  "event_id": "f4b27...",
  "kind": 1,
  "market": "MS-02",
  "side": "bid",
  "asset": "riddle.answer",
  "price_sats": 21,
  "quantity": "1",
  "order_id": "a1b2c3d4e5f6a7b8",
  "content": "BUY 1 riddle.answer @ 21 sats",
  "tags": [
    ["mkt","MS-02"],
    ["side","bid"],
    ["asset","riddle.answer"],
    ["qty","1"],
    ["px","21"],
    ["ord","a1b2c3d4e5f6a7b8"],
    ["flow","bid-first"]
  ],
  "relays": ["wss://relay.getsafebox.app"],
  "timestamp": 1770000000
}
```

### `POST /agent/market/ms02/construct_ask`

Constructs a deterministic MS-02 ask payload for the generic entitlement market using the current implementation profile.

Request fields:

- preferred:
  - `wrapper_ref` (required)
  - `wrapper_scheme` (optional, default `nostr_keypair_v1`)
  - `wrapper_commitment` (required)
  - `fulfillment_mode` (optional, default `provider_resolved_v1`)
  - `sealed_delivery_alg` (required when `fulfillment_mode=buyer_decryptable_v1`)
  - `encrypted_entitlement` (required when `fulfillment_mode=buyer_decryptable_v1`)
- `price_sats` (required)
- `expiry` (required)
- `content_format` (optional, default `yaml`)
Note:

- In `MS-02`, this helper should be interpreted as constructing an ask for the first entitlement profile, not as defining the market model itself.

### `POST /agent/market/ms02/publish_ask`

Publishes a previously constructed MS-02 ask to Nostr.

Request fields:

- `content` (required): the `content`, `content_yaml`, or `content_plain` returned by `construct_ask`
- `tags` (required): the exact `tags` array returned by `construct_ask`
- `kind` (optional, default `1`)
- `relays` (optional)

Behavior:

- publishes the ask as a Nostr event using the supplied content and tags without recomputing order data
- defaults to kind `1` publication
- allows a different kind to be specified explicitly

Response includes:

- `event_id`
- `kind`
- `content`
- `tags`
- `relays`
- `ask_id` (extracted from the published tags when present)
- `timestamp`

### `POST /agent/market/ms02/generate_wrapper`

Generates or normalizes the Nostr-native MS-02 trading wrapper profile.

Request:

```json
{
  "nsec": "nsec1..."
}
```

Behavior:

- if `nsec` is omitted, the server generates a fresh wrapper
- if `nsec` is provided, the server returns the normalized wrapper artifacts for that key

Response includes:

- `wrapper_scheme`
- `wrapper_ref`
- `wrapper_secret_nsec`
- `wrapper_commitment_hint`
- `hash_alg`
- `timestamp`

Note:

- `wrapper_secret_nsec` is the delivery encoding of the underlying wrapper secret material
- the returned `wrapper_commitment_hint` is the raw-secret-only hint derived from the wrapper key, not the full MS-02 wrapper commitment over entitlement material

### `POST /agent/market/ms02/derive_wrapper_commitment`

Derives the full MS-02 `wrapper_commitment` from:

- the wrapper secret
- `entitlement_code`
- `entitlement_secret`

Request:

```json
{
  "wrapper_scheme": "nostr_keypair_v1",
  "nsec": "nsec1...",
  "entitlement_code": "PROMO-2026-ALPHA",
  "entitlement_secret": "x9K...high-entropy-secret...",
  "hash_alg": "sha256"
}
```

Response includes:

- `wrapper_scheme`
- `wrapper_ref`
- `wrapper_commitment`
- `commitment_payload_jcs`
- `hash_alg`
- `timestamp`

### `POST /agent/market/ms02/generate_entitlement`

Generates or normalizes the provider-native entitlement material used as input to the MS-02 trading wrapper flow.

Request:

```json
{
  "entitlement_code": "OPTIONAL-CODE",
  "entitlement_secret": "OPTIONAL-SECRET"
}
```

Behavior:

- if both values are omitted, the server returns a generated test entitlement
- if one value is omitted, only the missing value is generated
- if values are provided, the server returns the normalized values unchanged

Response includes:

- `entitlement_code`
- `entitlement_secret`
- `generated_test_entitlement`
- `generated_code`
- `generated_secret`
- `timestamp`

### `POST /agent/market/secret_hash/derive`

Derives a canonical market secret hash from stable input fields using the server's current market-hash implementation.

Use this when agents need deterministic secret-hash generation without reimplementing the hashing convention locally.

Response includes:

- `status`
- `secret_hash`
- `hash_alg`
- `timestamp`

### `POST /agent/market/secret_hash/verify`

Verifies that a provided input set recomputes to a given canonical `secret_hash`.

Use this to confirm that market commitment material still matches the published hash before settlement, clearing, or redemption actions.

Response includes:

- `status`
- `valid`
- `hash_alg`
- `timestamp`

### `POST /agent/secure_dm`

Sends a secure direct message from the authenticated Safebox wallet to a recipient.

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

Payment reliability note:

- Payment endpoints are REQUIRED to follow the safeguards in:
  - [Payment Error Handling and Resilience Requirements](./PAYMENT-ERROR-HANDLING-AND-RESILIENCE.md)
- This includes proof-safety preflight, non-destructive mutation guards, explicit uncertain-state handling, and bounded timeout/retry behavior.

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
- `docs/specs/PAYMENT-ERROR-HANDLING-AND-RESILIENCE.md`
