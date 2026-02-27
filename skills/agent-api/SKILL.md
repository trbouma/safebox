# Agent API Skill

## Purpose

Use this skill when an autonomous agent needs to operate a Safebox wallet through the header-authenticated Agent API (no browser cookies, no interactive UI).

Primary outcomes:

- Onboard a wallet from invite code
- Read wallet info and balance
- Read transaction history
- Create and pay Lightning invoices
- Pay Lightning addresses directly
- Issue and accept Cashu ecash tokens
- Create recipient-first offer QR payloads so humans can send grants by scanning agent QR

## Inputs

Required:

- `base_url` (example: `https://skills.example.com`)

Conditional:

- `invite_code` for onboarding
- `access_key` for authenticated wallet actions
- `invoice` string for pay flow
- `lightning_address` and `amount_sats` for direct LN-address pay flow
- `amount` (sat integer) for create/issue flows
- `ecash_token` for accept flow

## Auth Model

- Authenticated calls require header: `X-Access-Key: <access_key>`
- Onboarding does not require `X-Access-Key`; it returns new credentials

## Canonical Endpoints

- `POST /agent/onboard`
- `GET /agent/info`
- `GET /agent/balance`
- `GET /agent/tx_history`
- `GET /agent/supported_currencies`
- `POST /agent/create_invoice`
- `GET /agent/invoice_status/{quote}`
- `POST /agent/pay_invoice`
- `POST /agent/pay_lightning_address`
- `POST /agent/issue_ecash`
- `POST /agent/accept_ecash`
- `POST /agent/offers/receive/create`
- `POST /agent/offers/create`
- `GET /agent/offers/{offer_id}/status`
- `POST /agent/offers/{offer_id}/capture`
- `POST /agent/offers/{offer_id}/send`
- `GET /agent/offers/{offer_id}/delivery`

## Execution Recipes

### 1) Onboard Wallet

1. Call `POST /agent/onboard` with `invite_code`.
2. Persist returned:
   - `wallet.access_key`
   - `wallet.nsec`
   - `wallet.seed_phrase`
   - `wallet.emergency_code`
3. Treat response as sensitive secret material.

Expected response includes:

- `wallet.handle`, `wallet.npub`, `wallet.home_relay`
- `session.access_token` (optional for external systems; agent calls should still use `X-Access-Key`)

### 2) Read Wallet State

1. Call `GET /agent/info` with `X-Access-Key`.
   - Includes `lightning_address` derived from request host.
2. Call `GET /agent/balance` for lightweight polling or confirmation.
3. Call `GET /agent/tx_history` for recent transaction audit context.

### 3) Create Invoice (Receive Payment)

1. Call `POST /agent/create_invoice` with sat amount and optional comment.
2. Return invoice immediately to payer.
3. Use returned `quote` and `status_path` to monitor settlement:
   - poll `GET /agent/invoice_status/{quote}`
   - terminal state is `quote_status: PAID`
4. Optionally confirm final wallet state with `GET /agent/balance` or `GET /agent/tx_history`.

### Currency Preflight (Before Address Payments)

1. Call `GET /agent/supported_currencies`.
2. Confirm requested currency appears with `available=true`.
3. Prefer `SAT` if rate metadata is unavailable for a fiat code.
4. Then call `POST /agent/pay_lightning_address`.

### 4) Pay Invoice

1. Call `POST /agent/pay_invoice` with BOLT11 invoice.
2. Check `status == OK`.
3. Use returned `balance` as post-payment state; optionally verify with `GET /agent/balance`.

### 5) Issue Ecash

1. Call `POST /agent/issue_ecash` with sat amount.
2. Capture returned `ecash_token`.
3. Treat token as bearer value until redeemed.

### 6) Pay Lightning Address

1. Call `POST /agent/pay_lightning_address` with:
   - `lightning_address` (for example `alice@example.com`)
   - either `amount_sats` (integer sats) OR `amount` + `currency` (floating-point amount in selected currency)
   - optional `comment`, `tendered_amount`, `tendered_currency`
2. Server performs LNURL resolution and payment using wallet core logic.
3. Verify `status == OK` and review `fees_paid`.
4. Use returned `balance` as post-payment state; optionally confirm with `GET /agent/balance`.

Why prefer this over manual LNURL flow:

- avoids client-side LNURL fetch/parse bugs
- avoids millisat conversion errors
- gives consistent behavior across LN-address providers
- centralizes error handling for unresolved/invalid addresses

### 7) Accept Ecash

1. Call `POST /agent/accept_ecash` with `ecash_token`.
2. Verify success and `accepted_amount`.
3. Confirm final wallet state via `GET /agent/balance`.

### 8) Recipient-First Offer Request (Agent Shows QR)

Use this flow when a human Safebox user will send a grant to the agent wallet by scanning a QR shown by the agent.

1. Call `POST /agent/offers/receive/create` with:
   - optional `ttl_seconds` and `compact_qr` (default `true`)
   - optional `grant_kind` and `grant_name` metadata (not required for handshake)
2. Display `qr_text` (or `qr_image_url`) to the human sender.
3. Sender scans QR from Safebox offer UI.
4. Sender transmits grant through existing offer flow.

Expected response includes:

- `intent.intent_id`, `intent.expires_at`
- `recipient.recipient_nauth`
- `qr_payload`, `qr_text`, `qr_image_url`

Field usage:

- Agent management fields: `status`, `intent`, and `recipient`.
- Human scan fields: `qr_text` (raw `recipient_nauth`) or `qr_image_url`.
- Structured optional context: `qr_payload` (for debugging/advanced clients).

Protocol note:

- Recipient-side nauth uses `scope=offer_request`.
- Scanner routing is expected to detect `offer_request` and redirect into records offer flow instead of generic accept flow.

### Copy/Paste Quickstart For OpenClaw

```bash
BASE_URL="https://skills.example.com"
API_KEY="your-wallet-access-key"

curl -sS -X POST \
  -H "X-Access-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "ttl_seconds": 120,
    "compact_qr": true
  }' \
  "${BASE_URL}/agent/offers/receive/create"
```

Use returned `qr_text` (raw `recipient_nauth`) as the QR content the human scans.

Compact behavior:

- `compact_qr=true` (default): `qr_text` stays raw `recipient_nauth`; structured metadata is available in `qr_payload`.
- `compact_qr=false`: QR includes explicit auth/transmittal relay metadata and KEM public metadata.
- Backward compatibility: `compact` is accepted as an alias for older clients.

### 9) Sender-Side Offer Dispatch Lifecycle

Use this flow when the agent is the sender and needs explicit dispatch states.

1. Create offer:
   - `POST /agent/offers/create` with `grant_kind`, `grant_name`
2. Wait for recipient auth:
   - `GET /agent/offers/{offer_id}/status?wait_seconds=30`
3. If needed, capture recipient nauth manually:
   - `POST /agent/offers/{offer_id}/capture`
4. Send grant:
   - `POST /agent/offers/{offer_id}/send`
5. Check dispatch result:
   - `GET /agent/offers/{offer_id}/delivery`

Status semantics:

- `offer_status`: `WAITING_RECIPIENT`, `RECIPIENT_READY`, `SENDING`, `SENT`, `FAILED`
- `delivery_status`: `PENDING`, `DISPATCHED`, `FAILED`

Note:

- `delivery_status=DISPATCHED` means sender-side dispatch completed.
- It does not prove recipient-side application-level receipt acknowledgment.

### Sender Flow Quick Test (Copy/Paste)

```bash
BASE_URL="https://skills.example.com"
API_KEY="your-wallet-access-key"
GRANT_KIND=34104
GRANT_NAME="Passport"
RECIPIENT_NAUTH="nauth1..."   # optional if using manual capture
```

1. Create offer:

```bash
OFFER_ID=$(curl -sS -X POST \
  -H "X-Access-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_kind\": ${GRANT_KIND},
    \"grant_name\": \"${GRANT_NAME}\",
    \"compact\": true
  }" \
  "${BASE_URL}/agent/offers/create" | jq -r '.offer.offer_id')
echo "OFFER_ID=${OFFER_ID}"
```

2. Check recipient readiness (or wait):

```bash
curl -sS \
  -H "X-Access-Key: ${API_KEY}" \
  "${BASE_URL}/agent/offers/${OFFER_ID}/status?wait_seconds=30"
```

3. Optional manual recipient capture:

```bash
curl -sS -X POST \
  -H "X-Access-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"recipient_nauth\":\"${RECIPIENT_NAUTH}\"}" \
  "${BASE_URL}/agent/offers/${OFFER_ID}/capture"
```

4. Send offer/grant:

```bash
curl -sS -X POST \
  -H "X-Access-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{}' \
  "${BASE_URL}/agent/offers/${OFFER_ID}/send"
```

5. Confirm dispatch lifecycle:

```bash
curl -sS \
  -H "X-Access-Key: ${API_KEY}" \
  "${BASE_URL}/agent/offers/${OFFER_ID}/delivery?wait_seconds=10"
```

Expected terminal state:

- `offer_status` should be `SENT` (or `FAILED`)
- `delivery_status` should be `DISPATCHED` (or `FAILED`)

## Error Handling

- `400`: invalid payload or business-rule failure (insufficient funds, malformed token, invoice failure)
- `401`: missing/invalid `X-Access-Key`
- `403`: invalid invite code (onboarding)
- `409`: onboarding registration conflict; retry safely
- `500`: transient server/wallet load error; retry with backoff

Retry guidance:

- Use bounded exponential backoff for `500` and network failures.
- Do not blindly retry non-idempotent payment operations without reconciliation checks.
- For invoice receive flows, prefer `GET /agent/invoice_status/{quote}` before concluding failure.
- For recipient-first offer requests, regenerate a fresh QR if `expires_at` has passed.

## Guardrails

- Never log `access_key`, `nsec`, `seed_phrase`, `ecash_token`, or full invoices in plaintext logs.
- Always use HTTPS in production.
- Store recovery materials separately from operational API credentials.
- Prefer explicit status checks over optimistic assumptions.

## References

- `/Users/trbouma/projects/safebox-2/docs/specs/AGENT-API.md`
- `/Users/trbouma/projects/safebox-2/docs/specs/AGENT-FLOWS.md`
- `/Users/trbouma/projects/safebox-2/app/routers/agent.py`
