# Agent API Skill

## Purpose

Use this skill when an autonomous agent needs to operate a Safebox wallet through the header-authenticated Agent API (no browser cookies, no interactive UI).

Primary outcomes:

- Onboard a wallet from invite code
- Read wallet info and balance
- Create and pay Lightning invoices
- Issue and accept Cashu ecash tokens

## Inputs

Required:

- `base_url` (example: `https://skills.example.com`)

Conditional:

- `invite_code` for onboarding
- `access_key` for authenticated wallet actions
- `invoice` string for pay flow
- `amount` (sat integer) for create/issue flows
- `ecash_token` for accept flow

## Auth Model

- Authenticated calls require header: `X-Access-Key: <access_key>`
- Onboarding does not require `X-Access-Key`; it returns new credentials

## Canonical Endpoints

- `POST /agent/onboard`
- `GET /agent/info`
- `GET /agent/balance`
- `POST /agent/create_invoice`
- `POST /agent/pay_invoice`
- `POST /agent/issue_ecash`
- `POST /agent/accept_ecash`

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
2. Call `GET /agent/balance` for lightweight polling or confirmation.

### 3) Create Invoice (Receive Payment)

1. Call `POST /agent/create_invoice` with sat amount and optional comment.
2. Return invoice immediately to payer.
3. Monitor settlement by polling `GET /agent/balance` or `GET /agent/info`.
   - Invoice settlement monitoring runs server-side asynchronously.

### 4) Pay Invoice

1. Call `POST /agent/pay_invoice` with BOLT11 invoice.
2. Check `status == OK`.
3. Use returned `balance` as post-payment state; optionally verify with `GET /agent/balance`.

### 5) Issue Ecash

1. Call `POST /agent/issue_ecash` with sat amount.
2. Capture returned `ecash_token`.
3. Treat token as bearer value until redeemed.

### 6) Accept Ecash

1. Call `POST /agent/accept_ecash` with `ecash_token`.
2. Verify success and `accepted_amount`.
3. Confirm final wallet state via `GET /agent/balance`.

## Error Handling

- `400`: invalid payload or business-rule failure (insufficient funds, malformed token, invoice failure)
- `401`: missing/invalid `X-Access-Key`
- `403`: invalid invite code (onboarding)
- `409`: onboarding registration conflict; retry safely
- `500`: transient server/wallet load error; retry with backoff

Retry guidance:

- Use bounded exponential backoff for `500` and network failures.
- Do not blindly retry non-idempotent payment operations without reconciliation checks.

## Guardrails

- Never log `access_key`, `nsec`, `seed_phrase`, `ecash_token`, or full invoices in plaintext logs.
- Always use HTTPS in production.
- Store recovery materials separately from operational API credentials.
- Prefer explicit status checks over optimistic assumptions.

## References

- `/Users/trbouma/projects/safebox-2/docs/specs/AGENT-API.md`
- `/Users/trbouma/projects/safebox-2/docs/specs/AGENT-FLOWS.md`
- `/Users/trbouma/projects/safebox-2/app/routers/agent.py`
