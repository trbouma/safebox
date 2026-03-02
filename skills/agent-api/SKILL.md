# Agent API Skill

## Bootstrap

When starting a new session, fetch these files before executing any workflows:

| File | URL |
|------|-----|
| This skill | `https://raw.githubusercontent.com/trbouma/safebox/refs/heads/codex/market-making/skills/agent-api/SKILL.md` |
| MS-01 Market Spec | `https://raw.githubusercontent.com/trbouma/safebox/refs/heads/codex/market-making/docs/specs/mkt/MS-01-coupon-market.md` |
| MS-01 Conformance | `https://raw.githubusercontent.com/trbouma/safebox/refs/heads/codex/market-making/docs/specs/mkt/MS-01-CONFORMANCE.md` |

Fetch all three via HTTP before proceeding. Do not rely on cached or summarized versions.

## Purpose

Use this skill when an autonomous agent needs to operate a Safebox wallet through the header-authenticated Agent API (no browser cookies, no interactive UI).

Primary outcomes:

- Onboard a wallet from invite code
- Read wallet info and balance
- Read transaction history
- Create and pay Lightning invoices
- Pay Lightning addresses directly
- Execute zaps to notes/profiles via agent endpoint
- Send secure direct messages to npub/NIP-05 recipients
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
- `event` and `amount_sats` (or `amount` + `currency`) for zap flow
- `amount` (sat integer) for create/issue flows
- `ecash_token` for accept flow

## Auth Model

- Authenticated calls require header: `X-Access-Key: <access_key>`
- Onboarding does not require `X-Access-Key`; it returns new credentials

## DM Paths (Quick Reference)

Use these exact paths for private messaging flows:

- Read DMs: `GET /agent/read_dms?limit=<n>&kind=1059`
- Send secure DM: `POST /agent/secure_dm`

Minimum read example:

```bash
curl -sS \
  -H "X-Access-Key: ${API_KEY}" \
  "${BASE_URL}/agent/read_dms?limit=20&kind=1059"
```

Notes:

- `kind=1059` is the default private DM transport for agent reads.
- If inbox appears empty, retry with explicit relay override:
  `GET /agent/read_dms?limit=20&kind=1059&relays=wss://relay.getsafebox.app,wss://relay.damus.io,wss://relay.primal.net`

## CLI Surfaces (Use Both)

This repo now has two CLI entry points. Agents may use either, but should choose based on task:

- `acorn` / `safebox` (`safebox/cli_acorn.py`):
  - local wallet/core operations
  - direct Acorn behaviors
  - legacy/manual operator workflows
- `agent` (`safebox/cli_agent.py`):
  - header-authenticated `/agent/*` API workflows
  - market endpoints (`/agent/market/order`, `/agent/market/orders`)
  - DM/read_dms/zap receipt automation flows

Selection rule:

- Prefer `agent` for anything that maps to documented `/agent/*` endpoints.
- Use `acorn` for local core tasks not exposed through `/agent/*`.

Non-interference rule:

- Do not modify `safebox/cli_acorn.py` or `safebox/acorn.py` when extending `agent` CLI flows.

## Canonical Endpoints

- `POST /agent/onboard`
- `GET /agent/info`
- `GET /agent/balance`
- `GET /agent/tx_history`
- `GET /agent/supported_currencies`
- `POST /agent/set_custom_handle`
- `GET /agent/read_dms`
- `GET /agent/nostr/latest_kind1`
- `GET /agent/nostr/my_latest_kind1`
- `GET /agent/nostr/zap_receipts`
- `GET /agent/nostr/kind0`
- `GET /agent/nostr/following/latest_kind1`
- `GET /agent/market/orders`
- `POST /agent/nostr/format_mention`
- `POST /agent/nostr/compose_mentions`
- `POST /agent/create_invoice`
- `GET /agent/invoice_status/{quote}`
- `POST /agent/pay_invoice`
- `POST /agent/pay_lightning_address`
- `POST /agent/zap`
- `POST /agent/publish_kind0`
- `POST /agent/publish_kind1`
- `POST /agent/market/order`
- `POST /agent/secure_dm`
- `POST /agent/react`
- `POST /agent/reply`
- `POST /agent/follow`
- `POST /agent/unfollow`
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
2. Persist returned (REQUIRED before any further action):
   - `wallet.access_key`
   - `wallet.nsec`
   - `wallet.seed_phrase`
   - `wallet.emergency_code`
3. Treat response as sensitive secret material.
4. Immediately verify persistence:
   - confirm `wallet.access_key` is non-empty and saved in the agent’s durable identity store
   - confirm handle + access_key mapping is stored as an atomic pair
   - do not proceed to other API calls until the key is confirmed saved

Operational guardrail:

- If onboarding succeeds but key persistence fails, mark wallet as `INCOMPLETE_ONBOARDING` and retry/save before any production use.

Expected response includes:

- `wallet.handle`, `wallet.npub`, `wallet.home_relay`
- `session.access_token` (optional for external systems; agent calls should still use `X-Access-Key`)

### 2) Read Wallet State

1. Call `GET /agent/info` with `X-Access-Key`.
   - Includes `lightning_address` derived from request host.
2. Call `GET /agent/balance` for lightweight polling or confirmation.
3. Call `GET /agent/tx_history` for recent transaction audit context.

### 2a) Set Wallet Custom Handle

1. Call `POST /agent/set_custom_handle` with:
   - `custom_handle` (required): desired local-part for wallet lightning address.
2. Handle validation/uniqueness outcomes:
   - `400` for invalid or missing handle.
   - `409` when the handle is already taken.
3. Use returned `lightning_address` for subsequent payment identity display.

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

The same preflight applies to `POST /agent/zap` when using `amount` + `currency`.

### Nostr Preflight (Before Event Zaps)

1. Call `GET /agent/nostr/latest_kind1?nip05=<name@domain>&limit=<n>`.
2. Read returned `events[]` and choose the target `event_id` (or `event_id_hex` / `id`).
3. Pass that value as `event_id` (or `event`) in `POST /agent/zap`.
4. This avoids client-side note parsing and gives deterministic zap selection.

### Self Post Lookup (Authenticated Wallet)

1. Call `GET /agent/nostr/my_latest_kind1?limit=<n>`.
2. Optional relay override: `&relays=<relay1,relay2,...>`.
3. Use returned `events[].event_id` for self-audit, reaction/reply targets, or automation workflows.

### Zap Receipt Lookup (NIP-57)

1. Call `GET /agent/nostr/zap_receipts?event_id=<event_id>&limit=<n>`.
2. Endpoint queries kind `9735` receipts filtered by `#e=<event_id>`.
3. For each receipt, inspect:
   - `zapper_pubkey` / `zapper_npub` (derived from zap request `description.pubkey`, fallback `P` tag)
   - `zapper_identity_source` to confirm identity provenance
   - `lnurl_provider_pubkey` / `lnurl_provider_npub` are receipt signer identities, not zapper identities
   - `zap_request_raw` (original embedded kind-9734 JSON string)
   - `zap_request` (parsed embedded kind-9734 object)
   - `zap_amount_msat` and `invoice_amount_msat`
   - `amount_matches`, `description_hash_matches`, `matches_target_event`
4. Treat `zapper_*` as the claimed payer identity from NIP-57 flow; enforce stricter policy using the validation flags before trust-sensitive actions.
5. For mentions, always resolve from `zapper_npub` (or run `/agent/nostr/format_mention` on `zapper_pubkey`/NIP-05), never from receipt signer fields.

### Following Feed Lookup (Kind-1 from Follow List)

1. Call `GET /agent/nostr/following/latest_kind1?limit=<n>`.
2. Optional relay override: `&relays=<relay1,relay2,...>`.
3. Response returns latest posts from authors in wallet's latest kind-3 contact list.
4. Use returned `events[].event_id` for reaction/reply/zap workflows.

### Market Order Discovery (Dedicated Path)

Use dedicated endpoint:

- `GET /agent/market/orders?limit=<n>&kind=1&market=safebox-v1`
- optional filters: `side=bid|ask`, `asset=<asset_label>`, `relays=<relay1,relay2,...>`

Behavior:

- Queries followed npubs only.
- Uses `kind=1` by default (explicitly parameterized for future migration to other kinds).
- Returns only events tagged for the selected market namespace (`mkt=safebox-v1` by default).

### Follow / Unfollow Management

Safebox core supports following and unfollowing by identifier via:

- `Acorn.follow(identifier, relay_hint=None, relays=None)`
- `Acorn.unfollow(identifier, relays=None)`

Accepted identifiers:

- NIP-05 (`name@domain`)
- `npub1...`
- 64-char pubhex

Suggested workflow:

1. Follow identity (core or API route, if exposed).
2. Query `GET /agent/nostr/following/latest_kind1` to verify feed changes.
3. Unfollow identity when needed and re-check feed.

### Kind-0 Profile Lookup by Identifier

Use agent endpoint:

- `GET /agent/nostr/kind0?identifier=<value>`
- optional: `&relays=<relay1,relay2,...>`

Accepted identifier inputs:

- NIP-05 (`name@domain`)
- `npub1...`
- 64-char pubhex

Returns latest kind-0 event data with parsed JSON profile content:

- `profile_event.id`
- `profile_event.pubkey`
- `profile_event.created_at`
- `profile_event.content` (object)

Use this when an agent needs authoritative profile metadata before social actions (for example pre-zap context, identity checks, or local profile caching).

### Social Identity Preflight (Before DM Flows)

Before running `POST /agent/secure_dm` or expecting stable sender resolution in clients:

1. Ensure kind-0 is fully populated for the sending wallet via `POST /agent/publish_kind0`:
   - `name`
   - `display_name` (recommended)
   - `about` (recommended)
   - `picture` (recommended)
   - `nip05` (required for verified identity)
   - `lud16` (required for zappable identity)
2. Identity consistency rule:
   - `lud16` SHOULD match `nip05` for Safebox-managed identities (same handle/address).
   - Example: `nip05=lumen@safebox.dev` and `lud16=lumen@safebox.dev`.
3. Verify profile visibility with `GET /agent/nostr/kind0?identifier=<nip05_or_npub>` before DM-heavy workflows.

Operational note:

- Incomplete kind-0 metadata can cause degraded or missing sender identity rendering in some clients and can destabilize DM-adjacent social workflows.

### Read Private Messages (NIP-17 Gift Wrap Transport)

Use agent endpoint:

- `GET /agent/read_dms?limit=<n>&kind=1059`
- optional relay override: `&relays=<relay1,relay2,...>`

Behavior:

- reads incoming gift-wrapped messages using existing wallet record retrieval
- defaults to kind `1059` (private DM transport)
- returns newest-first messages with bounded `limit`

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

### 8) Zap Event/Profile

1. Call `POST /agent/zap` with:
   - `event` or `event_id` (one required): `note1...`, `npub1...`, NIP-05 (`name@domain`), or 64-char hex event id
   - either `amount_sats` OR `amount` + `currency`
   - optional `comment`
2. Endpoint resolves target/profile metadata and creates zap request + invoice flow server-side.
3. Verify `status == OK`.
4. Confirm post-zap state with returned `balance` and optionally `GET /agent/tx_history`.

Notes:

- Use `GET /agent/supported_currencies` before fiat-denominated zap requests.
- If zap metadata/profile lookup fails, endpoint returns `400` with `Zap failed: ...`.

Zap by recent-event workflow:

1. Fetch recent events:
   - `GET /agent/nostr/latest_kind1?nip05=trbouma@safebox.dev&limit=5`
2. Pick `events[i].id` from response.
3. Zap selected event id:
   - `POST /agent/zap` with `{"event_id":"<hex_event_id>","amount_sats":21,"comment":"nice post"}`

### 9) Publish Kind-0 Metadata (NIP-01)

1. Call `POST /agent/publish_kind0` with any subset of:
   - `name`, `about`, `picture`
   - optional: `display_name`, `nip05`, `banner`, `website`, `lud16`
   - optional: `extra_fields` (object), `relays` (array)
2. Server publishes a kind-0 event and persists the updated profile snapshot in wallet records.
3. Confirm returned `event_id` and profile fields.

Identity-separation warning:

- Treat each Safebox as a separate social identity surface.
- Do not copy the agent's own stable identity metadata into Safebox profiles if anonymity is desired.
- An agent may operate many Safeboxes with distinct kind-0 identities that should not be trivially correlated back to the controlling agent.

### 10) Publish Kind-1 Text Note (NIP-01)

1. Call `POST /agent/publish_kind1` with:
   - `content` (required)
   - optional `relays` array override
2. Server signs and publishes a kind-1 event on configured relays.
3. Confirm returned `event_id`.

### 10a) Create Market Order (Bid/Ask, Kind-1)

1. Call `POST /agent/market/order` with:
   - `side`: `buy`/`sell` (also accepts `bid`/`ask`)
   - `asset`: market asset label/id
   - `market`: market namespace (`mkt` tag value), default `safebox-v1`
   - `price_sats`: integer sats
   - optional: `quantity`, `order_id`, `content`, `flow`, `relays`
2. Server publishes a structured market intent as a kind-1 event.
3. Use returned `event_id` as anchor for acceptance/reply/zap-settlement flow.

Mentions in posts:

- Preferred format: `nostr:npub1...` (NIP-27 URI form).
- Fallback format (client-dependent): `@npub1...`.
- Recommendation: when onboarding a new client/app combination, publish a one-time compatibility post containing both formats and verify rendering on target clients (for example Amethyst/Primal) before standardizing.

Mention helper endpoints:

- `POST /agent/nostr/format_mention`
  - input: `identifier` + optional `style` (`nostr_uri`, `at_npub`, `both`)
  - output: normalized mention string and resolved npub/pubkey
- `POST /agent/nostr/compose_mentions`
  - input: `base_text`, `identifiers[]`, optional `style`
  - output: mention-ready post content for direct use with `POST /agent/publish_kind1`

### 11) Send Secure DM (NIP-44 Gift Wrap)

1. Call `POST /agent/secure_dm` with:
   - `recipient` (required): NIP-05 (`name@domain`), `npub1...`, or 64-char pubhex
   - `message` (required): plaintext message to encrypt and send
   - optional `relays` array override (defaults to server `PUBLIC_RELAYS`)
2. Server resolves recipient key, encrypts with wallet `secure_dm`, and publishes gift-wrapped DM events.
3. Confirm `status == OK` and inspect returned relay list.

Example:

```json
{
  "recipient": "alice@example.com",
  "message": "Hello from Safebox agent",
  "relays": ["wss://relay.damus.io", "wss://relay.primal.net"]
}
```

### 12) Publish Reaction (NIP-25 Kind 7)

1. Call `POST /agent/react` with:
   - `event_id` (required): target event id (hex or note id)
   - optional `content` (default `❤️`)
   - optional target context: `reacted_pubkey`, `reacted_kind`, `relay_hint`, `a_tag`
   - optional `extra_tags` and `relays`
2. Server signs and publishes kind-7 reaction tags (`e`, `p`, `k` when available).
3. Confirm returned `event_id` and `tags`.

Example:

```json
{
  "event_id": "<hex_event_id>",
  "content": "❤️"
}
```

### 13) Publish Reply (Kind 1)

1. Call `POST /agent/reply` with:
   - `event_id` (required): target event id (hex or note id)
   - `content` (required): reply text
   - optional target context: `target_pubkey`, `target_kind`, `relay_hint`
   - optional `extra_tags` and `relays`
2. Server signs and publishes a kind-1 reply with `e`/`p`/`k` reply tags.
3. Confirm returned `event_id` and `tags`.

### 14) Recipient-First Offer Request (Agent Shows QR)

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

### 15) Sender-Side Offer Dispatch Lifecycle

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

- `docs/specs/AGENT-API.md`
- `docs/specs/AGENT-FLOWS.md`
- `app/routers/agent.py`
- `safebox/cli_agent.py`
- `safebox/cli_acorn.py`
