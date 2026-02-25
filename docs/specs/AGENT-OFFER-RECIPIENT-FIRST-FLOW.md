# Agent Offer Recipient-First Flow

## Overview

This spec defines a minimal recipient-first offer bootstrap for agents.

The recipient agent presents a QR code that contains only a `nauth` with `scope=offer_request` (plus optional lightweight envelope fields such as TTL/intent ID). The sender scans this QR from the existing offer UI and proceeds using normal offer context (selected grant/record on sender side).

PQC KEM material is exchanged through relay/auth steps, not embedded in QR.

## Scope

In scope:

- Generate recipient-first `nauth` with correct scope for scanner routing.
- Keep QR payload small and reliable.
- Route scanned `offer_request` into existing offer flow.
- Preserve all existing sender-first QR/NFC behavior.

Out of scope (for this phase):

- Full recipient intent lifecycle APIs (status/cancel).
- Embedding KEM in QR.
- Changing existing record transmission protocol.

## Flow Summary (Phase 1)

1. Recipient agent calls `POST /agent/offers/receive/create`.
2. API generates `recipient_nauth` with `scope=offer_request`.
3. Agent displays QR containing raw `recipient_nauth`.
4. Sender scans QR from existing Safebox offer page.
5. Scanner detects `scope=offer_request` and redirects into records offer flow.
6. Sender-side flow continues; grant/offer selection remains sender-context driven.

## API Contract

### `POST /agent/offers/receive/create`

Creates a recipient-side offer-request bootstrap for scanning.

Request:

```json
{
  "ttl_seconds": 120,
  "compact_qr": true
}
```

Request fields:

- `ttl_seconds` (int, optional, default `120`, min `30`, max `600`)
- `compact_qr` (bool, optional, default `true`)
- `compact` (bool, optional): backward-compatible alias for `compact_qr`
- `grant_kind` (int, optional metadata only)
- `grant_name` (string, optional metadata only)

Response `200`:

```json
{
  "status": "OK",
  "intent": {
    "intent_id": "rx_8fLkP2v1QmYz",
    "status": "WAITING_SEND",
    "created_at": 1772000000,
    "expires_at": 1772000120
  },
  "recipient": {
    "recipient_nauth": "nauth1..."
  },
  "qr_payload": {
    "v": 1,
    "mode": "recipient_first_offer",
    "intent_id": "rx_8fLkP2v1QmYz",
    "recipient_nauth": "nauth1...",
    "expires_at": 1772000120
  },
  "qr_text": "nauth1...",
  "qr_image_url": "https://skills.example.com/safebox/qr/nauth1..."
}
```

Errors:

- `400`: invalid TTL or payload shape.
- `401`: missing/invalid `X-Access-Key`.
- `429`: rate-limited.
- `500`: wallet/relay initialization error.

## Required `nauth` Semantics

The generated recipient nauth must have:

- `scope=offer_request`
- normal auth/transmittal fields as defined by existing `create_nauth` flow

No grant kind is required in nauth for this phase. Grant selection is determined by sender offer context after scan.

## QR Payload Rules

1. QR must be small enough for reliable scanning on older devices.
2. QR must include `recipient_nauth`.
3. QR should not include KEM public key.
4. `expires_at` is allowed and recommended for replay window control.
5. `qr_text` should be raw `recipient_nauth`; optional structured fields stay in `qr_payload`.

`compact_qr` modes:

1. `compact_qr=true` (default): QR includes minimal bootstrap fields only.
2. `compact_qr=false`: QR may include explicit defaults/metadata such as:
   - `auth_kind`
   - `auth_relays`
   - `transmittal_kind`
   - `transmittal_relays`
   - `kem_public_key`
   - `kemalg`

## KEM Exchange Strategy (Not QR)

KEM is delivered via relay/auth sequence:

1. Sender scans `offer_request` nauth.
2. Sender/recipient continue handshake via relay channels.
3. KEM public material is obtained through relay response/service channels.
4. Sender transmits record using relay-negotiated KEM context.

Reason:

- reduces QR size dramatically
- improves scanner reliability
- keeps cryptographic negotiation in dynamic secure channels

## Scanner Routing Rules

When scanner parses a `nauth`:

1. If `scope == "offer_request"`, route to records offer flow (not generic offer-accept flow).
2. Existing scope routing remains unchanged for all other scopes.

## Compatibility and Non-Breaking Rules

1. Existing sender-first offer QR flow remains unchanged.
2. Existing sender-first offer NFC flow remains unchanged.
3. Existing request/present flows remain unchanged.
4. New behavior activates only on `scope=offer_request`.

## Security Considerations

1. Use short TTL (`expires_at`) to constrain replay window.
2. Keep recipient private keys and KEM secret key server-side only.
3. Do not log full nauth or sensitive payloads at info/error level.

## Test Gates (Phase 1)

1. `POST /agent/offers/receive/create` returns `recipient_nauth` with `scope=offer_request`.
2. QR scan routes to records offer flow.
3. Existing `scope=offer:*` scanner behavior is unchanged.
4. Existing NFC offer/request regressions do not appear.

## Implementation References

- `app/routers/agent.py`
- `app/routers/scanner.py`
- `app/routers/records.py`
- `app/templates/records/offer.html`
- `app/templates/records/offerlist.html`
- `docs/specs/AGENT-API.md`
