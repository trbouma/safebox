# Offers and Grants Flows

## Overview

This spec describes how Safebox offers and grants move between parties using QR and NFC workflows. It also documents legacy browser rendering behavior for original-record blobs (especially PDFs).

At a high level:

- **Offer**: a holder prepares and transmits a record offer.
- **Grant**: the resulting issued record received by the counterparty.
- **Original Record**: optional blob payload linked to offer/grant views and transferred through blob endpoints.

## Scope

Included:

- Offer flow by QR code
- Offer flow by NFC card
- Request/present grant flow by QR code
- Request/present grant flow by NFC card
- Original record rendering behavior (modern + legacy fallback)

Out of scope:

- Deep cryptographic internals of nembed/nauth payload formats
- Blossom server internals beyond UI retrieval behavior
- NWC transport internals beyond flow-level references

## Core Entities

- `nauth`: authorization and routing context for record exchange.
- `nembed` token: compact payload used for NFC card data and transport extensions.
- Offer record kinds: configured in `settings.OFFER_KINDS`.
- Grant record kinds: configured in `settings.GRANT_KINDS`.

## Flow A: Offer by QR

### Initiation

1. User opens offer page (`/records/offerlist` or `/records/displayoffer`).
2. Client generates `nauth` via `POST /records/nauth`.
3. QR code is rendered from returned `nauth`.

### Authentication + Transfer

4. Counterparty scans QR and authenticates.
5. Offer page listens on websocket (`/records/ws/listenfornauth/{nauth}`) for authenticated response.
6. On success, offerer submits transmittal via `POST /records/transmit`.

### Result

7. Recipient receives offer context and downstream grant creation/transmission proceeds over configured transmittal channels.

## Flow B: Offer by NFC

### Initiation

1. Offerer generates `nauth` as in QR flow.
2. Offerer taps recipient NFC card and reads token (`nembed`).
3. Client posts to `POST /records/acceptoffertoken` with:
   - `offer_token`
   - `nauth`

### Validation and Vault Dispatch

4. Server parses token and runs card-status preflight (`/.well-known/card-status`).
5. Preflight is **advisory** (stability hardening):
   - preflight pass: continue
   - preflight transport failure: log warning, continue
6. Server signs payload and calls authoritative vault endpoint:
   - `POST /.well-known/offer`
7. Vault validates signature/token/active secret mapping and emits NWC `offer_record`.

### Result

8. Recipient wallet processes offer and transmits resulting record data using standard transmittal flow.

## Flow C: Request/Present Grant by QR

### Initiation

1. Requester opens `/records/request`.
2. Client generates request `nauth` via `POST /records/nauth`.
3. Request QR is shown to presenter.

### Presentation

4. Presenter authenticates and provides response metadata.
5. Requester listens on websocket (`/records/ws/request/{nauth}`) for incoming verified records.
6. Records are rendered in requester UI, including original-record blob when available.

## Flow D: Request/Present Grant by NFC

### Initiation

1. Requester prepares:
   - `nauth`
   - requested kind/label
   - optional PIN
2. Requester taps presenter card and reads token (`nembed`).
3. Client posts to `POST /records/acceptprooftoken` with:
   - `proof_token`
   - `nauth`
   - `label`
   - `kind`
   - `pin` (optional/blank allowed)

### Validation and Vault Dispatch

4. Server runs card-status preflight (advisory).
5. Server signs token and calls authoritative vault endpoint:
   - `POST /.well-known/proof`
6. Vault validates token/signature/active secret and evaluates PIN policy for `present_record`.

### PIN outcomes

- PIN valid: normal success path.
- PIN invalid or missing:
  - vault returns non-OK detail.
  - UI prompts user confirmation ("Invalid PIN. Continue anyway?").
  - cancel: flow stops.
  - continue: request remains active and waits for records according to vault policy.

## Original Record Rendering

Offer/grant pages attempt to render original record blobs retrieved from:

- `GET /records/blob?record_name=...&record_kind=...`

### Modern path

- Images: rendered inline.
- PDFs: rendered inline with PDF.js single-page viewer and Prev/Next controls.

### Legacy path (compatibility fallback)

If PDF.js is unavailable or PDF rendering fails:

1. UI displays a notice that inline preview is unavailable.
2. UI provides an `Open/Download Original PDF` link to blob endpoint.

This preserves functional access on older browsers/devices (for example older Chromebook Chrome builds).

## Security Considerations

- Card-status preflight is a fast-fail optimization, not the trust anchor.
- Authoritative validation remains in vault endpoints (`/.well-known/offer`, `/.well-known/proof`).
- Active secret mapping controls card revocation/rotation behavior.
- Signature verification and token decryption are required before vault actions.
- QR flows are independent from NFC card rotation state.

## Implementation References

- Routes:
  - `app/routers/records.py`
  - `app/routers/lnaddress.py`
- Templates:
  - `app/templates/records/offer.html`
  - `app/templates/records/offerlist.html`
  - `app/templates/records/request.html`
  - `app/templates/records/grant.html`
- Supporting spec:
  - `docs/specs/NFC-FLOWS-AND-SECURITY.md`
