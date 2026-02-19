# NFC Flows and Security

## Introduction

Safebox uses a software-defined NFC card model to provide near full wallet functionality on inexpensive commodity tags such as NTAG215. In practice, this means a user can carry a low-cost NFC card and still perform core wallet operations without requiring their phone at the moment of interaction.

With a provisioned card, Safebox supports card-mediated:

- Logging into an NFC-enabled web app session
- Sending payments
- Receiving/requesting payments
- Offering records
- Requesting/presenting records

This enables practical "card-only at point of interaction" usage for payments and record exchange, while Safebox services handle secure vault messaging, authorization, and settlement in the background.

Safebox also uses a self-issuance model. The holder issues their own cards from the wallet and controls lifecycle state through secret rotation:

- A user can issue multiple cards.
- Each issued card can have its own unique PIN.
- The user can rotate the active secret to revoke previously issued cards.
- Rotation invalidates any old card payloads still in circulation.

This gives users direct control to activate new cards and revoke any and all prior cards without relying on specialized secure hardware.

## Key Takeaways

- Safebox NFC works with inexpensive NTAG215 cards and similar commodity NFC tags.
- A provisioned card can drive payments and record exchange flows at the point of interaction.
- A cardholder can log into an NFC-enabled Safebox web app directly with the card.
- Card validity is controlled in software through an active secret mapping, not secure card hardware.
- Users can self-issue multiple cards and revoke all older cards by rotating the active secret.
- Multiple cards can be active at once, each with a distinct PIN, while sharing the current active secret set.
- QR flows remain independent and continue working even when NFC cards are rotated/revoked.

## Overview

This document defines how Safebox NFC works today for:

- Card issuance and rotation
- NFC login
- NFC payment flows (request/receive and send)
- NFC record flows (offer and request/present)

It also describes the active-secret security model and failure behavior.

## Core Security Model

Safebox uses an application-layer card token model:

1. A card payload contains an encrypted value `k` which decrypts to:
   - `nwc_secret:pin`
2. `nwc_secret` is looked up in `NWCSecret` to resolve the active target `npub`.
3. If no active mapping exists, the card is invalid.

### Single Active Secret per Safebox

Each Safebox has one active NWC secret mapping used for NFC card operations.

- Reusing cards:
  - Multiple physical cards can carry the same `nwc_secret`.
- Rotation:
  - Rotating creates a new `nwc_secret` mapping for that `npub`.
  - Previously issued cards with the old secret fail immediately.

### Cards Can Have Different PINs

The encrypted card payload includes `secret:pin`.
This means multiple cards can share the same active secret while using different PIN values.

- Secret identifies which wallet/card-set is valid.
- PIN is an additional per-card user gate.

## Issuance and Rotation

Holder endpoint:

- `GET /safebox/issuecard`

Behavior:

1. Fetch active `nwc_secret` for the safebox.
2. If rotate requested, generate/store a new `nwc_secret`.
3. Generate `secure_pin`.
4. Encrypt `"{nwc_secret}:{secure_pin}"` with service key (`SERVICE_NSEC`, NIP-44).
5. Build `nembed` token with:
   - `h` host binding
   - `k` encrypted payload
   - `a` default amount hint
   - `n` defaults metadata
6. User writes this `nembed` to one or more cards.

Operational result:

- No rotation: newly written cards remain compatible with existing active cards.
- Rotation: old cards are revoked by design.

## Card Validation and Fast-Fail

Public validation endpoint:

- `POST /.well-known/card-status`

Request must include signed token fields:

- `token`
- `pubkey`
- `sig`

Validation sequence:

1. Verify signature over token.
2. Decrypt token payload.
3. Resolve `nwc_secret` in active mapping table.
4. Return active status or reject.

Reject behavior:

- Rotated/revoked/unknown secret returns invalid-card response.
- NFC flows should stop immediately and show user-facing error.
- QR flows are not affected.

## NFC Login Flow

Endpoint:

- `POST /safebox/loginwithnfc`

Sequence:

1. Client submits NFC `nembed`.
2. Server parses token and validates host.
3. Server decrypts `k` and resolves `nwc_secret -> npub`.
4. If mapping exists, login proceeds and access token is issued.
5. If mapping does not exist, login fails (invalid/revoked card).

## NFC Payment Flows

### A. Request Payment (Receiver Reads Payer Card)

Client/API endpoint:

- `POST /safebox/requestnfcpayment`

Remote vault endpoint:

- `POST /.well-known/nfcvaultrequestpayment`

Flow:

1. Receiver taps payer NFC card and gets token.
2. Receiver submits token + amount/currency/comment.
3. Server parses token host and signs token payload.
4. Server forwards to payer vault endpoint.
5. Vault validates token/signature, decrypts card payload, resolves active secret.
6. Vault emits NWC instruction to payer wallet.
7. Payer wallet executes payment path (ecash or lightning workflow).
8. Receiver gets completion updates (notify/status channel) and balance refresh.

Failure mode:

- If card secret is stale/rotated, vault rejects early and request fails immediately.

### B. Send Payment (Sender Reads Recipient Card)

Client/API endpoint:

- `POST /safebox/paytonfctag`

Remote vault endpoint:

- `POST /.well-known/nfcpayout`

Flow:

1. Sender taps recipient NFC card.
2. Sender submits token + amount/currency/comment.
3. Server parses token and computes SAT amount.
4. Server signs token and posts to recipient vault.
5. Vault validates/decrypts token, resolves active recipient secret.
6. Vault starts recipient-side invoice/ecash handling.
7. Sender completes payment and both wallets update.

Failure mode:

- Stale/rotated card secret fails before payout processing.

## NFC Record Flows

### A. Offer Record over NFC

Client/API endpoint:

- `POST /records/acceptoffertoken`

Remote vault endpoint:

- `POST /.well-known/offer`

Flow:

1. Offerer prepares `nauth` context.
2. Offerer taps recipient card and captures token.
3. `acceptoffertoken` parses token and runs card preflight:
   - `POST /.well-known/card-status`
4. If preflight fails, request returns immediate `ERROR` to UI.
5. If preflight passes, service signs token and calls `/.well-known/offer`.
6. Vault validates token, resolves active secret, and emits NWC `offer_record`.
7. Recipient wallet handles offer flow and transmittal.

### B. Request/Present Record over NFC

Client/API endpoint:

- `POST /records/acceptprooftoken`

Remote vault endpoint:

- `POST /.well-known/proof`

Flow:

1. Requester prepares `nauth`, kind, label, and PIN.
2. Requester taps presenter card and captures token.
3. `acceptprooftoken` parses token and runs card preflight:
   - `POST /.well-known/card-status`
4. If preflight fails, request returns immediate `ERROR`.
5. If preflight passes, service signs token and calls `/.well-known/proof`.
6. Vault validates token, checks PIN, and emits NWC `present_record`.
7. Presenter wallet returns records over transmittal channels.
8. Requester receives, verifies, and renders records (including original blob flow when present).

## PIN Behavior

PIN is checked in proof/presentation-style authorization flows and can be used as a gate before sensitive actions.

Key points:

- PIN is card-specific and embedded with the active secret.
- PIN mismatch can reject or downgrade authorization depending on vault policy.
- Secret validity and PIN validity are separate checks.

## User Experience Requirements

For NFC actions, UI should:

1. Show immediate success/failure status after submit.
2. Alert on `status != OK` (invalid/rotated card, timeout, network failure).
3. Keep QR workflows unchanged and independent from NFC card rotation state.

## Operational Guidance

- Protect `SERVICE_NSEC`; compromise affects NFC token trust boundary.
- Keep `NWCSecret` mapping authoritative and auditable.
- Use structured logging for:
  - signature failures
  - decrypt failures
  - invalid/revoked secret lookups
  - upstream timeout/network errors
- Rotate secret when card set should be invalidated.
- Reissue cards after rotation.

## Endpoints Reference

Holder/client:

- `/safebox/issuecard`
- `/safebox/loginwithnfc`
- `/safebox/requestnfcpayment`
- `/safebox/paytonfctag`
- `/records/acceptoffertoken`
- `/records/acceptprooftoken`

Vault/public:

- `/.well-known/card-status`
- `/.well-known/nfcvaultrequestpayment`
- `/.well-known/nfcpayout`
- `/.well-known/offer`
- `/.well-known/proof`
