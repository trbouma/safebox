# NFC Flows and Security

## Overview

This document describes how NFC works in Safebox today, including:

- Issuance of an NFC card by the holder
- NFC login
- NFC-assisted payment flows (accept and send)
- NFC-assisted record flows (offer and present/request)
- Security model and hardening considerations

## Scope

This specification covers NFC issuance, login, payment, and record flows as currently implemented.

This specification does not define hardware-level secure element requirements.

## NFC Card Issuance (Holder)

The holder issues an NFC token from the protected route:

- `GET /safebox/issuecard`

At issuance time, the server:

1. Generates a one-time `secure_pin`.
2. Builds plaintext secret material:
   - `holder_privkey_hex:secure_pin`
3. Encrypts this with service key material (`SERVICE_NSEC`) using NIP-44.
4. Wraps encrypted token into a compact `nembed` payload:
   - `h`: expected host/domain
   - `k`: encrypted token material
   - `a`: default amount fallback (e.g., 21 sats)
   - `n`: NFC defaults/profile metadata (`NFC_DEFAULT`)

The resulting `nembed` string is what gets written to the NFC card/tag.

## NFC Login

Route:

- `POST /safebox/loginwithnfc`

Flow:

1. Client submits `nembed`.
2. Server parses and validates payload host.
3. Server resolves holder identity from token payload and looks up registered safebox.
4. If valid, server issues access token and redirects to `/safebox/access`.

## NFC Payment Flows

There are two distinct directions:

- **A. Accept payment from another card/token**
- **B. Send payment to another card/token**

### 3A. Accept Payment by NFC (`requestnfcpayment`)

Routes:

- Client/API: `POST /safebox/requestnfcpayment`
- Remote vault endpoint: `POST /.well-known/nfcvaultrequestpayment`

Sequence:

1. Receiver scans NFC token.
2. Receiver submits `{payment_token, amount, currency, comment}`.
3. Server parses token (`h`, `k`, optional default amount).
4. Server signs `k` (`sig = sign_payload(...)`) with service key.
5. If lightning path:
   - Creates invoice (`deposit(...)`), starts payment monitor task.
   - Sends signed request + invoice to remote `/.well-known/nfcvaultrequestpayment`.
6. If ecash-clearing path:
   - Sends signed ecash instruction and starts ecash listener.
7. Remote vault decrypts token, emits NWC instruction (`kind 23194`) to the payer wallet.
8. Payer wallet executes payment instruction; receiver settles and balance updates.

### 3B. Send Payment to NFC Tag (`paytonfctag`)

Routes:

- Client/API: `POST /safebox/paytonfctag`
- Remote vault endpoint: `POST /.well-known/nfcpayout`

Sequence:

1. Sender scans recipient NFC tag.
2. Sender submits `{nembed, amount, currency, comment}`.
3. Server parses token and computes final amount (fallback to `a` if needed).
4. Server signs token (`sig`) and posts to recipient vault `/.well-known/nfcpayout`.
5. Recipient vault resolves target wallet from token secret and:
   - creates invoice (lightning) or
   - accepts ecash path
6. Sender side pays invoice / sends ecash asynchronously.
7. Sender and recipient balances are updated via existing payment tasks.

## NFC Record Flows

There are two core record operations over NFC:

- **Offer a record**
- **Present a record in response to a request**

### 4A. Offer Record by NFC

Routes:

- Client/API: `POST /records/acceptoffertoken`
- Remote vault endpoint: `POST /.well-known/offer`

Sequence:

1. Offeror generates `nauth` (scope/grant context) and scans recipient NFC token.
2. Offeror posts `{offer_token, nauth}` to `/records/acceptoffertoken`.
3. Server parses token host + encrypted key, signs token, forwards to `/.well-known/offer`.
4. Vault decrypts token and publishes NWC instruction:
   - `method = "offer_record"`
   - `params = {nauth}`
5. Recipient wallet receives instruction and runs offer/grant transmittal flow.

### 4B. Request/Present Record by NFC

Routes:

- Client/API: `POST /records/acceptprooftoken`
- Remote vault endpoint: `POST /.well-known/proof`

Sequence:

1. Requestor creates `nauth` (record kind/scope) and scans presenter NFC token.
2. Requestor posts `{proof_token, nauth, label, kind, pin}`.
3. Server parses token, signs token, forwards to `/.well-known/proof`.
4. Vault verifies signature, checks token PIN, and emits NWC instruction:
   - `method = "present_record"`
   - `params = {nauth, label, kind, pin_ok}`
5. Presenter wallet resolves requested record and transmits result over nauth transmittal channels.
6. Requestor websocket receives, verifies, and renders record(s).
7. If original blob metadata is present, requestor fetches and renders original record inline.

## Security Considerations

## Token Confidentiality

- NFC tokens do **not** expose raw wallet secret directly.
- Sensitive token payload (`k`) is encrypted with service-side key material.

## Domain/Host Binding

- Token includes host `h` to bind operation to a target domain/environment.
- Parsing logic checks this to avoid cross-host misuse.

## Signed Vault Requests

- Outbound vault requests include:
  - `token` (encrypted payload)
  - `pubkey` (service pubkey)
  - `sig` (Schnorr signature over token payload)
- Some vault endpoints enforce signature failure with immediate reject.

## NWC Relay Isolation

- Vault endpoints do not perform direct wallet actions.
- They publish encrypted NWC instructions (`kind 23194`) addressed to wallet pubkey.
- Wallet executes instruction in its own context.

## PIN Gate for Presentation

- Proof/presentation path carries `pin_ok` from vault check.
- This signal can be used to enforce policy before record release.

## Original Blob Safety

- Original records may be transferred as encrypted metadata + blob references.
- Request-side retrieval can be one-time (fetch then delete at source) depending on flow.

## Operational Notes

These are important implementation notes for operators:

- Ensure signature verification is consistently enforced across **all** NFC vault endpoints.
  - Some endpoints enforce fail-fast today; others should be reviewed for parity.
- Keep `SERVICE_NSEC` protected; compromise impacts NFC trust boundary.
- Consider replay protections (nonce/timestamp/TTL) for signed vault payloads.
- Restrict allowed hosts for token-directed outbound calls (SSRF controls).
- Log structured status for:
  - signature failures
  - invalid token formats
  - upstream vault failures/timeouts
- Keep NFC token issuance and rotation operationally documented (revocation, reissue).

## Implementation References

Holder-facing:

- `/safebox/issuecard`
- `/safebox/loginwithnfc`
- `/safebox/requestnfcpayment`
- `/safebox/paytonfctag`
- `/records/acceptoffertoken`
- `/records/acceptprooftoken`

Vault-facing:

- `/.well-known/nfcvaultrequestpayment`
- `/.well-known/nfcpayout`
- `/.well-known/offer`
- `/.well-known/proof`
