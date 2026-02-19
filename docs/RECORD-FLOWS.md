# Record Flows: Offer, Grant, and Request Sequences

This page summarizes the operational sequences used by Safebox for:

- Offering a record
- Receiving a grant
- Requesting a record

It focuses on the actual app flow (web + Nostr/NWC + transmittal), including QR and NFC paths.

## Actors

- Offeror / Issuer: sends an offer or grant
- Recipient / Holder: accepts or receives records
- Requestor / Verifier: asks another party to present a record
- Vault endpoint: `/.well-known/*` handlers used for NFC/NWC orchestration
- NWC relay: carries encrypted wallet instructions (`kind 23194`)

## Shared Building Blocks

- `nauth`: session/auth/transmittal envelope exchanged between parties
- `nembed`: compact payload transport wrapper
- NWC instruction methods:
  - `offer_record`
  - `present_record`
  - `pay_invoice` / `pay_ecash` (for NFC payment rails)
- Record transmittal kinds:
  - Auth channel (request/ack)
  - Transmittal channel (record payloads)

## 1) Offer Record Sequence

### QR Path (primary)

1. Offeror opens offer screen (`/records/offer*`) and generates `nauth` (`/records/nauth`).
2. QR with `nauth` is displayed.
3. Recipient scans QR and authenticates (responds on auth kind/relays).
4. Offeror receives auth response on websocket (`/records/ws/listenfornauth/{nauth}`).
5. Offeror submits `/records/transmit` with:
   - originating offer kind
   - final grant kind
   - selected record label/name
   - PQC KEM params (when used)
6. Sender creates grant payload and transmits over configured transmittal kind/relays.

### NFC Path

1. Offeror reads recipient NFC token.
2. App posts token + `nauth` to `/records/acceptoffertoken`.
3. Backend calls recipient vault endpoint (`/.well-known/offer`) via signed token.
4. Vault publishes encrypted NWC instruction `offer_record` to recipient wallet.
5. Recipient wallet listens, processes, and transmits records/grant via transmittal channel.

## 2) Receive Grant Sequence

1. Recipient receives transmittal event(s) on transmittal kind/relays.
2. Payload is unwrapped/decrypted and parsed.
3. If PQC fields exist:
   - decrypt payload (`pqc_encrypted_payload`)
   - optionally decrypt original blob metadata (`pqc_encrypted_original`)
4. Grant is persisted as recipient record.
5. If original transfer metadata exists, recipient may fetch blob from transfer server and store/consume it.
6. UI shows received record with verification metadata.

## 3) Request Record Sequence

### QR Path (requestor-driven)

1. Requestor creates request `nauth` (`/records/nauth`) from request screen.
2. Presenter scans QR and responds on auth channel.
3. Requestor websocket (`/records/ws/request/{nauth}`) receives presenter handshake.
4. Requestor sends KEM material to presenter (for protected payload/original blob transfer).
5. Presenter sends record payload(s) over transmittal channel.
6. Requestor verifies and renders record cards.
7. If original record metadata is present, requestor fetches and renders original blob.

### NFC Path (requestor taps presenter token)

1. Requestor reads NFC token and posts `/records/acceptprooftoken`.
2. Backend calls presenter vault endpoint (`/.well-known/proof`) with signed request:
   - includes `nauth`, requested label/kind, pin, and signature
3. Vault publishes encrypted NWC instruction `present_record` to presenter wallet.
4. Presenter wallet resolves requested record and transmits it back over transmittal channel.
5. Requestor websocket receives, verifies, and renders record.
6. If `original_record` metadata is included, requestor fetches blob once and renders in-card.

## Original Blob Behavior

- Original blobs are fetched from transfer metadata (server, hash, encryption params).
- In request UI, blob fetch is one-time and may delete at source after retrieval.
- PDF rendering is single-page with Prev/Next pagination in modernized templates.

## Failure and Hardening Notes

- Signature verification is enforced in NFC vault endpoints.
- `/records/acceptprooftoken` now returns structured errors for invalid token/network/upstream failures.
- Missing trust/WoT configuration degrades gracefully (no hard crash).
- Request websocket flow now avoids unbound local errors during mixed payload shapes.

## Key Endpoints (quick index)

- Request/offer orchestration:
  - `/records/nauth`
  - `/records/transmit`
  - `/records/acceptprooftoken`
  - `/records/acceptoffertoken`
- Websockets:
  - `/records/ws/request/{nauth}`
  - `/records/ws/listenfornauth/{nauth}`
- Vault/NWC bridges:
  - `/.well-known/proof`
  - `/.well-known/offer`
  - `/.well-known/nfcvaultrequestpayment`
- Blob retrieval:
  - `/records/originalblob`
  - `/records/blob`
