# Record Presentation Strategy with nAuth

## Overview

This spec describes Safebox’s generalized record-presentation model built around `nAuth`, and how presentation interactions can be initiated through either QR codes or NFC cards.

Core idea:

- open/edge channels (QR, NFC) carry only minimal bootstrap information
- actual record transfer happens on a separate secure messaging channel
- credentials are treated as a subset of records, not a separate primitive

## Scope

Included:

- nAuth as interaction bootstrap and negotiation envelope
- QR-initiated presentation flow
- NFC-initiated presentation flow
- separation of insecure initiation channel vs secure transfer channel

Not included:

- low-level format internals of every related payload type
- detailed relay implementation internals

## nAuth as Generalized Bootstrap

`nAuth` provides the minimum interaction metadata needed to start a presentation session, including:

- initiator identity context
- authorization scope
- relay/routing hints
- transmittal parameters and negotiation context

It is intentionally compact enough to be transmitted through constrained edge channels (QR/NFC), while avoiding bulk payload exposure on those channels.

## Initiation Channels

### A. QR Code Initiation

1. Presenter or requester creates `nAuth`.
2. `nAuth` is rendered as QR and scanned by counterparty.
3. Counterparty uses `nAuth` to establish authenticated secure transmittal path.
4. Records are transferred on secure channel, not in QR payload.

### B. NFC Card Initiation

1. Card carries tokenized bootstrap payload (for example `nembed` containing token reference).
2. Reader extracts token and resolves/validates card context.
3. Flow invokes nAuth-mediated secure messaging path.
4. Records are transferred on secure channel after authorization.

In both cases, QR/NFC are treated as edge bootstrap channels, not final data channels.

## Multi-Channel Presentation Model

Safebox separates interaction into two channel classes:

1. **Open/insecure bootstrap channel**
   - optical QR or NFC read event
   - limited metadata only
2. **Secure negotiated transfer channel**
   - signed/encrypted message exchange
   - record payload movement
   - dynamic transmittal negotiation (relays, kinds, method context)

This separation provides stronger privacy and flexibility than single-channel verification patterns.

## Why This Is More General Than Credential-Only Verification

Traditional credential verification stacks usually assume:

- fixed credential schema
- constrained payload size
- tightly coupled verification transport

Safebox’s record-presentation model is broader:

- no hard distinction between “credential” and “record”
  - a credential is simply a record with specific semantics
- supports arbitrary record payloads and original blobs
- supports dynamic secure channel negotiation independent of QR/NFC edge channel
- keeps edge channel data minimal even when final payload is large/complex

## Payload Size and Data-Class Neutrality

Because transfer occurs on negotiated secure channels rather than inside QR/NFC payloads:

- payload size is not constrained by QR symbol size or NFC tag practical limits
- large records/blobs can be transferred using the same interaction pattern
- model remains uniform across:
  - credentials
  - attestations
  - grants/offers
  - generic records and associated blob data

## Security Considerations

- Treat QR/NFC data as bootstrap-only and potentially observable.
- Perform authorization and trust checks on secure-channel processing path.
- Keep record acceptance and trust policy independent from initiation channel.
- Prefer signed/encrypted transmittal for all non-trivial payloads.

## Implementation References

- `app/routers/records.py`
- `app/templates/records/request.html`
- `app/templates/records/offer.html`
- `app/templates/records/offerlist.html`
- `docs/specs/NAUTH-PROTOCOL.md`
- `docs/specs/NFC-FLOWS-AND-SECURITY.md`
- `docs/specs/OFFERS-AND-GRANTS-FLOWS.md`
