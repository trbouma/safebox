# Card Tokenization and NFC Payment Strategy

## Overview

This design note describes how Safebox virtualizes NFC cards for payments and record operations, and how that strategy is analogous to tokenized card systems used by Apple Pay and Google Wallet for Visa/Mastercard rails.

Safebox does not copy card-network protocols directly. Instead, it applies the same architectural idea:

- never use a long-lived primary credential directly at the interaction edge
- use a revocable tokenized surrogate
- validate token state server-side before authorizing value movement
- keep policy and risk controls in software

## Scope

Included:

- NFC card credential model in Safebox
- mapping to tokenization concepts used by Apple/Google ecosystems
- payment execution path and authorization checks
- lifecycle controls (issue, rotate, revoke)

Not included:

- EMV cryptogram internals
- scheme network message formats (ISO 8583, etc.)
- secure element hardware implementation details

## Design Strategy

Safebox uses a software tokenization model for NFC cards:

1. Card stores a compact `nembed` payload.
2. Payload contains encrypted token material (`k`) rather than raw wallet credentials.
3. Decrypted token yields `nwc_secret:pin`.
4. `nwc_secret` resolves to active wallet identity through `NWCSecret` mapping.
5. If mapping is missing/rotated, card is rejected.

This mirrors network tokenization semantics:

- PAN equivalent in card networks -> `nwc_secret` mapping in Safebox
- device/card token lifecycle -> card secret lifecycle
- issuer authorization policy -> vault + app-level authorization policy

## Apple/Google Analogy

In Apple Pay / Google Wallet:

- A device-account token is provisioned instead of exposing raw PAN.
- Token is domain-bound and can be revoked independently.
- Transactions are authorized through issuer/network risk systems.

In Safebox:

- A card token (`nembed -> encrypted k`) is provisioned instead of exposing wallet private material.
- Token is host-bound and secret-mapped, and can be revoked by rotation.
- Transactions are authorized through application vault checks and active-secret mapping.

Practical equivalence:

- both systems virtualize cards into replaceable token handles
- both reduce blast radius of credential leakage
- both separate edge credential from core account authorization

## Payment Flow Model

### A. Request Payment (payer card is read)

1. Receiver scans payer NFC card.
2. App parses token and performs card-status preflight.
3. App signs request and calls payer vault endpoint.
4. Vault validates token/signature and resolves active mapping.
5. Wallet executes payment workflow (ecash first path, lightning fallback as configured).

### B. Send Payment (recipient card is read)

1. Sender scans recipient NFC card.
2. App parses token and amount context.
3. App signs request and calls recipient payout vault endpoint.
4. Vault validates token/signature, resolves wallet, and initiates payout handling.

## Generalized Record-Transfer Model

Safebox extends tokenized card authorization with a generalized transport pattern: value and data are both transmitted as records over secure messaging channels.

### Ecash as Transfer Record

In Safebox-to-Safebox payment paths, ecash payloads are transmitted as record-like messages and redeemed by the receiving Safebox. To the end user this can appear like a Lightning payment, but internally it is often:

1. card-authorized request/payout intent
2. secure message delivery of ecash token payload
3. receiver-side redemption and settlement

This turns payments into a record-processing workflow with explicit validation and replay resistance.

### Offers and Grants as Transfer Records

The same control plane is used for offers and grants:

- an offer is transmitted as a structured record intent
- acceptance generates grant-oriented record artifacts
- optional original blob transfer attaches source material to the resulting record

From a system perspective, ecash transfer, offer transmission, and grant presentation are all variants of the same mechanism:

- authenticate actor/card token
- authorize operation
- transmit structured record payload
- validate and ingest at destination

### Why This Matters

By unifying payments and records under one transfer model, Safebox avoids maintaining separate trust stacks for "money" vs "data". The same tokenized card, vault checks, and message transport can safely drive both.

## Card as Independent Wallet Interface

Because payment and record operations share the same tokenized record-transfer model, a provisioned NFC card effectively becomes a full wallet interface at the point of interaction:

- initiate send payment
- initiate/request receive payment
- initiate offer transmission
- initiate record request/presentation
- log in to NFC-enabled Safebox web workflows

This does not require a specific mobile OS wallet framework. The application-layer policy and cryptographic validation live in Safebox services, enabling low-cost cards and heterogeneous client devices (mobile/desktop/web NFC capable) to participate consistently.

## NWC Extension and Messaging-Bus Direction

Safebox payment and record flows currently leverage and extend Nostr Wallet Connect (NWC) patterns. In practice, NWC is used as the secure instruction and response channel between vault-facing endpoints and wallet execution logic.

### Current NWC-Extended Usage

- Payment methods (for example payout/request orchestration) are dispatched as structured wallet instructions.
- Record methods (for example offer/present flows) are dispatched over the same mechanism.
- Payloads are serialized as JSON-RPC-like instruction objects and transported over Nostr relay messaging.

This turns NWC from a narrow wallet-action interface into a broader control plane for cross-instance Safebox workflows.

### Why Extend Beyond REST-First

REST/API endpoints are still used where needed, but they depend on DNS and HTTPS endpoint reachability. Safebox’s longer-term direction is to reduce this dependency by routing more operations through signed, encrypted messaging between service keys.

Benefits of the bus approach:

- endpoint-agnostic routing through relay fabric
- reduced coupling to domain/address stability
- unified authn/authz and signing semantics across flow types
- easier policy enforcement at message level

### Target Architecture

Longer term, the majority of inter-service operations are expected to run through the NWC-like messaging service using JSON-RPC messages as the primary transport abstraction, with REST retained for compatibility, bootstrap, and public discovery surfaces.

Design intent:

- "payments" and "records" are first-class methods on one secure message bus
- additional Safebox workflows can be onboarded without creating parallel transport stacks
- trust-anchor and Web-of-Trust policy can be applied at the same message-processing layer

## Authorization and Policy Layer

Safebox intentionally keeps security logic in application code:

- token signature verification
- card-status and active-secret checks
- optional PIN validation
- amount and flow constraints
- endpoint-scoped policy enforcement

This allows commodity cards (for example NTAG215) and non-specialized acquisition devices while still enforcing robust policy.

## Lifecycle and Rotation

Issuance:

- user issues one or more physical cards from current active secret mapping
- each card may have a distinct PIN

Rotation:

- generating a new active secret invalidates all cards carrying old secret
- equivalent to mass token revocation event

Operationally:

- users can self-revoke cards in circulation without changing wallet root identity

## Security Considerations

- Treat `SERVICE_NSEC` and vault signing keys as critical trust anchors.
- Keep `NWCSecret` mapping authoritative; rotation should be audited.
- Distinguish:
  - definitive invalid-card outcomes (reject immediately)
  - transport uncertainty (retry/advisory path as policy allows)
- Use structured logs for token verify failures, mapping misses, and vault errors.
- PIN is a policy gate, not the root credential.

## Trust Anchors and Planned WoT Enforcement

Each Safebox service instance can be treated as a trust anchor identified by its service public key.

Current model:

- Inter-service operation is open by default.
- Incoming payloads are still cryptographically validated (signature verification across instances is already in place).

Planned model:

- Introduce explicit trust lists of service anchors to support private-network enforcement while preserving optional open interoperability.
- A Safebox instance may query published trust-list events (or equivalent configuration) to determine which service public keys are trusted.
- Payloads from non-trusted anchors can be ignored or downgraded by policy.

This is expected to be an incremental extension of existing verification logic rather than a protocol rewrite, once operational requirements for trust-list distribution and governance are finalized.

## Implementation References

- `app/routers/safebox.py`
- `app/routers/lnaddress.py`
- `app/routers/records.py`
- `app/nwc.py`
- `docs/specs/NFC-FLOWS-AND-SECURITY.md`
- `docs/specs/NWC-NFC-VAULT-EXTENSION.md`
