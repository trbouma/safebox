# Emergent Markets Over Safebox

## Overview

This document describes how a decentralized bid/ask market can emerge from existing Safebox capabilities without introducing a centralized matching engine, custody layer, or privileged market operator.

The model composes four existing primitives:

- Public intent publication (Nostr kind `1`)
- Payment authorization and settlement signaling (NIP-57 zaps, kinds `9734`/`9735`)
- Private fulfillment delivery (NIP-17 DM transport, kind `1059` gift-wrap)
- Public settlement confirmation (Nostr kind `1`)

In this model, market behavior emerges from interoperable messages and verifiable payment artifacts rather than a single exchange process.

## Scope

This specification covers:

- A minimal order intent format (bid/ask)
- A deterministic two-party match and settlement flow
- Delivery and settlement evidence patterns
- Agent-compatible operation using existing Safebox agent endpoints

This specification does not cover:

- Central limit order book consensus
- Custodial escrow
- Dispute arbitration guarantees
- Regulatory classification or venue licensing

## Market Model

### Participants

- Seller: posts an `ASK`, receives zap payment, delivers fulfillment payload.
- Buyer: posts a `BID` or accepts an `ASK`, zaps seller, receives payload.
- Observer/agent: indexes public intents and settlement signals.

### Economic Unit

- Price is denoted in sats for execution.
- Optional display currencies are informational only.

### Asset Class

- Digital artifacts, records, attestations, or service outputs deliverable through Safebox private messaging and/or record transfer.

## Message Contracts

### 1. Public Order Intent (kind `1`)

Orders are published as normal kind-1 posts with machine-parseable tags.

Recommended tags:

- `["mkt","safebox-v1"]`
- `["side","bid" | "ask"]`
- `["asset","<asset_id_or_label>"]`
- `["qty","<decimal_or_int>"]`
- `["px","<sats_per_unit>"]`
- `["ord","<client_order_id>"]`
- `["exp","<unix_ts_optional>"]`
- `["seller","<pubhex_or_npub_optional>"]`
- `["buyer","<pubhex_or_npub_optional>"]`

`content` should remain human-readable while tags provide parsing structure.

### 2. Match Declaration (optional, kind `1`)

Either party may publish a match note before payment:

- `["mkt","safebox-v1"]`
- `["type","match"]`
- `["bid","<bid_event_id>"]`
- `["ask","<ask_event_id>"]`
- `["px","<execution_price_sats>"]`
- `["qty","<execution_qty>"]`

### 3. Payment (NIP-57)

Buyer executes zap against seller profile or listing event.

Verification-relevant receipt facts:

- Receipt event kind `9735`
- Target event linkage via `e` tag
- Embedded zap request (`description`) kind `9734`
- Zapper identity from `description.pubkey` (not receipt signer)

### 4. Private Fulfillment (NIP-17)

Seller delivers artifact/service material over private DM transport after payment signal.

Recommended delivery tags (inside delivered payload/event contract):

- `trade_id`
- `asset`
- `hash` (artifact digest)
- `delivery_ref` (optional pointer)

### 5. Public Settlement Confirmation (kind `1`)

Either or both parties publish settlement:

- `["mkt","safebox-v1"]`
- `["type","settled"]`
- `["bid","<bid_event_id>"]`
- `["ask","<ask_event_id>"]`
- `["zap_receipt","<9735_event_id_optional>"]`
- `["delivery","complete" | "partial" | "failed"]`

## Matching and Execution Flow

Minimal deterministic flow:

1. Sellers publish asks and buyers publish bids.
2. A counterparty detects crossing prices (`bid_px >= ask_px`).
3. Counterparty selection is bilateral (no central matcher required).
4. Buyer sends zap.
5. Seller verifies receipt signal and zapper identity.
6. Seller delivers payload privately.
7. Parties publish settlement notes.

## Two-Round Example

Round 1:

- Ask: Rare Insight @ 50 (Lumen)
- Bid: Rare Insight @ 55 (Nova) -> fill @ 50
- Ask: Lucky Byte @ 30 (Pixel)
- Bid: Lucky Byte @ 35 (Lumen) -> fill @ 30

Round 2:

- Ask: Signal Fragment @ 40 (Nova)
- Bid: Signal Fragment @ 45 (Pixel) -> fill @ 40
- Ask: Entropy Seed @ 25 (Lumen)
- Bid: Entropy Seed @ 25 (Nova) -> fill @ 25

This demonstrates repeated price discovery and bilateral settlement using only open protocol messages.

## Agent-Ready Operation

The same flow is automatable using existing Safebox agent endpoints:

- Post/read market intents: kind-1 publish + latest-kind1 queries
- Discover own listings: `/agent/nostr/my_latest_kind1`
- Read zap receipts and zapper identity: `/agent/nostr/zap_receipts`
- Send private fulfillment: `/agent/secure_dm`

This preserves human/agent parity: humans can perform the flow manually in clients; agents can execute the same contract via API.

## Trust and Validation

Implementations should enforce:

- Receipt signer vs zapper distinction:
  - receipt signer = LNURL provider key
  - zapper identity = embedded `9734` sender key
- Amount coherence checks:
  - requested amount vs invoice amount (msat)
- Target coherence checks:
  - receipt references intended order/listing event
- Delivery evidence integrity:
  - include digest/hash for delivered artifact when possible

## Failure and Recovery

Expected failure classes:

- Payment seen, delivery delayed
- Delivery sent, settlement post missing
- Relay inconsistency or delayed receipt visibility

Recommended handling:

- Define trade TTLs and retry windows
- Reconcile via private channel first, public settlement second
- Publish correction/cancel notes rather than mutating prior events

## Security Considerations

- Do not derive payer identity from `9735.pubkey` alone.
- Keep sensitive fulfillment artifacts off public relays.
- Treat zaps as payment signals with cryptographic evidence, not court-final proof.
- Use minimal public metadata for market intents when confidentiality is required.

## Implementation References

- `docs/specs/AGENT-API.md`
- `docs/specs/AGENT-FLOWS.md`
- `docs/specs/HUMAN-FIRST-APPROACH.md`
- `docs/specs/HARDENING-IN-UNPREDICTABLE-AND-ADVERSARIAL-ENVIRONMENTS.md`
- `docs/specs/PAYMENTS-SAFEBOX-CASHU-LIGHTNING-FALLBACK.md`
