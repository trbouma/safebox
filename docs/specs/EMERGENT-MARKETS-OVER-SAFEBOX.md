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

## Market Microstructure

### Order Types

| Type | Initiator | Opening Signal | Execution Signal |
| --- | --- | --- | --- |
| `ASK` | Seller | Kind-1 post with price and asset tags | Buyer zap confirming acceptance |
| `BID` | Buyer | Kind-1 post with price and asset tags | Seller acknowledgement + buyer zap |

### Five-Layer Stack

| Layer | Technology | Role |
| --- | --- | --- |
| Identity | Nostr keypair + NIP-05 | Sovereign participant identity |
| Communication | Kind-1 posts + replies | Public order intent and negotiation |
| Payment | NIP-57 zaps | Instant execution and payment signal |
| Delivery | NIP-17 private DMs | Encrypted delivery of digital goods |
| Settlement | Kind-1 settlement notes | Public, immutable post-trade evidence |

### Continuous Auction Mapping

The model can evolve into a continuous double auction (CDA) without changing core message types.

| CDA Function | Traditional Exchange | Safebox Emergent Market |
| --- | --- | --- |
| Order book | Centralized internal DB | Relay-indexed public kind-1 intents |
| Match trigger | Matching engine decision | Bilateral acceptance with price crossing |
| Payment settlement | Clearing/custody rails | Lightning zap finality |
| Delivery | Custodial transfer mechanisms | NIP-17 encrypted delivery |
| Settlement evidence | Internal ledger entries | Public settlement events and zap receipts |

Execution price is established by accepted counterparty terms and confirmed by zap execution.

## Permissionless Operation Principles

### Open Participation

Any npub-holder can publish bid/ask intents. Protocol participation is not restricted by Safebox at the base layer.

### No Mandatory Trusted Intermediary

Payment and delivery are coordinated peer-to-peer via zap evidence and encrypted direct delivery. No mandatory escrow layer is required for baseline operation.

### Resilient Market Surface

Order intent and settlement traces are relay-distributed; single relay outages degrade visibility but do not eliminate the market.

### Micropayment-Native Market Granularity

The model supports very small trade sizes in sats, allowing digitally deliverable goods to clear at granularity impractical in legacy venues.

### Human-Agent Parity

The same contracts are executable by humans and agents. Agent automation is an operational extension, not a separate protocol.

## Agentic Execution Loop

A minimal autonomous loop:

1. Observe order intents and detect crossing opportunities.
2. Publish bid/ask intents or counter-intents.
3. Execute zap payment.
4. Verify receipt identity and amount coherence.
5. Deliver payload privately.
6. Publish settlement note.
7. Reconcile P&L and repeat.

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

## Bid-First Reference Implementation (Current Safebox Profile)

This section defines the concrete implementation profile used by current Safebox agent workflows for the bid-first path.

### A. Bid Post (kind `1`)

Bidder publishes a kind-1 note with parseable market tags:

- `["mkt","safebox-v1"]`
- `["flow","bid-first"]`
- `["side","bid"]`
- `["asset","riddle.answer"]`
- `["px","21"]` (sats)
- `["qty","1"]`
- `["ord","<bid_order_id>"]`

Recommended `content` style:

- Human-readable sentence including the price and requested item.

### B. Seller Acceptance Reply (kind `1` reply)

Seller replies to the bid event and includes linkage tags:

- `["mkt","safebox-v1"]`
- `["type","accept"]`
- `["bid","<bid_event_id>"]`
- `["ord","<bid_order_id>"]`
- `["px","21"]`
- `["qty","1"]`

Reply `content` should explicitly instruct bidder to zap the reply event for execution.

### C. Execution Signal (NIP-57 zap)

Bidder zaps the seller’s acceptance reply event id.

Execution is considered initiated when the zap call returns success and considered confirmed when matching `9735` receipt(s) are visible for the acceptance reply event.

### D. Receipt Verification Gate

Seller (or seller agent) queries receipt events for the acceptance reply event id and verifies all of:

1. `matches_target_event == true`
2. `amount_matches == true` (when amount tag present in embedded request)
3. `description_hash_matches == true` (when invoice includes description hash)
4. `zapper_identity_source in {"description_pubkey","P_tag"}`

The seller must not use receipt signer (`lnurl_provider_pubkey`) as payer identity.

### E. Private Delivery (NIP-17 DM)

After verification gate passes, seller sends DM to zapper identity:

- Recipient: `zapper_npub` (preferred) or `zapper_pubkey`
- Message payload includes:
  - `trade_id` (derived from order + execution context)
  - fulfillment content (for example, riddle answer)
  - optional `artifact_hash` for integrity trace

### F. Public Settlement Confirmation

Bidder replies to original bid thread with settlement confirmation tags:

- `["mkt","safebox-v1"]`
- `["type","settled"]`
- `["flow","bid-first"]`
- `["bid","<bid_event_id>"]`
- `["ask","<accept_reply_event_id>"]`
- `["zap_receipt","<receipt_event_id_optional>"]`
- `["delivery","complete"]`

This note closes the trade in public order-flow state.

### G. Agent Endpoint Sequence

Current `/agent/*` sequence for deterministic execution:

1. `POST /agent/publish_kind1`  
   Bid creation
2. `POST /agent/reply`  
   Seller acceptance reply
3. `POST /agent/zap`  
   Bidder zaps acceptance reply event
4. `GET /agent/nostr/zap_receipts?event_id=<accept_reply_event_id>`  
   Seller verifies receipt identity + coherence
5. `POST /agent/secure_dm`  
   Seller sends private fulfillment
6. `POST /agent/reply`  
   Bidder posts settlement confirmation to bid thread

### H. State Machine (Bid-First)

- `OPEN_BID` -> bid posted, awaiting acceptance
- `ACCEPTED` -> acceptance reply posted
- `PAYMENT_PENDING` -> zap requested, awaiting verified receipt
- `PAYMENT_CONFIRMED` -> receipt verification gate passed
- `DELIVERED` -> private fulfillment DM sent
- `SETTLED_PUBLIC` -> public settlement confirmation posted

Terminal error states:

- `EXPIRED` -> TTL reached without acceptance/payment
- `FAILED_PAYMENT_VALIDATION` -> receipt seen but verification gate failed
- `DELIVERY_FAILED` -> payment confirmed but DM delivery failed after retries

### I. Idempotency and Replay Controls

Implementations should enforce:

- Stable `ord`/`trade_id` identifiers.
- At-most-once delivery per confirmed payment receipt id.
- Reconciliation retries on relay lag before moving to failure states.

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

## Progression to Production-Grade Continuous Auction

| Capability | Practical Requirement | Protocol/Implementation Anchor |
| --- | --- | --- |
| Order aggregation | Relay indexing for open intents | Kind-1 tags (`mkt`, `side`, `asset`, `px`) |
| Order expiry | Time-bounded intent validity | Expiration tag conventions (e.g., NIP-40 style) |
| Partial fills | Multi-fill settlement tracking | Multiple zap receipts + per-fill settlement notes |
| Market depth views | Aggregated open bid/ask states | Relay queries over structured tags |
| Reputation | Counterparty execution history | Public settlement trail + verified zap evidence |
| Price history | Executed trade indexing | Kind-9735 receipts + settlement posts |

These upgrades can be layered without replacing the core flow defined in this document.

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
