# MS-02: Hash-Committed Entitlement Market
**Version**: `2.0`
**Status**: Draft  
**Tag**: `#MS02`  
**Market Namespace**: `mkt=MS-02`  
**Date**: 2026-03-07

---

## 1. Purpose

Define a generic market protocol for trading single-use, hash-committed service entitlements over Nostr with deterministic settlement and verifiable redemption.

This specification uses four market primitives:

1. `Entitlement`
2. `Order`
3. `Trade`
4. `Redemption`

These primitives define the full lifecycle from issuance through final service delivery.

### 1.3 Historical Parallel (Non-Normative)

MS-02 follows the same economic pattern as historical redeemable-claim instruments, including:

- bills of exchange
- warehouse receipts
- bearer bonds

In each case, the traded object is the redeemable claim, not the underlying asset/service itself.
MS-02 applies this model using cryptographic commitments and digital settlement rails rather than paper instruments.

---

## 1.1 Scope

MS-02 defines:

- entitlement creation and commitment binding
- order publication and deterministic ask identity
- trade settlement and winner selection
- secret delivery and buyer verification
- redemption proof-of-control and single-use enforcement

MS-02 does not define:

- escrow/custody guarantees
- mandatory refund enforcement
- downstream service API schemas
- concrete redemption HTTP endpoint contracts

---

## 1.2 Normative Language

The key words `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` are to be interpreted as described in RFC 2119 and RFC 8174.

---

## 2. Roles

| Role | Responsibility |
|------|----------------|
| **Seller** | Issues entitlements, publishes orders, detects settlement, selects winner, delivers entitlement secret |
| **Buyer** | Settles an order, verifies delivered entitlement against commitment, redeems service |
| **Redemption Provider** | Verifies redemption proof, releases service/resource, enforces one-time redemption |

---

## 3. Core Primitives

### 3.1 Entitlement

An `Entitlement` is the fundamental unit of trade.

An entitlement represents a redeemable claim on a future service or resource provided by a redemption provider.

Examples include:

- compute credits
- API calls
- inference tokens
- storage capacity
- other digital services

Each entitlement is implemented as a hash-committed redemption key.

Where:

- `npub_i` identifies the redemption handle (`entitlement_ref` in `nostr_keypair_v1`)
- `sk_i` is the private redemption secret (`entitlement_secret` in `nostr_keypair_v1`)
- `h_i` is the commitment hash (`commitment_hash`) that locks entitlement control until settlement-time secret delivery

Ownership/control transfer occurs when `sk_i` is delivered to the winning buyer and verified against `h_i`.

### 3.2 Order

An `Order` is a public sell intent for exactly one entitlement unit.

An order binds price/expiry metadata to an entitlement commitment hash and is identified by deterministic `ask_id`.

Order parameters include:

- entitlement reference and scheme
- quantity (v2.0 fixed at `1`)
- price and settlement method
- expiry
- optional redemption provider metadata/commitment
- commitment hash and deterministic ask identifier

### 3.3 Trade

A `Trade` is the settlement outcome for an order.

A trade occurs when payment satisfies the order price.

For `nip57_zap_v1` settlement:

- buyers send zaps referencing the order event
- seller aggregates settled zap receipts per sender
- the first sender to reach `price_sats` becomes the buyer

Partial payments from non-winning participants do not, by themselves, constitute a trade.

Zap receipts are treated as settlement evidence because they are emitted only after payment clears.

After settlement, the seller transfers control of the entitlement by revealing `sk_i` (the `entitlement_secret`) to the winning buyer.

### 3.4 Redemption

A `Redemption` is the provider-side challenge/response process that converts a valid entitlement into delivered service.

Example redemption flow:

1. Buyer presents `npub_i` (`entitlement_ref`)
2. Redemption provider issues challenge
3. Buyer signs challenge with `sk_i` (`entitlement_secret`)
4. Provider verifies signature/proof-of-control

If valid and unused, provider releases the underlying service.

A successful redemption MUST consume entitlement spend state.

---

## 4. Terminology

| Term | Definition |
|------|------------|
| **Entitlement Reference** | Public identifier/locator used in redemption (`entitlement_ref`) |
| **Entitlement Secret** | Private secret delivered to winning buyer (`entitlement_secret`) |
| **Commitment Hash** | Hash over canonical secret-derived commitment bytes |
| **Order Details** | Canonical JSON object describing traded unit and settlement policy |
| **Ask ID** | Deterministic identifier over issuer + canonical order details + commitment hash |
| **Trade Winner** | Buyer identity selected after settlement policy evaluation |
| **Spent State** | Provider state that prevents entitlement reuse |

---

## 4.1 Pricing Abstraction

Prices in this market are expressed generically as the number of settlement units required to acquire one service entitlement.

Formal quote model:

`price = settlement_units / entitlement`

Definitions:

- `settlement_unit`: asset used to complete payment in a trade
- `entitlement`: redeemable claim being purchased

MS-02 intentionally separates settlement from entitlement semantics so the market model remains portable across payment systems.

Nostr profile in this specification:

- settlement unit is `sat` (satoshi)
- prices are quoted as sats per entitlement

Future profiles MAY use other settlement units (for example tokens, credits, or fiat rails) without changing the core entitlement market mechanics.

---

## 5. Data Model

| Field | Type | Required | Notes |
|------|------|----------|------|
| `market` | string | Yes | `MS-02` |
| `issuer_pubkey` | string | Yes | seller pubkey hex |
| `entitlement_scheme` | string | Yes | scheme profile id (for example `nostr_keypair_v1`) |
| `entitlement_ref` | string | Yes | scheme-specific public reference |
| `quantity` | integer | Yes | MUST be `1` in v2.0 |
| `price_sats` | integer | Yes | required settlement total in sats (Nostr profile of generic settlement-unit price) |
| `expiry` | string | Yes | ISO-8601 UTC |
| `redemption_provider` | string | No | endpoint, `npub`, or provider locator |
| `provider_commitment` | string | No | optional hash commitment to provider metadata |
| `hash_alg` | string | Yes | `sha256` for v2.0 |
| `commitment_hash` | string | Yes | full hex digest |
| `settlement_method` | string | Yes | default `nip57_zap_v1` |
| `ask_id` | string | Yes | deterministic identifier |

### 5.1 Compatibility Profile: `nostr_keypair_v1`

For compatibility with existing deployments:

- `entitlement_ref` is `npub1...`
- `entitlement_secret` is `nsec1...`
- commitment bytes are raw private key bytes `sk_i`
- `commitment_hash = sha256(sk_i)`

Legacy mapping:

- previous `capability_ref` maps directly to `entitlement_ref`
- previous `capability_secret` maps directly to `entitlement_secret`

---

## 6. Deterministic Order Binding

Canonical `order_details` object:

```json
{
  "entitlement_scheme": "nostr_keypair_v1",
  "entitlement_ref": "<npub_i>",
  "quantity": 1,
  "price_sats": 21,
  "expiry": "2026-03-31T23:59:59Z",
  "redemption_provider": "npub1...",
  "settlement_method": "nip57_zap_v1"
}
```

Canonical ask id:

`ask_id = sha256(issuer_pubkey || canonical_json(order_details) || commitment_hash)`

Requirements:

- `canonical_json` MUST use RFC 8785 JCS.
- `commitment_hash` MUST be full digest (64 hex chars for sha256).
- order validation MUST fail if recomputed `ask_id` does not match published `ask_id`.
- `redemption_provider` MAY be omitted from public order content.
- if provider immutability is required while hidden, `provider_commitment` SHOULD be present.

---

## 7. Primitive Lifecycle

### 7.1 Entitlement Issuance

Provider/seller prepares entitlement records and, for each entitlement:

- generates `entitlement_ref_i` and `entitlement_secret_i` per `entitlement_scheme`
- derives commitment bytes from `entitlement_secret_i`
- computes `commitment_hash_i`
- stores provider mapping for redemption resolution

### 7.2 Order Publication

Seller constructs `order_details`, computes `ask_id`, and publishes order event containing:

- `ask_id`
- `issuer_pubkey`
- `order_details`
- `hash_alg`
- `commitment_hash`

`entitlement_secret` MUST NOT be published in public events.

### 7.3 Trade Settlement

Buyer settles according to `settlement_method`.

For `nip57_zap_v1`:

- buyers zap the ask event id
- seller aggregates receipts by sender identity

Winner policy:

- `required_amount = price_sats`
- sender is eligible if `sum(sender_settlements) >= required_amount`
- first eligible sender wins
- tie-break in same processing window MUST be deterministic and documented
- at or after `expiry`, order is closed
- partial payments from non-winning participants do not create a trade
- zap receipts SHOULD be retained as settlement evidence

### 7.4 Secret Delivery and Verification

On successful trade:

- seller privately delivers `entitlement_secret` to winner
- seller SHOULD include `redemption_provider` if omitted from public order

Buyer MUST verify:

- secret-derived commitment hash equals published `commitment_hash`
- recomputed `ask_id` equals published `ask_id`

### 7.5 Redemption and Spend Enforcement

Buyer submits redemption request using `entitlement_ref` and scheme proof-of-control.

Provider:

- verifies challenge response
- checks entitlement is unspent
- delivers service/resource if valid
- marks entitlement spent

Further redemption attempts for same entitlement MUST fail.

---

## 8. Accountability Boundary

Seller is accountable for:

- order correctness and deterministic binding
- settlement observation and winner selection
- delivery of correct entitlement secret

Redemption provider is accountable for:

- entitlement mapping integrity
- proof verification correctness
- single-use enforcement
- downstream service release behavior

---

## 9. Security and Guardrails

- Seller MUST use fresh entitlement material per traded unit.
- Commitment hash MUST be computed from secret-derived bytes only.
- Full `commitment_hash` is authoritative; shortened display values are non-authoritative.
- Seller MUST NOT leak `entitlement_secret` in public channels.
- Provider MUST reject already-spent entitlements.
- Implementations SHOULD persist auditable evidence for order, trade, and redemption events.
- Tie-break and overpayment policy MUST be deterministic and documented.

---

## 10. Conformance Cases

| Test ID | Class | Requirement | Pass Criteria |
|---------|-------|-------------|---------------|
| `TC-MS02-001` | Seller | Fresh entitlement material | unique `entitlement_ref` per unit |
| `TC-MS02-002` | Seller | Commitment publication | order includes full `commitment_hash` |
| `TC-MS02-003` | Seller | Ask determinism | recomputed `ask_id` equals published |
| `TC-MS02-004` | Seller | Winner policy | deterministic winner at threshold |
| `TC-MS02-005` | Seller | Expiry enforcement | no new winner after `expiry` |
| `TC-MS02-006` | Buyer | Secret verification | delivered secret matches commitment |
| `TC-MS02-007` | Provider | Challenge verification | invalid proofs rejected |
| `TC-MS02-008` | Provider | Single-use enforcement | second redemption attempt fails |

---

## 11. Example Order Content (Kind-1)

```text
ASK #MS02
entitlement_scheme=nostr_keypair_v1
entitlement_ref=npub1...
quantity=1
price_sats=21
expiry=2026-03-31T23:59:59Z
settlement_method=nip57_zap_v1
hash_alg=sha256
commitment_hash=7f3a9c2d41b8d4479c31c6f3a4b7a1e1d0f9d8c7b6a5e4d3c2b1a09182736455
ask_id=5f13...
partial_payment_policy=non_refundable
#MS02 #entitlement
```

---

## 12. Revision History

| Version | Date | Notes |
|---------|------|-------|
| `1.0` | 2026-03-05 | Initial hash-committed capability market draft. |
| `1.1` | 2026-03-05 | Genericized scheme/profile model and deterministic ask binding clarifications. |
| `2.0` | 2026-03-07 | Reframed market using four core primitives (`Entitlement`, `Order`, `Trade`, `Redemption`) and replaced capability terminology with entitlement terminology. |
