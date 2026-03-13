# MS-02: Hash-Committed Entitlement Market
**Version**: `2.5`
**Status**: Draft  
**Tag**: `#MS02`  
**Market Namespace**: `mkt=MS-02`  
**Date**: 2026-03-12

---

## 1. Purpose

Define a generic market protocol for trading hash-committed service entitlements with deterministic settlement and verifiable fulfillment.

MS-02 is the generic entitlement market base.

Nostr is the first transport and settlement profile for this market family, not the market model itself.

This specification uses five market primitives:

1. `Entitlement`
2. `Order`
3. `Clearing`
4. `Trade`
5. `Fulfillment`

These primitives define the full lifecycle from issuance through final service delivery.

## 1.1 Scope

MS-02 defines:

- underlying entitlement creation and wrapper binding
- wrapper commitment binding
- optional sealed entitlement encryption for direct buyer-side recovery
- order publication and deterministic ask identity
- clearing and winner selection
- trade formation and wrapper-secret delivery
- wrapper-secret verification
- either:
  - redemption proof-of-control and single-use enforcement against the wrapped entitlement, or
  - buyer-side decryption of sealed entitlement material after successful trade

MS-02 does not define:

- escrow/custody guarantees
- mandatory refund enforcement
- downstream service API schemas
- concrete redemption HTTP endpoint contracts

---

## 1.2 Normative Language

The key words `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` are to be interpreted as described in RFC 2119 and RFC 8174.

---

## 1.3 Historical Parallel (Non-Normative)

MS-02 follows the same economic pattern as historical redeemable-claim instruments, including:

- bills of exchange
- warehouse receipts
- bearer bonds

In each case, the traded object is the redeemable claim, not the underlying asset/service itself.
MS-02 applies this model using cryptographic commitments and digital settlement rails rather than paper instruments.

---

## 2. Roles

| Role | Responsibility |
|------|----------------|
| **Entitlement Provider** | Creates the underlying entitlement material, binds it into a trading wrapper, and ensures redemption can resolve to the promised underlying entitlement |
| **Market Seller** | Publishes orders, observes settlement evidence, applies clearing policy, selects winner, and delivers wrapper secret |
| **Market Buyer** | Settles an order, verifies delivered wrapper secret against commitment, and MAY redeem or re-sell the wrapped entitlement |
| **Redemption Provider** | Verifies redemption proof, resolves wrapper-to-entitlement binding, releases service/resource, enforces one-time redemption |

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

An entitlement is a claim, not a specific credential format.

Implementations MUST define how the claim is bound to a trading wrapper.

In the generic model, an entitlement has:

- provider-defined underlying entitlement material
- a wrapper reference usable during redemption
- a wrapper secret or equivalent proof material
- a wrapper commitment over canonical wrapper-and-entitlement commitment bytes

The compatibility profile `nostr_keypair_v1` realizes this model using a Nostr keypair as the first trading wrapper profile.

Where:

- the provider may maintain native entitlement material such as `entitlement_code` and `entitlement_secret`
- `npub_i` identifies the wrapper handle (`wrapper_ref` in `nostr_keypair_v1`)
- `sk_i` is the private wrapper secret (`wrapper_secret` in `nostr_keypair_v1`)
- `h_i` is the wrapper commitment (`wrapper_commitment`) that locks wrapper control and underlying entitlement binding until settlement-time secret delivery

Ownership/control transfer occurs when `sk_i` is delivered to the winning market buyer and verified against `h_i`.

The wrapped underlying entitlement MUST remain immutably bound to the wrapper once the order is published.

### 3.2 Order

An `Order` is a public sell intent for exactly one wrapped entitlement unit.

An order binds price/expiry metadata to a wrapper commitment and is identified by deterministic `ask_id`.

Order parameters include:

- wrapper reference and scheme
- fulfillment mode
- quantity (v2.0 fixed at `1`)
- price and settlement method
- expiry
- optional redemption provider metadata/commitment
- optional encrypted entitlement payload
- wrapper commitment and deterministic ask identifier

### 3.3 Clearing

A `Clearing` step determines whether settlement evidence is sufficient to form a binding trade obligation for a specific market buyer.

Clearing is the transition from:

- public order intent
- observed settlement evidence

to:

- one winning market buyer identity
- one market seller delivery obligation
- closure of competing claims for the same entitlement unit

For `nip57_zap_v1` settlement:

- market buyers send zaps referencing the order event
- market seller aggregates settled zap receipts by canonical market buyer identity
- a market buyer becomes eligible when aggregate settled receipts satisfy `price_sats`
- the first eligible market buyer under the published tie-break rule clears the order

At or after `expiry`, the order MUST be treated as closed for new clearing decisions.

Partial payments from non-winning participants MAY remain non-refundable if that is the published order policy, but they MUST NOT create a trade claim by themselves.

### 3.4 Trade

A `Trade` is the settlement outcome for an order.

A trade exists only after clearing identifies a winning market buyer and binds the market seller to delivery of the wrapper secret.

For `nip57_zap_v1` settlement:

- clearing uses settled zap receipts as evidence
- the cleared market buyer is the canonical buyer identity selected by the market seller's published winner policy

Zap receipts are treated as settlement evidence because they are emitted only after payment clears on the payment rail.

After settlement, the market seller transfers control of the wrapped entitlement by revealing `sk_i` (the `wrapper_secret`) to the winning market buyer.

### 3.5 Fulfillment

A `Fulfillment` step converts a successfully traded wrapper into usable entitlement value.

MS-02 defines two fulfillment modes:

1. `provider_resolved_v1`
2. `buyer_decryptable_v1`

For `provider_resolved_v1`, fulfillment is provider-side challenge/response redemption:

1. Market buyer presents `npub_i` (`wrapper_ref`)
2. Redemption provider issues challenge
3. Market buyer signs challenge with `sk_i` (`wrapper_secret`)
4. Provider verifies signature/proof-of-control
5. Provider resolves the wrapper binding and releases the underlying service

A successful `provider_resolved_v1` redemption MUST consume entitlement spend state.

For `buyer_decryptable_v1`, fulfillment is direct buyer-side recovery of the sealed underlying entitlement:

1. Market seller publishes `encrypted_entitlement`
2. Market buyer receives `wrapper_secret`
3. Market buyer derives the profile-defined decryption key from `wrapper_secret`
4. Market buyer decrypts `encrypted_entitlement`
5. Market buyer recovers `entitlement_code` and `entitlement_secret` locally

`buyer_decryptable_v1` eliminates the requirement for a redemption provider, but it does not by itself provide provider-side single-use enforcement. Implementations using this mode MUST document how replay, reuse, or downstream redemption uniqueness is controlled.

---

## 4. Terminology

| Term | Definition |
|------|------------|
| **Wrapper Reference** | Public identifier/locator traded in the market and presented at redemption (`wrapper_ref`) |
| **Wrapper Secret** | Private secret delivered to winning market buyer (`wrapper_secret`) |
| **Underlying Entitlement** | Provider-native claim material bound behind the trading wrapper |
| **Wrapper Commitment** | Hash over canonical wrapper-and-entitlement commitment bytes |
| **Fulfillment Mode** | Mechanism by which a winning market buyer obtains usable entitlement value after trade |
| **Encrypted Entitlement** | Sealed ciphertext containing `entitlement_code` and `entitlement_secret` for buyer-side recovery |
| **Order Details** | Canonical JSON object describing traded unit and settlement policy |
| **Ask ID** | Deterministic identifier over issuer + canonical order details + wrapper commitment |
| **Clearing** | Determination that specific settlement evidence forms a binding trade with one market buyer |
| **Trade Winner** | Market buyer identity selected after settlement policy evaluation |
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

### 4.2 Alignment with MS-00

MS-02 is a tokenized market in the `MS-00` sense, but its canonical execution unit is one entitlement.

For cross-market comparability:

- `quote_unit` SHOULD be `SAT_PER_TOKEN`
- `effective_price_sats_per_token` SHOULD equal `price_sats` when `quantity = 1`
- `token_definition` SHOULD describe what one entitlement redeems
- `token_basis` SHOULD be `REDEMPTION_UNIT`

MS-02 keeps `price_sats` as the core market field because the entitlement unit is fixed at one in v2.0.

---

## 5. Data Model

| Field | Type | Required | Notes |
|------|------|----------|------|
| `market` | string | Yes | `MS-02` |
| `issuer_pubkey` | string | Yes | market seller pubkey hex |
| `wrapper_scheme` | string | Yes | wrapper profile id (for example `nostr_keypair_v1`) |
| `fulfillment_mode` | string | Yes | `provider_resolved_v1` or `buyer_decryptable_v1` |
| `wrapper_ref` | string | Yes | scheme-specific public wrapper reference |
| `quantity` | integer | Yes | MUST be `1` in v2.0 |
| `price_sats` | integer | Yes | required settlement total in sats (Nostr profile of generic settlement-unit price) |
| `expiry` | string | Yes | ISO-8601 UTC |
| `redemption_provider` | string | No | endpoint, `npub`, or provider locator |
| `provider_commitment` | string | No | optional hash commitment to provider metadata |
| `encrypted_entitlement` | string | No | required for `buyer_decryptable_v1`; omitted for `provider_resolved_v1` unless dual-mode |
| `hash_alg` | string | Yes | `sha256` for v2.0 |
| `wrapper_commitment` | string | Yes | full hex digest |
| `settlement_method` | string | Yes | default `nip57_zap_v1` |
| `partial_payment_policy` | string | No | for example `non_refundable`, `seller_discretion`, `refundable` |
| `tie_break_policy` | string | No | deterministic winner policy description |
| `ask_id` | string | Yes | deterministic identifier |

### 5.1 Compatibility Profile: `nostr_keypair_v1`

`nostr_keypair_v1` is the first compatibility profile for MS-02.

For this profile:

- `wrapper_ref` is `npub1...`
- `wrapper_secret` is the raw private key material `sk_i`
- `nsec1...` is the encoded delivery form of `wrapper_secret`
- canonical commitment bytes MUST bind:
  - wrapper secret bytes `sk_i`
  - `entitlement_code`
  - `entitlement_secret`
- recommended derivation:

```text
wrapper_commitment = sha256(
  canonical_json({
    "wrapper_scheme": "nostr_keypair_v1",
    "wrapper_secret_hex": hex(sk_i),
    "entitlement_code": entitlement_code,
    "entitlement_secret": entitlement_secret
  })
)
```

- the underlying entitlement remains provider-defined and is bound behind the wrapper

Legacy mapping:

- previous `capability_ref` maps directly to `wrapper_ref`
- previous `capability_secret` maps directly to `wrapper_secret`

### 5.2 Fulfillment Profile: `buyer_decryptable_v1`

`buyer_decryptable_v1` is an optional fulfillment profile for direct sealed delivery.

Requirements:

- `encrypted_entitlement` MUST contain the sealed underlying entitlement material
- the decryption key MUST be derivable only from the delivered `wrapper_secret` and profile-defined context
- the published `wrapper_commitment` MUST still bind:
  - `wrapper_secret`
  - `entitlement_code`
  - `entitlement_secret`
- implementations SHOULD use authenticated encryption over canonical entitlement bytes

Recommended derivation:

```text
K = HKDF(sk_i, "MS02|buyer_decryptable_v1|entitlement")
encrypted_entitlement = AEAD_Encrypt(
  K,
  canonical_json({
    "entitlement_code": entitlement_code,
    "entitlement_secret": entitlement_secret
  })
)
```

If `buyer_decryptable_v1` is used, `redemption_provider` MAY be omitted.

---

## 6. Deterministic Order Binding

Canonical `order_details` object:

```json
{
  "wrapper_scheme": "nostr_keypair_v1",
  "fulfillment_mode": "provider_resolved_v1",
  "wrapper_ref": "<npub_i>",
  "quantity": 1,
  "price_sats": 21,
  "expiry": "2026-03-31T23:59:59Z",
  "redemption_provider": "npub1...",
  "settlement_method": "nip57_zap_v1",
  "partial_payment_policy": "non_refundable",
  "tie_break_policy": "first_cleared_by_seller_observation"
}
```

Canonical ask id:

`ask_id = sha256(issuer_pubkey || canonical_json(order_details) || wrapper_commitment)`

Requirements:

- `canonical_json` MUST use RFC 8785 JCS.
- `wrapper_commitment` MUST be full digest (64 hex chars for sha256).
- order validation MUST fail if recomputed `ask_id` does not match published `ask_id`.
- `encrypted_entitlement` MUST be present when `fulfillment_mode = buyer_decryptable_v1`.
- `redemption_provider` MAY be omitted from public order content.
- `redemption_provider` SHOULD be present when `fulfillment_mode = provider_resolved_v1`.
- if provider immutability is required while hidden, `provider_commitment` SHOULD be present.
- if `partial_payment_policy` is omitted, implementations MUST define and document the default policy.
- if `tie_break_policy` is omitted, implementations MUST define and document the default deterministic policy.

---

## 7. Primitive Lifecycle

### 7.1 Entitlement Issuance

Entitlement provider and market seller prepare the underlying entitlement records and, for each entitlement:

- generates or receives provider-native entitlement material
- generates `wrapper_ref_i` and `wrapper_secret_i` per `wrapper_scheme`
- derives canonical wrapper commitment bytes from:
  - `wrapper_secret_i`
  - `entitlement_code_i`
  - `entitlement_secret_i`
- computes `wrapper_commitment_i`
- if `fulfillment_mode = buyer_decryptable_v1`, encrypts the entitlement material into `encrypted_entitlement_i` before publication
- before publishing the trading wrapper together with its `wrapper_commitment`, stores a persistent internal redemption binding from the trading wrapper to the exact underlying entitlement being sold. For `nostr_keypair_v1`, this means binding `wrapper_ref` (`npub_i`) to the provider-native entitlement material (for example `entitlement_code` and `entitlement_secret`). This binding is not public. It exists so that, after a successful trade and private delivery of `wrapper_secret`, the market buyer can present `wrapper_ref`, prove control of `wrapper_secret`, and the provider can deterministically locate and release the correct underlying entitlement during redemption.

If `fulfillment_mode = buyer_decryptable_v1`, the provider-side redemption binding MAY be omitted because the market buyer will recover the entitlement material directly from `encrypted_entitlement`. In that case, the implementation MUST define how replay, double-use, or downstream redemption uniqueness is enforced.

### 7.2 Order Publication

Market seller constructs `order_details`, computes `ask_id`, and publishes order event containing:

- `ask_id`
- `issuer_pubkey`
- `order_details`
- `hash_alg`
- `wrapper_commitment`
- `fulfillment_mode`
- `encrypted_entitlement` when required by the fulfillment profile
- settlement policy metadata needed for deterministic clearing

`wrapper_secret` MUST NOT be published in public events.

The trading wrapper MUST NOT be published without the corresponding authoritative `wrapper_commitment`. The public publication unit is the wrapper reference bound to its wrapper commitment inside the order.

### 7.3 Clearing and Trade Formation

Market buyer settles according to `settlement_method`.

For `nip57_zap_v1`:

- market buyers zap the ask event id
- market seller aggregates receipts by canonical market buyer identity

Winner policy:

- `required_amount = price_sats`
- market buyer is eligible if `sum(buyer_settlements) >= required_amount`
- first eligible market buyer under `tie_break_policy` wins
- tie-break in same processing window MUST be deterministic and documented
- at or after `expiry`, order is closed
- partial payments from non-winning participants do not create a trade
- zap receipts SHOULD be retained as settlement evidence

Canonical market buyer identity for `nip57_zap_v1` MUST be derived from the zap payer pubkey carried by the settlement evidence used by the implementation. Implementations MUST document the exact extraction rule and use it consistently for aggregation, winner selection, and audit.

Once a winner is selected, a trade is formed and the market seller is obligated to deliver the correct wrapper secret for that order.

### 7.4 Secret Delivery and Verification

On successful trade:

- market seller privately delivers `wrapper_secret` to winner
- market seller SHOULD include `redemption_provider` if omitted from public order

Market buyer MUST verify:

- recomputed wrapper commitment equals published `wrapper_commitment`
- recomputed `ask_id` equals published `ask_id`

### 7.5 Fulfillment and Spend Enforcement

For `provider_resolved_v1`:

Market buyer submits redemption request using `wrapper_ref` and scheme proof-of-control.

Provider:

- verifies challenge response against the wrapper
- checks entitlement is unspent
- delivers service/resource if valid
- marks entitlement spent

Further redemption attempts for same entitlement MUST fail.

For `buyer_decryptable_v1`:

Market buyer derives the decryption key from `wrapper_secret`, decrypts `encrypted_entitlement`, and locally recovers:

- `entitlement_code`
- `entitlement_secret`

MS-02 does not impose a universal one-time enforcement mechanism for `buyer_decryptable_v1`. Implementations using this mode MUST document their replay and uniqueness guarantees separately.

---

## 8. Accountability Boundary

Market seller is accountable for:

- order correctness and deterministic binding
- settlement observation and winner selection
- delivery of correct wrapper secret

Redemption provider is accountable for:

- entitlement mapping integrity
- proof verification correctness
- single-use enforcement
- downstream service release behavior

When `buyer_decryptable_v1` is used, market seller is additionally accountable for:

- correct encryption of the underlying entitlement into `encrypted_entitlement`
- ensuring the delivered `wrapper_secret` decrypts the published ciphertext
- documenting the downstream uniqueness and replay model

---

## 9. Security and Guardrails

- Market seller MUST use a fresh trading wrapper per traded unit.
- Market seller MUST keep the underlying entitlement immutably bound to the published wrapper once the order is open.
- Market seller MUST define and consistently apply canonical market buyer identity extraction for settlement evidence.
- Wrapper commitment MUST be computed from canonical bytes that bind the wrapper secret and the underlying entitlement material.
- If `buyer_decryptable_v1` is used, `encrypted_entitlement` MUST decrypt successfully using only the delivered `wrapper_secret` and the documented profile derivation rules.
- Full `wrapper_commitment` is authoritative; shortened display values are non-authoritative.
- Market seller MUST NOT leak `wrapper_secret` in public channels.
- Provider MUST reject already-spent entitlements.
- Implementations SHOULD persist auditable evidence for order, trade, and redemption events.
- Tie-break and overpayment policy MUST be deterministic and documented.
- `buyer_decryptable_v1` SHOULD NOT be used where provider-side one-time redemption enforcement is a hard requirement unless an equivalent downstream uniqueness mechanism is defined.

---

## 10. Conformance Cases

| Test ID | Class | Requirement | Pass Criteria |
|---------|-------|-------------|---------------|
| `TC-MS02-001` | Market Seller | Fresh wrapper material | unique `wrapper_ref` per unit |
| `TC-MS02-002` | Market Seller | Commitment publication | order includes full `wrapper_commitment` |
| `TC-MS02-003` | Market Seller | Ask determinism | recomputed `ask_id` equals published |
| `TC-MS02-004` | Market Seller | Clearing policy | deterministic winner at threshold |
| `TC-MS02-005` | Market Seller | Expiry enforcement | no new winner after `expiry` |
| `TC-MS02-006` | Market Buyer | Wrapper verification | delivered wrapper secret matches commitment |
| `TC-MS02-007` | Provider | Challenge verification | invalid proofs rejected |
| `TC-MS02-008` | Provider | Single-use enforcement | second redemption attempt fails |
| `TC-MS02-009` | Market Seller | Buyer identity rule | same settlement evidence yields same market buyer identity |
| `TC-MS02-010` | Market Seller | Buyer-decryptable fulfillment | delivered wrapper secret decrypts published encrypted entitlement |

---

## 11. Example Order Content (Kind-1)

```text
ASK #MS02
wrapper_scheme=nostr_keypair_v1
wrapper_ref=npub1...
quantity=1
price_sats=21
expiry=2026-03-31T23:59:59Z
settlement_method=nip57_zap_v1
hash_alg=sha256
wrapper_commitment=7f3a9c2d41b8d4479c31c6f3a4b7a1e1d0f9d8c7b6a5e4d3c2b1a09182736455
ask_id=5f13...
partial_payment_policy=non_refundable
tie_break_policy=first_cleared_by_seller_observation
#MS02 #entitlement
```

---

## 12. Revision History

| Version | Date | Notes |
|---------|------|-------|
| `1.0` | 2026-03-05 | Initial hash-committed capability market draft. |
| `1.1` | 2026-03-05 | Genericized scheme/profile model and deterministic ask binding clarifications. |
| `2.0` | 2026-03-07 | Reframed market using four core primitives (`Entitlement`, `Order`, `Trade`, `Redemption`) and replaced capability terminology with entitlement terminology. |
| `2.1` | 2026-03-12 | Reframed MS-02 as the generic entitlement market base, added explicit `Clearing` primitive, clarified profile separation, and aligned quote semantics with `MS-00`. |
| `2.2` | 2026-03-12 | Separated underlying entitlement from the traded wrapper credential, defined `wrapper_ref`/`wrapper_secret`, and clarified that `nostr_keypair_v1` is a wrapper profile over provider-native entitlement material. |
| `2.5` | 2026-03-12 | Added alternate `buyer_decryptable_v1` fulfillment mode with sealed entitlement delivery and documented its tradeoffs versus provider-resolved redemption. |
| `2.4` | 2026-03-12 | Normalized role terminology to `Entitlement Provider`, `Market Seller`, `Market Buyer`, and `Redemption Provider` across the base market model. |
| `2.3` | 2026-03-12 | Replaced `commitment_hash` with `wrapper_commitment` and defined it as binding both wrapper secret material and underlying entitlement material. |
