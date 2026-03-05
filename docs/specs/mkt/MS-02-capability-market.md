# MS-02: Hash-Committed Capability Market
**Version**: `1.0`  
**Status**: Draft  
**Tag**: `#MS02`  
**Market Namespace**: `mkt=MS-02`  
**Date**: 2026-03-05

---

## 1. Purpose

Define a market model for selling single-use service entitlements as hash-committed capabilities over Nostr with Lightning zap settlement.

This specification separates:

- market execution (ask publication and buyer competition)
- payment settlement (zap aggregation and winner selection)
- redemption execution (provider-side challenge/response and one-time use)

---

## 1.1 Scope

MS-02 defines:

- capability creation and ask publication
- deterministic ask binding using commitment hash
- zap-based settlement and winner policy
- secret (`nsec`) delivery and buyer verification
- redemption provider obligations and single-use enforcement

MS-02 does not define:

- custody guarantees or escrow
- protocol-level refund enforcement for partial payments
- downstream service API schema for entitlement consumption

---

## 1.2 Normative Language

The key words `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` in this document are to be interpreted as described in RFC 2119 and RFC 8174.

---

## 2. Roles

| Role | Responsibility |
|------|----------------|
| **Selling Agent** | Publish asks, observe zaps, select winner per rule, deliver committed `nsec` |
| **Redemption Provider** | Map redemption `npub` to entitlement, verify signatures, release service, enforce one-time redemption |
| **Buyer** | Zap ask, verify delivered capability against commitment, redeem entitlement |

---

## 3. Terminology

| Term | Definition |
|------|------------|
| **Capability** | Single-use bearer redemption credential |
| **Redemption Keypair** | Fresh Nostr keypair generated for one entitlement |
| **Commitment Hash** | `sha256(sk_i)` over raw private key bytes |
| **Ask** | Sell-side market order offering one capability |
| **Ask ID** | Deterministic id binding issuer + order details + commitment |

---

## 4. Data Model

| Field | Type | Required | Notes |
|------|------|----------|------|
| `market` | string | Yes | `MS-02` |
| `instrument` | string | Yes | `service_entitlement` |
| `issuer_pubkey` | string | Yes | seller pubkey hex |
| `npub` | string | Yes | redemption public key (`npub1...`) |
| `quantity` | integer | Yes | typically `1` |
| `price_sats` | integer | Yes | required zap total |
| `expiry` | string | Yes | ISO-8601 UTC |
| `hash_alg` | string | Yes | `sha256` |
| `commitment_hash` | string | Yes | `sha256(sk_i)` hex |
| `ask_id` | string | Yes | deterministic identifier |

---

## 5. Deterministic Ask Binding

Canonical `order_details` object:

```json
{
  "instrument": "service_entitlement",
  "npub": "<npub_i>",
  "quantity": 1,
  "price_sats": 21,
  "expiry": "2026-03-31T23:59:59Z"
}
```

Canonical ask id:

`ask_id = sha256(issuer_pubkey || canonical_json(order_details) || commitment_hash)`

Requirements:

- `canonical_json` MUST use stable key order and deterministic UTF-8 serialization.
- `commitment_hash` MUST be full hex digest (64 chars).
- Ask validation MUST fail if recomputed `ask_id` mismatches published `ask_id`.

---

## 6. Protocol Flow

### 6.1 Prepare Entitlements

Provider prepares service unlock records (`s_i`) for resources (compute, API access, inference tokens, storage, etc.).

### 6.2 Create Redemption Capabilities

For each entitlement:

- generate fresh keypair: `sk_i`, `pk_i`
- encode: `nsec_i`, `npub_i`
- compute: `commitment_hash_i = sha256(sk_i)`
- store provider mapping: `npub_i -> entitlement s_i`

### 6.3 Construct Ask

Seller constructs order fields and computes `ask_id` per Section 5.

### 6.4 Publish Ask

Seller publishes ask event with:

- `ask_id`
- `issuer_pubkey`
- `order_details`
- `hash_alg=sha256`
- `commitment_hash`

Private key material (`sk_i`, `nsec_i`) MUST NOT appear in public content.

### 6.5 Buyer Zaps Ask

Buyers zap ask event id.
Seller observes zap receipts and groups totals by sender identity (`zapper_pubkey`).

### 6.6 Settlement and Competing Buyers

Let `required_amount = price_sats`.

Rules:

- If `sum(sender_zaps) == required_amount`, sender wins and settlement is complete.
- If `sum(sender_zaps) < required_amount`, seller MAY wait for more zaps from same sender.
- If another sender reaches `required_amount` first, first complete sender wins.
- At or after `expiry`, ask MUST be treated as closed with no new winner.

Policy note:

- Partial payment refund behavior is implementation policy; if no refund policy exists, this MUST be disclosed in ask content.
- Due to the atomic and microtransaction nature of this protocol, partial order fulfillment is not prohibited, but is strongly discouraged.
- If zaps are received from multiple competing buyers, refund or non-refund behavior is at seller discretion.
- Seller refund behavior is a policy decision; implementations are RECOMMENDED to avoid refunds by default to reduce griefing surface.

### 6.7 Secret Delivery

On successful settlement, seller delivers `nsec_i` privately to winning buyer (DM or secure equivalent).

### 6.8 Buyer Verification

Buyer verifies:

- `sha256(sk_i) == commitment_hash`
- recomputed `ask_id` matches published `ask_id`

### 6.9 Redemption

Buyer presents `npub_i` to provider.
Provider issues challenge; buyer signs with `sk_i`; provider verifies signature.
If valid and unused, provider releases entitlement.

### 6.10 Single-Use Enforcement

Provider marks redemption spent:

`npub_i -> spent`

Further redemption attempts MUST fail.

---

## 7. Accountability Boundary

Selling Agent is accountable for:

- ask correctness and commitment publication
- payment detection and winner selection per policy
- delivery of committed capability (`nsec`)

Redemption Provider is accountable for:

- entitlement mapping integrity (`npub -> entitlement`)
- challenge verification correctness
- one-time redemption enforcement
- downstream service release behavior

---

## 8. Security and Guardrails

- Seller MUST use fresh keypairs per entitlement (no key reuse).
- Commitment hash MUST be computed from private key material only.
- Full `commitment_hash` MUST be authoritative; truncated display hashes are non-authoritative.
- Seller MUST NOT publish `nsec` in public Nostr posts.
- Provider MUST reject already-spent capabilities.
- Implementations SHOULD log settlement and redemption evidence with event ids for audit.

---

## 9. Conformance Cases

| Test ID | Class | Requirement | Pass Criteria |
|---------|-------|-------------|---------------|
| `TC-MS02-001` | Seller | Fresh capability keypair | unique `npub` per entitlement |
| `TC-MS02-002` | Seller | Commitment publication | ask includes full `commitment_hash` |
| `TC-MS02-003` | Seller | Ask determinism | recomputed `ask_id` equals published |
| `TC-MS02-004` | Seller | Winner selection | first sender reaching required amount wins |
| `TC-MS02-005` | Seller | Expiry enforcement | no settlement after `expiry` |
| `TC-MS02-006` | Buyer | Capability verification | delivered `nsec` matches commitment |
| `TC-MS02-007` | Provider | Signature challenge | invalid signatures rejected |
| `TC-MS02-008` | Provider | Single-use enforcement | second redemption attempt fails |

---

## 10. Example Ask Content (Kind-1)

```text
ASK #MS02
instrument=service_entitlement
npub=npub1...
quantity=1
price_sats=21
expiry=2026-03-31T23:59:59Z
hash_alg=sha256
commitment_hash=7f3a9c2d41b8d4479c31c6f3a4b7a1e1d0f9d8c7b6a5e4d3c2b1a09182736455
ask_id=5f13...
partial_payment_policy=non_refundable
#MS02 #capability
```

---

## 11. Revision History

| Version | Date | Notes |
|---------|------|-------|
| `1.0` | 2026-03-05 | Initial draft of capability market model with hash-committed redemption keys and zap settlement lifecycle. |
