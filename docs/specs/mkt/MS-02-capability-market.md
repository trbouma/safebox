# MS-02: Hash-Committed Capability Market
**Version**: `1.1`  
**Status**: Draft  
**Tag**: `#MS02`  
**Market Namespace**: `mkt=MS-02`  
**Date**: 2026-03-05

---

## 1. Purpose

Define a generic market model for selling single-use service entitlements as hash-committed capabilities over Nostr with zap settlement.

This specification separates:

- market execution (ask publication and buyer competition)
- payment settlement (receipt aggregation and winner selection)
- capability delivery and buyer verification
- redemption execution (provider-side challenge/response and one-time use)

---

## 1.1 Scope

MS-02 defines:

- capability creation and ask publication
- deterministic ask binding using commitment hash
- settlement and winner policy
- secret delivery and buyer verification
- provider obligations for one-time redemption

MS-02 does not define:

- custody guarantees or escrow
- protocol-level refund enforcement for partial payments
- downstream service API schema for entitlement consumption
- concrete redemption endpoint design (provider-local concern)

---

## 1.2 Normative Language

The key words `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` in this document are to be interpreted as described in RFC 2119 and RFC 8174.

---

## 2. Roles

| Role | Responsibility |
|------|----------------|
| **Selling Agent** | Publish asks, observe settlement signals, select winner per rule, deliver committed capability secret |
| **Redemption Provider** | Map capability reference to entitlement, verify proof-of-control, release service, enforce one-time redemption |
| **Buyer** | Settle ask, verify delivered capability against commitment, redeem entitlement |

---

## 3. Terminology

| Term | Definition |
|------|------------|
| **Capability** | Single-use bearer redemption credential |
| **Capability Scheme** | Concrete representation/profile for references, secrets, and verification |
| **Capability Reference** | Public capability locator/identifier for redemption |
| **Capability Secret** | Private material delivered to winning buyer |
| **Commitment Hash** | Hash over canonical commitment bytes derived from capability secret |
| **Ask** | Sell-side market order offering one capability |
| **Ask ID** | Deterministic id binding issuer + order details + commitment |

---

## 4. Data Model

| Field | Type | Required | Notes |
|------|------|----------|------|
| `market` | string | Yes | `MS-02` |
| `instrument` | string | Yes | default `service_entitlement`; extensible |
| `issuer_pubkey` | string | Yes | seller pubkey hex |
| `capability_scheme` | string | Yes | e.g. `nostr_keypair_v1` |
| `capability_ref` | string | Yes | scheme-specific public reference |
| `quantity` | integer | Yes | typically `1` |
| `price_sats` | integer | Yes | required settlement total |
| `expiry` | string | Yes | ISO-8601 UTC |
| `redemption_provider` | string | No | provider endpoint, `npub`, or provider-defined locator; optional in public ask |
| `provider_commitment` | string | No | optional binding commitment for provider locator |
| `hash_alg` | string | Yes | `sha256` for v1.1 |
| `commitment_hash` | string | Yes | hash over canonical commitment bytes |
| `ask_id` | string | Yes | deterministic identifier |
| `settlement_method` | string | Yes | default `nip57_zap_v1` |

### 4.1 Compatibility Profile: `nostr_keypair_v1`

For compatibility with existing deployments:

- `capability_ref` is `npub1...`
- `capability_secret` delivery value is `nsec1...`
- commitment bytes are raw private key bytes `sk_i`
- `commitment_hash = sha256(sk_i)`

Legacy field mapping:

- legacy `npub` is equivalent to `capability_ref` under `nostr_keypair_v1`

---

## 5. Deterministic Ask Binding

Canonical `order_details` object:

```json
{
  "instrument": "service_entitlement",
  "capability_scheme": "nostr_keypair_v1",
  "capability_ref": "<npub_i>",
  "quantity": 1,
  "price_sats": 21,
  "expiry": "2026-03-31T23:59:59Z",
  "redemption_provider": "npub1...",
  "settlement_method": "nip57_zap_v1"
}
```

`redemption_provider` is OPTIONAL in public `order_details`.

Canonical ask id:

`ask_id = sha256(issuer_pubkey || canonical_json(order_details) || commitment_hash)`

Requirements:

- `canonical_json` MUST use RFC 8785 JSON Canonicalization Scheme (JCS).
- `commitment_hash` MUST be full hex digest (64 chars for sha256).
- Ask validation MUST fail if recomputed `ask_id` mismatches published `ask_id`.
- `redemption_provider` MAY be omitted from `order_details` for privacy/security.
- If `redemption_provider` is omitted and provider immutability is required, `provider_commitment` SHOULD be present.

---

## 6. Protocol Flow

### 6.1 Prepare Entitlements

Provider prepares service unlock records (`s_i`) for resources (compute, API access, inference tokens, storage, etc.).

### 6.2 Create Redemption Capabilities

For each entitlement:

- generate capability material per selected `capability_scheme`
- derive public reference `capability_ref_i`
- derive private secret `capability_secret_i`
- derive commitment bytes from secret per scheme
- compute: `commitment_hash_i = hash(commitment_bytes_i)`
- store provider mapping: `capability_ref_i -> entitlement s_i`

### 6.3 Construct Ask

Seller constructs order fields and computes `ask_id` per Section 5.

### 6.4 Publish Ask

Seller publishes ask event with:

- `ask_id`
- `issuer_pubkey`
- `order_details`
- `hash_alg`
- `commitment_hash`

Private secret material MUST NOT appear in public content.

### 6.5 Buyer Settlement Signal

Buyers settle against the ask according to `settlement_method`.

For `nip57_zap_v1`, buyers zap ask event id and seller groups receipts by sender identity.

### 6.6 Settlement and Competing Buyers

Let `required_amount = price_sats`.

Rules:

- If `sum(sender_settlements) >= required_amount`, sender is eligible to win.
- First sender to reach or exceed `required_amount` wins.
- If multiple sender receipts cross in the same processing window, deterministic tie-break MUST be defined and documented (RECOMMENDED: earliest receipt `created_at`, then lexicographic `receipt_id`).
- At or after `expiry`, ask MUST be treated as closed with no new winner.

Policy note:

- Partial payment refund behavior is implementation policy; if no refund policy exists, this MUST be disclosed in ask content.
- Due to the atomic and microtransaction nature of this protocol, partial order fulfillment is not prohibited, but is strongly discouraged.
- If settlements are received from multiple competing buyers, refund or non-refund behavior is at seller discretion.
- Seller refund behavior is a policy decision; implementations are RECOMMENDED to avoid refunds by default to reduce griefing surface.

### 6.7 Secret Delivery

On successful settlement, seller delivers `capability_secret_i` privately to winning buyer (DM or secure equivalent).

Delivery payload SHOULD include:

- `capability_scheme` (required)
- `capability_secret` (required)
- `redemption_provider` (required unless already disclosed in public `order_details`)
- `provider_hint` (optional provider-defined metadata)

If `redemption_provider` is intentionally omitted from public ask content for privacy/security reasons, seller MUST include it in secret delivery to enable redemption.

### 6.8 Buyer Verification

Buyer verifies:

- scheme-specific commitment verification produces published `commitment_hash`
- recomputed `ask_id` matches published `ask_id`

### 6.9 Redemption

Buyer presents `capability_ref_i` to provider.
Provider issues challenge; buyer proves control using scheme-specific method.
If valid and unused, provider releases entitlement.

### 6.10 Single-Use Enforcement

Provider marks redemption spent:

`capability_ref_i -> spent`

Further redemption attempts MUST fail.

---

## 7. Accountability Boundary

Selling Agent is accountable for:

- ask correctness and commitment publication
- settlement detection and winner selection per policy
- delivery of committed capability secret

Redemption Provider is accountable for:

- entitlement mapping integrity (`capability_ref -> entitlement`)
- proof-of-control verification correctness
- one-time redemption enforcement
- downstream service release behavior

---

## 8. Security and Guardrails

- Seller MUST use fresh capabilities per entitlement (no secret reuse).
- Commitment hash MUST be computed from secret-derived commitment bytes only.
- Full `commitment_hash` MUST be authoritative; truncated display hashes are non-authoritative.
- Seller MUST NOT publish capability secret in public Nostr posts.
- Provider MUST reject already-spent capabilities.
- Implementations SHOULD log settlement and redemption evidence with event ids for audit.
- Tie-break and overpayment handling policy MUST be deterministic and documented.

---

## 9. Conformance Cases

| Test ID | Class | Requirement | Pass Criteria |
|---------|-------|-------------|---------------|
| `TC-MS02-001` | Seller | Fresh capability material | unique `capability_ref` per entitlement |
| `TC-MS02-002` | Seller | Commitment publication | ask includes full `commitment_hash` |
| `TC-MS02-003` | Seller | Ask determinism | recomputed `ask_id` equals published |
| `TC-MS02-004` | Seller | Winner selection | first sender reaching required amount wins |
| `TC-MS02-005` | Seller | Expiry enforcement | no settlement after `expiry` |
| `TC-MS02-006` | Buyer | Capability verification | delivered secret matches commitment |
| `TC-MS02-007` | Provider | Challenge verification | invalid proofs rejected |
| `TC-MS02-008` | Provider | Single-use enforcement | second redemption attempt fails |

---

## 10. Example Ask Content (Kind-1, `nostr_keypair_v1` profile)

```text
ASK #MS02
instrument=service_entitlement
capability_scheme=nostr_keypair_v1
capability_ref=npub1...
quantity=1
price_sats=21
expiry=2026-03-31T23:59:59Z
settlement_method=nip57_zap_v1
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
| `1.1` | 2026-03-05 | Genericized capability model (`capability_scheme`, `capability_ref`, `capability_secret`), standardized canonical JSON (RFC 8785), clarified settlement tie-break/overpay semantics, and kept `nostr_keypair_v1` compatibility profile. |
