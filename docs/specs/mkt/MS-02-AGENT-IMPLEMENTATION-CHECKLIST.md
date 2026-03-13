# MS-02 Agent Implementation Checklist
**Spec Family**: `MS-02`  
**Version**: `1.0`  
**Status**: Draft  
**Date**: `2026-03-13`  
**Primary Spec**: `MS-02-entitlement-market.md`

---

## 1. Purpose

Provide a practical implementation checklist for building the Nostr-native agent capabilities required to support the `MS-02` entitlement market.

This document is implementation-oriented. The normative market rules remain in:

- `MS-02-entitlement-market.md`
- `MS-02-END-TO-END-SCENARIO.md`
- `MS-02-CONFORMANCE.md`

---

## 2. Build Order

Build in this order:

1. wrapper generation
2. entitlement input model
3. wrapper commitment derivation
4. ask construction
5. ask id derivation
6. ask publication
7. zap receipt retrieval
8. clearing engine
9. wrapper secret delivery
10. buyer verification
11. `buyer_decryptable_v1` sealed delivery
12. `provider_resolved_v1` redemption

This ordering gets a tradable market loop working before the stronger redemption-control features are added.

---

## 3. Core Data Model

The implementation needs to support two layers:

### 3.1 Underlying Entitlement

- `entitlement_code`
- `entitlement_secret`

These are provider-native values.

### 3.2 Trading Wrapper

For the first profile:

- `wrapper_scheme = nostr_keypair_v1`
- `wrapper_ref = npub_i`
- `wrapper_secret = sk_i`
- delivery form of `wrapper_secret` is `nsec_i`

### 3.3 Core Integrity Values

- `wrapper_commitment`
- `ask_id`

### 3.4 Optional Fulfillment Fields

For `buyer_decryptable_v1`:

- `fulfillment_mode = buyer_decryptable_v1`
- `sealed_delivery_alg = nip44_v2`
- `encrypted_entitlement`

For `provider_resolved_v1`:

- `fulfillment_mode = provider_resolved_v1`
- optional `redemption_provider`

---

## 4. Checklist

### 4.1 Wrapper Generation

Implement:

- fresh Nostr keypair generation
- derivation of:
  - `sk_i`
  - `pk_i`
  - `npub_i`
  - `nsec_i`

Acceptance:

- every unit gets a fresh wrapper
- `npub_i` is reproducible from `sk_i`
- `nsec_i` round-trips back to `sk_i`

### 4.2 Entitlement Input Model

Implement canonical handling for:

- `entitlement_code`
- `entitlement_secret`

Acceptance:

- provider-native entitlement data is represented in a stable internal structure
- inputs can be serialized consistently before commitment generation

### 4.3 Wrapper Commitment Derivation

Implement:

- RFC 8785 canonical JSON serialization
- wrapper commitment derivation:

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

Acceptance:

- same inputs always produce same `wrapper_commitment`
- changing any of:
  - `sk_i`
  - `entitlement_code`
  - `entitlement_secret`
  changes the commitment

### 4.4 Ask Construction

Implement deterministic order builder for:

- `market = MS-02`
- `wrapper_scheme`
- `fulfillment_mode`
- `wrapper_ref`
- `quantity = 1`
- `price_sats`
- `expiry`
- `settlement_method`
- optional:
  - `redemption_provider`
  - `sealed_delivery_alg`
  - `encrypted_entitlement`

Acceptance:

- order object is deterministic
- no mutable hidden values are needed after publication

### 4.5 Ask ID Derivation

Implement:

```text
ask_id = sha256(issuer_pubkey || canonical_json(order_details) || wrapper_commitment)
```

Acceptance:

- recomputation matches published `ask_id`
- any order-term mutation changes `ask_id`

### 4.6 Ask Publication

Implement Nostr ask publication containing:

- `ask_id`
- `wrapper_commitment`
- `order_details`

Acceptance:

- published event contains enough data for independent verification
- `wrapper_secret` is never published

### 4.7 Zap Receipt Retrieval

Implement:

- fetch zap receipts for ask event
- normalize receipt structure
- derive canonical market buyer identity consistently

Acceptance:

- same receipt set yields same buyer identities
- receipts can be grouped by canonical buyer identity

### 4.8 Clearing Engine

Implement:

- aggregation of settled receipts by canonical buyer identity
- threshold comparison against `price_sats`
- deterministic tie-break handling
- order close on expiry

Acceptance:

- one and only one winner is selected
- same evidence set yields same result
- no new winner after expiry

### 4.9 Wrapper Secret Delivery

Implement private delivery channel for winning buyer:

- likely Nostr DM / secure DM
- deliver `nsec_i`

Acceptance:

- winner can decode `nsec_i -> sk_i`
- non-winners never receive the wrapper secret

### 4.10 Buyer Verification

Implement buyer-side verification:

- recompute `wrapper_commitment`
- recompute `ask_id`

Acceptance:

- buyer can reject mismatched secret delivery
- delivery integrity is independently checkable

### 4.11 Buyer-Decryptable Fulfillment

Implement:

- `fulfillment_mode = buyer_decryptable_v1`
- `sealed_delivery_alg = nip44_v2`
- `encrypted_entitlement`

Acceptance:

- market buyer can decrypt the sealed entitlement after receiving `wrapper_secret`
- recovered plaintext contains:
  - `entitlement_code`
  - `entitlement_secret`

### 4.12 NIP-44 Sealed Delivery

Implement Nostr-native sealed delivery to the wrapper public key.

Plaintext:

```json
{
  "entitlement_code": "<...>",
  "entitlement_secret": "<...>"
}
```

Encryption:

```text
encrypted_entitlement = nip44_encrypt(
  sender_sk = seller_sk,
  receiver_pk = pk_i,
  plaintext = canonical_json({
    "entitlement_code": entitlement_code,
    "entitlement_secret": entitlement_secret
  })
)
```

Decryption:

```text
plaintext = nip44_decrypt(
  receiver_sk = sk_i,
  ciphertext = encrypted_entitlement
)
```

Acceptance:

- only the holder of delivered `sk_i` can decrypt
- recovered plaintext matches the expected entitlement material
- recomputed `wrapper_commitment` still matches the published value

### 4.13 Provider-Resolved Fulfillment

Implement:

- provider-side wrapper binding store:
  - `wrapper_ref -> entitlement_code, entitlement_secret`
- challenge/response redemption using wrapper key control

Acceptance:

- valid wrapper control releases the entitlement/service
- invalid challenge proof is rejected
- second redemption fails if single-use is enforced

---

## 5. Suggested Agent Method Surface

Recommended first method set:

- `generate_trading_wrapper()`
- `derive_wrapper_commitment()`
- `build_ms02_order()`
- `derive_ask_id()`
- `publish_ms02_ask()`
- `get_settlement_receipts()`
- `clear_ms02_order()`
- `deliver_wrapper_secret()`
- `verify_ms02_delivery()`
- `encrypt_entitlement_nip44()`
- `decrypt_entitlement_nip44()`

Optional later methods:

- `create_provider_redemption_binding()`
- `redeem_provider_resolved_wrapper()`
- `mark_entitlement_spent()`

---

## 6. Milestones

### 6.1 Milestone 1: Tradable Wrapper Loop

Build:

1. wrapper generation
2. wrapper commitment
3. ask building
4. ask publication
5. zap receipt fetch
6. clearing
7. wrapper secret delivery
8. buyer verification

Outcome:

- full market loop works up to secret transfer

### 6.2 Milestone 2: Direct Buyer Recovery

Build:

1. `buyer_decryptable_v1`
2. NIP-44 entitlement encryption/decryption

Outcome:

- direct agent-to-agent market flow works without a redemption provider

### 6.3 Milestone 3: Controlled Redemption

Build:

1. `provider_resolved_v1`
2. challenge/response redemption
3. single-use enforcement

Outcome:

- stronger operational model with provider-side uniqueness guarantees

---

## 7. Implementation Risks To Watch

### 7.1 Commitment Drift

Risk:

- different serializers or field order produce different commitments

Mitigation:

- use one canonical JSON implementation everywhere

### 7.2 Buyer Identity Instability

Risk:

- different zap parsing yields different winners

Mitigation:

- define one canonical buyer identity extraction rule and reuse it everywhere

### 7.3 Secret-Encoding Confusion

Risk:

- code mixes `sk_i` and `nsec_i`

Mitigation:

- commit over raw `sk_i`
- deliver encoded `nsec_i`
- decode immediately before verification/decryption

### 7.4 Sealed Delivery Without Uniqueness

Risk:

- `buyer_decryptable_v1` does not itself provide one-time enforcement

Mitigation:

- use it only where downstream replay risk is acceptable or separately controlled

### 7.5 Wrapper Reuse

Risk:

- same wrapper used for multiple asks

Mitigation:

- enforce fresh wrapper generation per entitlement unit

---

## 8. Ready-To-Build Summary

If you want the fastest useful implementation path:

1. implement wrapper generation
2. implement commitment derivation
3. implement ask construction/publication
4. implement zap receipt retrieval and clearing
5. implement private wrapper secret delivery
6. implement buyer verification
7. implement `buyer_decryptable_v1` with NIP-44

That gives you the first fully Nostr-native agent market path.
