# MS-02 End-to-End Scenario
**Spec Family**: `MS-02`  
**Version**: `1.4`
**Status**: Draft  
**Date**: `2026-03-12`  
**Primary Spec**: `MS-02-entitlement-market.md`

---

## 1. Purpose

Provide a concrete end-to-end walkthrough of how an MS-02 underlying entitlement is:

- created,
- bound into a traded wrapper,
- committed,
- offered for trade,
- cleared and settled,
- transferred to the market buyer,
- fulfilled after a successful trade.

This document is explanatory. The normative market rules remain in `MS-02-entitlement-market.md`.

---

## 2. Historical Context

Before modern markets were dominated by centralized exchanges, custodians, payment processors, and platform intermediaries, trade was often conducted through direct claims, bearer instruments, warehouse receipts, bills of exchange, and other redeemable obligations exchanged between counterparties.

In those older market forms:

- the traded object was often a claim on a good or service rather than the good itself,
- settlement and delivery could be separated in time,
- redemption depended on possession and validation of the claim,
- counterparties, merchants, and local clearing relationships played a larger role than centralized institutions.

MS-02 revives that older market structure in a modern cryptographic form.

Instead of paper claims, it uses:

- public digital order publication,
- hash-committed wrapper control material,
- deterministic clearing rules,
- direct wrapper-secret delivery,
- provider-side redemption verification, or
- buyer-side sealed entitlement recovery.

This is a strong fit for emerging agent-to-agent markets because autonomous agents need market primitives that are:

- machine-verifiable,
- low-friction,
- directly executable between counterparties,
- portable across providers and settlement rails,
- not dependent on a single centralized exchange or custodial marketplace.

In this model, an agent can:

- create a redeemable underlying claim,
- bind it into a market-traded wrapper,
- quote and publish it,
- observe settlement,
- clear a winning counterparty,
- settle by revealing the committed wrapper secret,
- redeem or trigger redemption at the provider.

That closely resembles older commercial patterns, but with stronger guarantees:

- the claim can be publicly advertised without exposing the wrapper secret,
- the commitment hash proves the wrapper secret was fixed before settlement,
- deterministic order binding prevents silent mutation of terms,
- redemption can be challenge-verified and single-use enforced.

The result is an old market form with new technology:

- direct trade execution,
- explicit clearing,
- programmable settlement,
- verifiable redemption.

This makes MS-02 especially well-suited to agent commerce, where software actors need to trade claims on future service delivery without relying on continuous human supervision or centralized market operators.

Direct sealed delivery via `buyer_decryptable_v1` extends that fit further for agent markets that prefer direct handoff of redeemable material without a post-trade online provider lookup.

---

## 3. Scenario Overview

Actors:

- `Entitlement Provider`: creates the provider-native entitlement material and ensures it is bound to the trading wrapper before publication
- `Market Seller`: posts the ask and delivers the wrapper secret after settlement
- `Market Buyer A`: first interested market buyer
- `Market Buyer B`: competing market buyer
- `Redemption Provider`: honors redemption for the underlying entitlement once wrapper control is proven

This scenario document covers two fulfillment paths:

1. `provider_resolved_v1`
2. `buyer_decryptable_v1`

In both paths, the concrete trading wrapper profile used in this scenario is Nostr-native:

- `wrapper_scheme = nostr_keypair_v1`

For the buyer-decryptable branch, the concrete sealed-delivery profile used in this scenario is also Nostr-native:

- `sealed_delivery_alg = nip44_v2`

Example underlying asset:

- one entitlement redeemable for `10,000 inference tokens`

Example settlement:

- `21 sats`
- settlement method: `nip57_zap_v1`

Example implementation profile:

- `nostr_keypair_v1`

In this profile:

- underlying entitlement material may be `entitlement_code` + `entitlement_secret`
- `wrapper_ref = npub_i`
- `wrapper_secret` is the raw private key material `sk_i`
- `nsec_i` is the encoded delivery form of `wrapper_secret`
- `wrapper_commitment` binds `sk_i`, `entitlement_code`, and `entitlement_secret`

---

## 4. Core Security Invariant

The essential invariant in MS-02 is:

> the wrapper secret is fixed before the order is published, but remains hidden until after clearing.

This is guaranteed by the hash commitment.

The market seller publishes:

- the public order details
- the full `wrapper_commitment`
- the deterministic `ask_id`

The market seller does **not** publish:

- the wrapper secret

Because the wrapper commitment is published before payment and included in the `ask_id` derivation, the market seller cannot later substitute either the wrapper secret or the underlying entitlement material without detection.

---

## 5. Step 1: Create the Underlying Entitlement

The entitlement provider first creates one underlying entitlement instance.

At the generic MS-02 level, that means creating provider-native entitlement material.

Example:

```text
entitlement_code = "PROMO-2026-ALPHA"
entitlement_secret = "x9K...high-entropy-secret..."
```

These provider-native values are not necessarily the traded market object.

Instead, the entitlement provider binds them into a trading wrapper.

---

## 6. Step 2: Create the Traded Wrapper

In `nostr_keypair_v1`, the entitlement provider generates a fresh Nostr keypair:

```text
sk_i = fresh private key bytes
pk_i = public key derived from sk_i
npub_i = bech32(pk_i)
nsec_i = bech32(sk_i)
```

This creates:

- `wrapper_ref = npub_i`
- `wrapper_secret = sk_i`
- `wrapper_secret_delivery = nsec_i`

Before publishing the trading wrapper together with its `wrapper_commitment`, the redemption provider MUST store a persistent internal binding from the trading wrapper to the exact underlying entitlement being sold. For `nostr_keypair_v1`, this means binding `wrapper_ref` (`npub_i`) to the provider-native entitlement material (for example `entitlement_code` and `entitlement_secret`). This binding is not public. It exists so that, after a successful trade and private delivery of `wrapper_secret`, the market buyer can present `wrapper_ref`, prove control of `wrapper_secret`, and the provider can deterministically locate and release the correct underlying entitlement during redemption.

Example:

```text
npub_i -> {
  entitlement_code: "PROMO-2026-ALPHA",
  entitlement_secret: "x9K...high-entropy-secret..."
}
```

The market trades the wrapper, not the provider-native entitlement fields directly. The wrapper must be published together with its authoritative `wrapper_commitment`, not as a free-standing public reference.

If the fulfillment mode is `buyer_decryptable_v1`, the entitlement provider also prepares an encrypted payload containing the underlying entitlement material so the winning market buyer can decrypt it locally after receiving `wrapper_secret`.

---

## 7. Step 3: Create the Hash Commitment

The wrapper commitment is what locks both the wrapper secret and the underlying entitlement material before the trade.

For `nostr_keypair_v1`, the recommended derivation is:

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

Important properties:

- the underlying entitlement is fixed behind the wrapper
- the wrapper secret is high-entropy
- the wrapper reference is public-safe
- the wrapper secret is still private

This gives the market a public fingerprint of the future wrapper and the exact underlying entitlement bound behind it, without disclosing either secret directly. When delivery occurs later, `sk_i` may be encoded as `nsec_i` for transport, but the committed value remains the raw key material `sk_i`.

The commitment must be:

- computed before publication,
- stable for the lifetime of the order,
- included in the order binding,
- verified by the market buyer after secret delivery.

Why this matters:

- if the market seller later tried to reveal a different wrapper secret or a different underlying entitlement, then:
  - recomputation would not equal `wrapper_commitment`
  - market buyer verification fails

So the commitment prevents post-payment substitution.

If `buyer_decryptable_v1` is used, the encrypted entitlement payload is additional delivery material, but it is not a replacement for `wrapper_commitment`. The commitment remains the authoritative anti-substitution control.

---

## 8. Step 4: Construct the Order

The market seller creates `order_details` for one wrapped entitlement unit.

Example:

```json
{
  "wrapper_scheme": "nostr_keypair_v1",
  "fulfillment_mode": "provider_resolved_v1",
  "sealed_delivery_alg": null,
  "wrapper_ref": "npub1...",
  "quantity": 1,
  "price_sats": 21,
  "expiry": "2026-03-31T23:59:59Z",
  "redemption_provider": "npub1provider...",
  "settlement_method": "nip57_zap_v1",
  "partial_payment_policy": "non_refundable",
  "tie_break_policy": "first_cleared_by_seller_observation"
}
```

Then the market seller computes:

```text
ask_id = sha256(issuer_pubkey || canonical_json(order_details) || wrapper_commitment)
```

This is the second critical lock.

The `ask_id` binds together:

- who is selling
- what wrapper is being sold
- how it can be settled
- when it expires
- which wrapper-secret commitment is locked to the order

If any of those change, the recomputed `ask_id` changes too.

That means:

- the market seller cannot silently swap the wrapper reference
- the market seller cannot silently swap the price
- the market seller cannot silently swap the wrapper commitment
- the market seller cannot silently swap the redemption provider metadata
- the market seller cannot silently swap the underlying entitlement commitment if one is published

without producing an invalid order binding

---

## 9. Step 5: Publish the Ask

The market seller publishes the order over the chosen market channel.

Publicly visible:

- `ask_id`
- `issuer_pubkey`
- `order_details`
- `hash_alg`
- `wrapper_commitment`

Not publicly visible:

- `wrapper_secret`

At this point:

- the market can inspect the trade terms
- market buyers can verify deterministic order binding
- nobody except the market seller can control the wrapper needed to redeem the entitlement

---

## 10. Step 6: Market Buyers Send Settlement

Now market buyers compete to satisfy the order.

For `nip57_zap_v1`:

- Market Buyer A zaps the ask
- Market Buyer B may also zap the ask
- the market seller observes zap receipts as settlement evidence

The important point is that settlement evidence is still not enough by itself to form a trade.

The order remains in a pre-trade state until clearing determines:

- which market buyer identity is authoritative
- which market buyer reached the threshold first under the published policy

---

## 11. Step 7: Clearing

Clearing converts observed payment evidence into one binding winner.

The market seller:

1. collects settlement evidence
2. derives canonical market buyer identities from that evidence
3. aggregates settled amounts by market buyer identity
4. checks who reached `price_sats`
5. applies the tie-break rule
6. closes the order for one market buyer

Example:

```text
Market Buyer A total settled: 10 sats
Market Buyer B total settled: 21 sats
Required amount: 21 sats
Winner: Market Buyer B
```

After clearing:

- Market Buyer B is the winner
- Market Seller now owes delivery of the wrapper secret to Market Buyer B
- Market Buyer A has no claim to the wrapped entitlement

This is the moment where competing payment attempts become one trade.

---

## 12. Step 8: Trade Formation

A trade exists once clearing succeeds.

The trade state includes:

- the order identity (`ask_id`)
- the winning market buyer identity
- the settlement evidence supporting the win
- the market seller obligation to deliver the wrapper secret

MS-02 deliberately separates this from raw payment observation.

That distinction matters because:

- multiple market buyers may pay
- partial payments may exist
- tie-break rules may matter
- only one market buyer can receive control of the wrapper for that entitlement

---

## 13. Step 9: Wrapper Secret Delivery

After the trade forms, the market seller privately delivers:

- `wrapper_secret`

For `nostr_keypair_v1`, this is:

- `nsec_i` (the delivery encoding of `wrapper_secret = sk_i`)

This must happen over a private channel because possession of the wrapper secret is what enables redemption.

If `redemption_provider` was hidden in the public order for privacy, the market seller should also include it here.

At this stage, the market seller has transferred control of the wrapper to the winning market buyer.

---

## 14. Step 10: Market Buyer Verifies the Wrapper Secret

This is where the hash commitment does its job.

The market buyer performs two checks.

### 14.1 Verify the Commitment Hash

The market buyer decodes the delivered `nsec_i` to recover the private key bytes `sk_i`.

Then the market buyer recomputes:

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

The result must exactly equal the published `wrapper_commitment`.

If it does not match:

- the delivered wrapper secret is invalid for the order
- the market seller has failed delivery
- redemption should not proceed

### 14.2 Verify the Ask Binding

The market buyer then recomputes:

```text
ask_id = sha256(issuer_pubkey || canonical_json(order_details) || wrapper_commitment)
```

This verifies that:

- the order terms are the ones the market buyer saw publicly
- the wrapper commitment belongs to that exact order
- the delivered wrapper secret is the one fixed when the order was published

Combined effect:

- `wrapper_commitment` prevents wrapper or underlying-entitlement substitution
- `ask_id` prevents order-term substitution around that commitment

This is the main anti-tamper guarantee in the protocol.

---

## 15. Step 11: Fulfillment

MS-02 supports two fulfillment paths after wrapper-secret verification.

### 15.1 Provider-Resolved Fulfillment

Now the market buyer redeems the underlying entitlement with the provider.

Generic flow:

1. market buyer presents `wrapper_ref`
2. provider issues challenge
3. market buyer proves control using `wrapper_secret`
4. provider verifies proof
5. provider resolves the wrapper binding and releases the service

For `nostr_keypair_v1`:

1. market buyer presents `npub_i`
2. provider sends challenge nonce
3. market buyer signs the challenge using `sk_i`
4. provider verifies signature against `pk_i`

If valid and unspent:

- provider resolves `wrapper_ref` to the underlying entitlement material
- provider releases the service
- underlying entitlement is consumed

### 15.2 Buyer-Decryptable Fulfillment

If the order uses `buyer_decryptable_v1`, the public order also includes:

- `sealed_delivery_alg`
- `encrypted_entitlement`

In this scenario, the concrete Nostr-native sealed-delivery choice is:

- `sealed_delivery_alg = nip44_v2`

The market buyer then:

1. uses `sealed_delivery_alg` together with `wrapper_secret`
2. decrypts `encrypted_entitlement`
3. recovers:
   - `entitlement_code`
   - `entitlement_secret`

Example Nostr-native derivation:

```text
sealed_delivery_alg = nip44_v2
plaintext = nip44_decrypt(
  receiver_sk = sk_i,
  ciphertext = encrypted_entitlement
)
```

At that point, the market buyer holds the underlying entitlement material directly and no redemption provider lookup is required.

---

## 16. Step 12: Mark the Entitlement Spent

For `provider_resolved_v1`, successful redemption must be single-use.

So the provider records spent state for that wrapped entitlement.

Example:

```text
npub_i -> spent
```

Any second redemption attempt must fail.

This is what makes the entitlement a redeemable one-time claim rather than a reusable credential.

For `buyer_decryptable_v1`, MS-02 does not guarantee provider-side single-use enforcement by itself. Any one-time or replay protection must be implemented by the downstream system that accepts the decrypted entitlement material.

---

## 17. What the Hash Commitments Guarantee

The commitment system guarantees four things.

### 17.1 The Wrapper Secret Exists Before Trade Completion

Because the market seller publishes a hash of the wrapper secret before the order is traded, the wrapper secret must already exist in some fixed form before settlement completes.

### 17.2 The Wrapper Secret Cannot Be Swapped Later Without Detection

If the market seller reveals a different wrapper secret or changes the bound underlying entitlement after payment, the market buyer's recomputed value will not match `wrapper_commitment`.

### 17.3 The Order Terms Cannot Be Rebound to a Different Commitment Without Detection

Because `ask_id` includes:

- `issuer_pubkey`
- canonical `order_details`
- `wrapper_commitment`

any change to the commercial terms or the commitment changes the `ask_id`.

### 17.4 Fulfillment Happens Against the Same Locked Wrapper That Was Traded

The market buyer verifies the delivered wrapper secret and the expected underlying entitlement material against the same public wrapper commitment that was bound into the order at publication time.

That preserves continuity from:

- underlying entitlement creation
- wrapper creation
- order publication
- clearing
- trade
- fulfillment

---

## 18. Compact End-to-End Trace

```text
1. Entitlement Provider creates underlying entitlement:
   entitlement_code, entitlement_secret, or equivalent provider-native claim material

2. Entitlement Provider creates wrapper:
   wrapper_ref, wrapper_secret, wrapper_commitment

3. Market Seller constructs order:
   order_details + wrapper_commitment -> ask_id

4. Market Seller publishes ask:
   ask_id, order_details, wrapper_commitment

5. Market Buyers settle:
   zap receipts or other settlement evidence arrive

6. Market Seller clears:
   one market buyer wins under deterministic policy

7. Trade forms:
   market seller now owes the wrapper secret to the winner

8. Market Seller privately reveals wrapper_secret

9. Market Buyer verifies:
   recomputed wrapper_commitment == published wrapper_commitment
   recomputed ask_id == published ask_id

10. Market Buyer fulfills:
   either proves control of wrapper_secret to provider
   or decrypts encrypted_entitlement locally

11. Provider releases service and marks entitlement spent
```

---

## 19. Implementation Notes

- Fresh wrapper material MUST be used per traded unit.
- Underlying entitlement material MUST remain immutably bound to the wrapper once the ask is published.
- Full `wrapper_commitment` is authoritative; display-shortened hashes are not.
- Market buyer identity extraction for settlement MUST be deterministic and documented by the implementation.
- The public ask commits to the wrapper without disclosing the wrapper secret.
- Redemption provider behavior is downstream of trade, but spend enforcement is mandatory for market integrity.
- `buyer_decryptable_v1` removes the requirement for a redemption provider but also removes provider-side spend enforcement unless an equivalent downstream mechanism exists.

---

## 20. Revision History

| Version | Date | Notes |
|---------|------|-------|
| `1.4` | 2026-03-12 | Added alternate `buyer_decryptable_v1` fulfillment path with local entitlement decryption after wrapper-secret delivery. |
| `1.3` | 2026-03-12 | Normalized role terminology to `Entitlement Provider`, `Market Seller`, `Market Buyer`, and `Redemption Provider` throughout the scenario. |
| `1.2` | 2026-03-12 | Reframed the scenario around the trading-wrapper model and the authoritative `wrapper_commitment` over wrapper and underlying entitlement material. |
