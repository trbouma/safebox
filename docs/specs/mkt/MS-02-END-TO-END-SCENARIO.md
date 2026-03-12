# MS-02 End-to-End Scenario
**Spec Family**: `MS-02`  
**Version**: `1.0`  
**Status**: Draft  
**Date**: `2026-03-12`  
**Primary Spec**: `MS-02-entitlement-market.md`

---

## 1. Purpose

Provide a concrete end-to-end walkthrough of how an MS-02 entitlement is:

- created,
- committed,
- offered for trade,
- cleared and settled,
- transferred to the buyer,
- redeemed exactly once.

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
- hash-committed entitlement control material,
- deterministic clearing rules,
- direct secret delivery,
- provider-side redemption verification.

This is a strong fit for emerging agent-to-agent markets because autonomous agents need market primitives that are:

- machine-verifiable,
- low-friction,
- directly executable between counterparties,
- portable across providers and settlement rails,
- not dependent on a single centralized exchange or custodial marketplace.

In this model, an agent can:

- create a redeemable claim,
- quote and publish it,
- observe settlement,
- clear a winning counterparty,
- settle by revealing the committed secret,
- redeem or trigger redemption at the provider.

That closely resembles older commercial patterns, but with stronger guarantees:

- the claim can be publicly advertised without exposing the redemption secret,
- the commitment hash proves the claim was fixed before settlement,
- deterministic order binding prevents silent mutation of terms,
- redemption can be challenge-verified and single-use enforced.

The result is an old market form with new technology:

- direct trade execution,
- explicit clearing,
- programmable settlement,
- verifiable redemption.

This makes MS-02 especially well-suited to agent commerce, where software actors need to trade claims on future service delivery without relying on continuous human supervision or centralized market operators.

---

## 3. Scenario Overview

Actors:

- `Seller`: posts the ask and delivers the entitlement secret after settlement
- `Buyer A`: first interested buyer
- `Buyer B`: competing buyer
- `Redemption Provider`: honors redemption for the entitlement

Example asset:

- one entitlement redeemable for `10,000 inference tokens`

Example settlement:

- `21 sats`
- settlement method: `nip57_zap_v1`

Example implementation profile:

- `nostr_keypair_v1`

In this profile:

- `entitlement_ref = npub_i`
- `entitlement_secret = nsec_i`
- `commitment_hash = sha256(sk_i)`

---

## 4. Core Security Invariant

The essential invariant in MS-02 is:

> the entitlement secret is fixed before the order is published, but remains hidden until after clearing.

This is guaranteed by the hash commitment.

The seller publishes:

- the public order details
- the full `commitment_hash`
- the deterministic `ask_id`

The seller does **not** publish:

- the underlying secret

Because the commitment hash is published before payment and included in the `ask_id` derivation, the seller cannot later substitute a different entitlement secret without detection.

---

## 5. Step 1: Create the Entitlement

The seller or provider first creates one entitlement instance.

At the generic MS-02 level, that means creating:

- an `entitlement_ref`
- an `entitlement_secret`
- a `commitment_hash`

In `nostr_keypair_v1`, the seller generates a fresh Nostr keypair:

```text
sk_i = fresh private key bytes
pk_i = public key derived from sk_i
npub_i = bech32(pk_i)
nsec_i = bech32(sk_i)
```

Then the seller computes:

```text
commitment_hash = sha256(sk_i)
```

The provider stores an internal mapping:

```text
entitlement_ref (npub_i) -> underlying service entitlement
```

Example:

```text
npub_i -> "10,000 inference tokens on model X"
```

Important properties:

- the entitlement is fresh
- the secret is high-entropy
- the reference is public-safe
- the secret is still private

---

## 6. Step 2: Create the Hash Commitment

The hash commitment is what locks the entitlement secret before the trade.

For `nostr_keypair_v1`:

```text
commitment_hash = sha256(sk_i)
```

This gives the market a public fingerprint of the future secret without disclosing the secret itself.

The commitment must be:

- computed before publication,
- stable for the lifetime of the order,
- included in the order binding,
- verified by the buyer after secret delivery.

Why this matters:

- if the seller later tried to reveal a different secret `sk_j`, then:
  - `sha256(sk_j) != commitment_hash`
  - buyer verification fails

So the commitment prevents post-payment substitution.

---

## 7. Step 3: Construct the Order

The seller creates `order_details` for one entitlement unit.

Example:

```json
{
  "entitlement_scheme": "nostr_keypair_v1",
  "entitlement_ref": "npub1...",
  "quantity": 1,
  "price_sats": 21,
  "expiry": "2026-03-31T23:59:59Z",
  "redemption_provider": "npub1provider...",
  "settlement_method": "nip57_zap_v1",
  "partial_payment_policy": "non_refundable",
  "tie_break_policy": "first_cleared_by_seller_observation"
}
```

Then the seller computes:

```text
ask_id = sha256(issuer_pubkey || canonical_json(order_details) || commitment_hash)
```

This is the second critical lock.

The `ask_id` binds together:

- who is selling
- what is being sold
- how it can be settled
- when it expires
- which secret commitment is locked to the order

If any of those change, the recomputed `ask_id` changes too.

That means:

- the seller cannot silently swap the entitlement reference
- the seller cannot silently swap the price
- the seller cannot silently swap the commitment hash
- the seller cannot silently swap the redemption provider metadata

without producing an invalid order binding

---

## 8. Step 4: Publish the Ask

The seller publishes the order over the chosen market channel.

Publicly visible:

- `ask_id`
- `issuer_pubkey`
- `order_details`
- `hash_alg`
- `commitment_hash`

Not publicly visible:

- `entitlement_secret`

At this point:

- the market can inspect the trade terms
- buyers can verify deterministic order binding
- nobody except the seller can redeem the entitlement

---

## 9. Step 5: Buyers Send Settlement

Now buyers compete to satisfy the order.

For `nip57_zap_v1`:

- Buyer A zaps the ask
- Buyer B may also zap the ask
- the seller observes zap receipts as settlement evidence

The important point is that settlement evidence is still not enough by itself to form a trade.

The order remains in a pre-trade state until clearing determines:

- which buyer identity is authoritative
- which buyer reached the threshold first under the published policy

---

## 10. Step 6: Clearing

Clearing converts observed payment evidence into one binding winner.

The seller:

1. collects settlement evidence
2. derives canonical buyer identities from that evidence
3. aggregates settled amounts by buyer identity
4. checks who reached `price_sats`
5. applies the tie-break rule
6. closes the order for one buyer

Example:

```text
Buyer A total settled: 10 sats
Buyer B total settled: 21 sats
Required amount: 21 sats
Winner: Buyer B
```

After clearing:

- Buyer B is the winner
- Seller now owes delivery of the entitlement secret to Buyer B
- Buyer A has no claim to the entitlement

This is the moment where competing payment attempts become one trade.

---

## 11. Step 7: Trade Formation

A trade exists once clearing succeeds.

The trade state includes:

- the order identity (`ask_id`)
- the winning buyer identity
- the settlement evidence supporting the win
- the seller obligation to deliver the secret

MS-02 deliberately separates this from raw payment observation.

That distinction matters because:

- multiple buyers may pay
- partial payments may exist
- tie-break rules may matter
- only one buyer can receive the entitlement

---

## 12. Step 8: Secret Delivery

After the trade forms, the seller privately delivers:

- `entitlement_secret`

For `nostr_keypair_v1`, this is:

- `nsec_i`

This must happen over a private channel because possession of the secret is what enables redemption.

If `redemption_provider` was hidden in the public order for privacy, the seller should also include it here.

At this stage, the seller has transferred control of the entitlement to the winning buyer.

---

## 13. Step 9: Buyer Verifies the Secret

This is where the hash commitment does its job.

The buyer performs two checks.

### 13.1 Verify the Commitment Hash

The buyer decodes the delivered `nsec_i` to recover the private key bytes `sk_i`.

Then the buyer recomputes:

```text
sha256(sk_i)
```

The result must exactly equal the published `commitment_hash`.

If it does not match:

- the delivered secret is invalid for the order
- the seller has failed delivery
- redemption should not proceed

### 13.2 Verify the Ask Binding

The buyer then recomputes:

```text
ask_id = sha256(issuer_pubkey || canonical_json(order_details) || commitment_hash)
```

This verifies that:

- the order terms are the ones the buyer saw publicly
- the commitment hash belongs to that exact order
- the delivered secret is the one fixed when the order was published

Combined effect:

- `commitment_hash` prevents secret substitution
- `ask_id` prevents order-term substitution around that commitment

This is the main anti-tamper guarantee in the protocol.

---

## 14. Step 10: Redemption

Now the buyer redeems the entitlement with the provider.

Generic flow:

1. buyer presents `entitlement_ref`
2. provider issues challenge
3. buyer proves control using `entitlement_secret`
4. provider verifies proof
5. provider releases the service

For `nostr_keypair_v1`:

1. buyer presents `npub_i`
2. provider sends challenge nonce
3. buyer signs the challenge using `sk_i`
4. provider verifies signature against `pk_i`

If valid and unspent:

- provider releases the service
- entitlement is consumed

---

## 15. Step 11: Mark the Entitlement Spent

Successful redemption must be single-use.

So the provider records spent state for that entitlement reference.

Example:

```text
npub_i -> spent
```

Any second redemption attempt must fail.

This is what makes the entitlement a redeemable one-time claim rather than a reusable credential.

---

## 16. What the Hash Commitments Guarantee

The commitment system guarantees four things.

### 16.1 The Secret Exists Before Trade Completion

Because the seller publishes a hash of the secret before the order is traded, the secret must already exist in some fixed form before settlement completes.

### 16.2 The Secret Cannot Be Swapped Later Without Detection

If the seller reveals a different secret after payment, the buyer's recomputed hash will not match `commitment_hash`.

### 16.3 The Order Terms Cannot Be Rebound to a Different Commitment Without Detection

Because `ask_id` includes:

- `issuer_pubkey`
- canonical `order_details`
- `commitment_hash`

any change to the commercial terms or the commitment changes the `ask_id`.

### 16.4 Redemption Happens Against the Same Locked Claim That Was Traded

The buyer verifies the delivered secret against the same public commitment that was bound into the order at publication time.

That preserves continuity from:

- entitlement creation
- to order publication
- to clearing
- to trade
- to redemption

---

## 17. Compact End-to-End Trace

```text
1. Seller creates entitlement:
   entitlement_ref, entitlement_secret, commitment_hash

2. Seller constructs order:
   order_details + commitment_hash -> ask_id

3. Seller publishes ask:
   ask_id, order_details, commitment_hash

4. Buyers settle:
   zap receipts or other settlement evidence arrive

5. Seller clears:
   one buyer wins under deterministic policy

6. Trade forms:
   seller now owes the entitlement secret to the winner

7. Seller privately reveals entitlement_secret

8. Buyer verifies:
   hash(secret) == commitment_hash
   recomputed ask_id == published ask_id

9. Buyer redeems:
   proves control of entitlement_secret to provider

10. Provider releases service and marks entitlement spent
```

---

## 18. Implementation Notes

- Fresh entitlement material MUST be used per traded unit.
- Full `commitment_hash` is authoritative; display-shortened hashes are not.
- Buyer identity extraction for settlement MUST be deterministic and documented by the implementation.
- The public ask commits to the claim without disclosing the redemption secret.
- Redemption provider behavior is downstream of trade, but spend enforcement is mandatory for market integrity.
