# MS-02 Conformance Checklist
**Spec**: `MS-02`  
**Version**: `2.5`
**Date**: `2026-03-12`  
**Primary Spec**: `MS-02-entitlement-market.md`

---

## 1. Purpose

Provide an executable checklist for validating implementation conformance against MS-02 using Safebox Agent API endpoints and either provider-side redemption verification or buyer-side decryptable fulfillment validation.

This checklist maps directly to:
- `TC-MS02-001` ... `TC-MS02-010`

---

## 2. Test Environment

Required:
- A running Safebox instance with market/zap/social endpoints deployed.
- A redemption provider test harness with challenge/response verification.
- At least 4 principals:
  - `SELLER`
  - `BUYER_A`
  - `BUYER_B` (competing market buyer)
  - `PROVIDER` (or provider simulator)
- Valid `X-Access-Key` for wallet actors.
- Relay setup stable enough for ask publication, settlement receipts, and DM delivery.

Suggested environment variables:

```bash
BASE_URL="https://safebox.dev"
SELLER_KEY="..."
BUYER_A_KEY="..."
BUYER_B_KEY="..."
PROVIDER_URL="https://provider.example.com"
```

---

## 3. Conformance Classes

- `MS02-MarketSeller`
- `MS02-MarketBuyer`
- `MS02-Provider`
- `MS02-Observer` (optional run role for evidence audit)

Pass rule:
- A class is `PASS` only if all mandatory test cases for that class pass.

---

## 4. Global Run Ledger

Fill once per run:

| Field | Value |
|------|-------|
| Run ID | |
| Runner | |
| Reviewer | |
| Date/Time (UTC) | |
| Base URL | |
| Provider URL | |
| Relay set | |
| Spec version under test | 2.5 |
| Wrapper scheme under test | |
| Settlement method under test | |
| Market buyer identity extraction rule | |
| Notes | |

---

## 5. Test Case Checklist

Use `PASS`, `FAIL`, or `N/A`.

| Test ID | Class | Enforcement | Result | Evidence (event ids / tx ids / logs) | Notes |
|---------|-------|-------------|--------|----------------------------------------|-------|
| `TC-MS02-001` | Market Seller | Protocol | | | |
| `TC-MS02-002` | Market Seller | Protocol | | | |
| `TC-MS02-003` | Market Seller | Protocol | | | |
| `TC-MS02-004` | Market Seller | Protocol | | | |
| `TC-MS02-005` | Market Seller | Protocol | | | |
| `TC-MS02-006` | Market Buyer | Protocol | | | |
| `TC-MS02-007` | Provider | Protocol | | | |
| `TC-MS02-008` | Provider | Protocol | | | |
| `TC-MS02-009` | Market Seller | Protocol | | | |
| `TC-MS02-010` | Market Seller | Protocol | | | |

---

## 6. Execution Steps by Test Case

## 6.1 `TC-MS02-001` Fresh Wrapper Material

Requirement:
- Each traded unit uses unique wrapper material, producing unique `wrapper_ref`.

Steps:
1. Prepare two wrapped entitlement instances under the same `wrapper_scheme`.
2. Publish two asks from the market seller.
3. Extract `wrapper_ref` values from ask payloads/tags/content.

Pass:
- `wrapper_ref` values are distinct.

## 6.2 `TC-MS02-002` Wrapper Commitment Publication

Requirement:
- Ask contains full authoritative `wrapper_commitment` and `hash_alg=sha256`.

Steps:
1. Publish ask.
2. Read ask event data.
3. Confirm hash fields are present and not truncated.

Pass:
- `wrapper_commitment` exists and is 64-char hex.
- `hash_alg` equals `sha256`.

## 6.3 `TC-MS02-003` Ask Determinism

Requirement:
- Recomputed `ask_id` equals published `ask_id`.

Steps:
1. Capture published `issuer_pubkey`, `order_details`, `wrapper_commitment`, `ask_id`.
2. Canonicalize `order_details` using RFC 8785 (JCS).
3. Recompute deterministic id using:
   `sha256(issuer_pubkey || canonical_json(order_details) || wrapper_commitment)`.
4. Compare with published `ask_id`.

Pass:
- Exact match.

## 6.4 `TC-MS02-004` Clearing Policy

Requirement:
- Clearing deterministically selects one market buyer once settlement evidence reaches the threshold.

Steps:
1. Market Buyer A sends partial settlement receipts.
2. Market Buyer B sends receipts and reaches total first (or vice versa).
3. Market Seller applies the documented canonical market buyer identity extraction rule.
4. Market Seller finalizes clearing for the first fully funded market buyer under the documented tie-break policy.
5. If tie occurs in same processing window, evaluate documented tie-break policy.

Pass:
- Winner is the first eligible market buyer at `sum(buyer_settlements) >= price_sats`.
- Wrapper secret delivered only to winner.
- Tie-break behavior matches documented deterministic rule.

## 6.5 `TC-MS02-005` Expiry Enforcement

Requirement:
- No settlement after `expiry`.

Steps:
1. Create ask with short expiry.
2. Wait until expired.
3. Attempt additional settlement and settlement completion.

Pass:
- Ask is treated closed; no new winner; no wrapper secret delivery post-expiry.

## 6.6 `TC-MS02-006` Wrapper Secret Verification

Requirement:
- Delivered `wrapper_secret` verifies against published commitment and ask binding.

Steps:
1. Winning market buyer receives secret via DM/secure channel.
2. Run scheme-specific commitment verification to derive hash from secret.
3. Recompute `wrapper_commitment` from canonical wrapper-secret and entitlement inputs.
4. Compare derived value to `wrapper_commitment`.
5. Recompute `ask_id` and compare to published value.

Pass:
- Commitment check succeeds.
- Ask-id check succeeds.

Note:
- For `nostr_keypair_v1`, verify the recomputed canonical wrapper commitment matches published `wrapper_commitment`, using:
  - wrapper secret bytes decoded from delivered `nsec`
  - the bound `entitlement_code`
  - the bound `entitlement_secret`

## 6.7 `TC-MS02-007` Challenge Verification

Requirement:
- Provider challenge is verified using wrapper control proof.

Steps:
1. Market buyer submits `wrapper_ref` to provider.
2. Provider sends challenge nonce.
3. Market buyer proves control with scheme-specific method.
4. Provider verifies proof.

Pass:
- Valid proof accepted.
- Invalid proof variant rejected.

## 6.8 `TC-MS02-008` Single-Use Enforcement

Requirement:
- Second redemption attempt fails after first success.

Steps:
1. Complete one successful redemption for wrapped entitlement `wrapper_ref`.
2. Repeat redemption attempt with same wrapped entitlement.

Pass:
- First attempt succeeds.
- Second attempt fails with spent/used response.

## 6.9 `TC-MS02-009` Market Buyer Identity Determinism

Requirement:
- The same settlement evidence set yields the same canonical market buyer identity and winner result on repeated evaluation.

Steps:
1. Capture the complete settlement evidence set used for one cleared order.
2. Apply the implementation's documented market buyer identity extraction rule to each receipt/event.
3. Re-run aggregation and winner selection at least twice using the same evidence set.
4. Compare derived market buyer identities and clearing result.

Pass:
- Market buyer identity extraction is stable across runs.
- Aggregation result is stable across runs.
- Winner selection is identical across runs.

## 6.10 `TC-MS02-010` Buyer-Decryptable Fulfillment

Requirement:
- For `buyer_decryptable_v1`, delivered `wrapper_secret` decrypts the published `encrypted_entitlement` into the expected entitlement material.

Steps:
1. Publish an ask using `fulfillment_mode = buyer_decryptable_v1`.
2. Capture published `encrypted_entitlement` and `wrapper_commitment`.
3. Complete clearing and deliver `wrapper_secret` to the winning market buyer.
4. Derive the documented decryption key from `wrapper_secret`.
5. Decrypt `encrypted_entitlement`.
6. Confirm recovered plaintext contains the expected `entitlement_code` and `entitlement_secret`.
7. Recompute `wrapper_commitment` from:
   - wrapper secret bytes
   - `entitlement_code`
   - `entitlement_secret`
8. Confirm recomputed value matches the published `wrapper_commitment`.

Pass:
- Decryption succeeds.
- Recovered entitlement material matches the expected underlying entitlement.
- Recomputed `wrapper_commitment` matches the published commitment.

---

## 7. Class Certification Summary

| Class | Mandatory Tests | Result |
|-------|------------------|--------|
| `MS02-MarketSeller` | `001,002,003,004,005,009` | |
| `MS02-MarketBuyer` | `006` | |
| `MS02-Provider` | `007,008` | |
| `MS02-Observer` | Audit evidence traceability across all tests | |

If `buyer_decryptable_v1` is implemented, `TC-MS02-010` is mandatory for `MS02-MarketSeller`.

---

## 8. Evidence Minimums

Record at minimum:
- Ask event id
- Published `ask_id`
- Published `wrapper_commitment`
- Published `wrapper_scheme`
- Published `wrapper_ref`
- Settlement receipt ids used for winner decision
- Canonical market buyer identity used for winner decision
- Wrapper secret delivery evidence id (DM event id or secure channel log id)
- Redemption transaction id / provider request id
- Spent-marker evidence for single-use enforcement
- Decryption trace or ciphertext-validation evidence for `buyer_decryptable_v1`

---

## 9. Optional API Exercise Template

```bash
# 1) Publish ask
curl -sS -X POST \
  -H "X-Access-Key: ${SELLER_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "side":"sell",
    "asset":"service_entitlement",
    "price_sats":21,
    "market":"MS-02",
    "content":"ASK #MS02 ..."
  }' \
  "${BASE_URL}/agent/market/order"

# 2) Check settlement receipts for ask event
curl -sS \
  -H "X-Access-Key: ${SELLER_KEY}" \
  "${BASE_URL}/agent/nostr/zap_receipts?event_id=<ASK_EVENT_ID>&limit=100"
```

---

## 10. Revision History

| Version | Date | Notes |
|---------|------|-------|
| `1.0` | 2026-03-05 | Initial conformance checklist for MS-02 entitlement market lifecycle. |
| `1.1` | 2026-03-05 | Aligned checklist terminology and pass criteria to generic capability model (`capability_scheme/ref/secret`), RFC 8785 ask determinism, and deterministic tie-break semantics. |
| `2.1` | 2026-03-12 | Aligned checklist to the generic entitlement market base, explicit clearing primitive, and canonical buyer identity determinism. |
| `2.2` | 2026-03-12 | Updated checklist to treat the traded object as a wrapper over an underlying entitlement and normalized references accordingly. |
| `2.5` | 2026-03-12 | Added `TC-MS02-010` for `buyer_decryptable_v1` fulfillment and updated checklist scope for direct encrypted entitlement delivery. |
| `2.4` | 2026-03-12 | Normalized conformance roles to `Market Seller` and `Market Buyer` and aligned checklist language to the updated MS-02 role model. |
| `2.3` | 2026-03-12 | Replaced `commitment_hash` with `wrapper_commitment` and aligned verification rules to the combined wrapper-plus-entitlement commitment model. |
