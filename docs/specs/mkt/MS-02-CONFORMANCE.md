# MS-02 Conformance Checklist
**Spec**: `MS-02`  
**Version**: `1.1`  
**Date**: `2026-03-05`  
**Primary Spec**: `docs/specs/mkt/MS-02-capability-market.md`

---

## 1. Purpose

Provide an executable checklist for validating implementation conformance against MS-02 using Safebox Agent API endpoints and provider-side redemption verification.

This checklist maps directly to:
- `TC-MS02-001` ... `TC-MS02-008`

---

## 2. Test Environment

Required:
- A running Safebox instance with market/zap/social endpoints deployed.
- A redemption provider test harness with challenge/response verification.
- At least 4 principals:
  - `SELLER`
  - `BUYER_A`
  - `BUYER_B` (competing buyer)
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

- `MS02-Seller`
- `MS02-Buyer`
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
| Spec version under test | 1.1 |
| Capability scheme under test | |
| Settlement method under test | |
| Notes | |

---

## 5. Test Case Checklist

Use `PASS`, `FAIL`, or `N/A`.

| Test ID | Class | Enforcement | Result | Evidence (event ids / tx ids / logs) | Notes |
|---------|-------|-------------|--------|----------------------------------------|-------|
| `TC-MS02-001` | Seller | Protocol | | | |
| `TC-MS02-002` | Seller | Protocol | | | |
| `TC-MS02-003` | Seller | Protocol | | | |
| `TC-MS02-004` | Seller | Protocol | | | |
| `TC-MS02-005` | Seller | Protocol | | | |
| `TC-MS02-006` | Buyer | Protocol | | | |
| `TC-MS02-007` | Provider | Protocol | | | |
| `TC-MS02-008` | Provider | Protocol | | | |

---

## 6. Execution Steps by Test Case

## 6.1 `TC-MS02-001` Fresh Capability Material

Requirement:
- Each entitlement uses unique capability material, producing unique `capability_ref`.

Steps:
1. Prepare two capabilities for two entitlements under the same `capability_scheme`.
2. Publish two asks from seller.
3. Extract `capability_ref` values from ask payloads/tags/content.

Pass:
- `capability_ref` values are distinct.

## 6.2 `TC-MS02-002` Commitment Publication

Requirement:
- Ask contains full authoritative `commitment_hash` and `hash_alg=sha256`.

Steps:
1. Publish ask.
2. Read ask event data.
3. Confirm hash fields are present and not truncated.

Pass:
- `commitment_hash` exists and is 64-char hex.
- `hash_alg` equals `sha256`.

## 6.3 `TC-MS02-003` Ask Determinism

Requirement:
- Recomputed `ask_id` equals published `ask_id`.

Steps:
1. Capture published `issuer_pubkey`, `order_details`, `commitment_hash`, `ask_id`.
2. Canonicalize `order_details` using RFC 8785 (JCS).
3. Recompute deterministic id using:
   `sha256(issuer_pubkey || canonical_json(order_details) || commitment_hash)`.
4. Compare with published `ask_id`.

Pass:
- Exact match.

## 6.4 `TC-MS02-004` Winner Selection

Requirement:
- First sender reaching required amount wins settlement.

Steps:
1. Buyer A sends partial settlement receipts.
2. Buyer B sends receipts and reaches total first (or vice versa).
3. Seller finalizes settlement for first fully funded sender.
4. If tie occurs in same processing window, evaluate documented tie-break policy.

Pass:
- Winner is first sender at `sum(sender_settlements) >= price_sats`.
- Capability secret delivered only to winner.
- Tie-break behavior matches documented deterministic rule.

## 6.5 `TC-MS02-005` Expiry Enforcement

Requirement:
- No settlement after `expiry`.

Steps:
1. Create ask with short expiry.
2. Wait until expired.
3. Attempt additional settlement and settlement completion.

Pass:
- Ask is treated closed; no new winner; no capability delivery post-expiry.

## 6.6 `TC-MS02-006` Capability Verification

Requirement:
- Delivered `capability_secret` verifies against published commitment and ask binding.

Steps:
1. Winning buyer receives secret via DM/secure channel.
2. Run scheme-specific commitment verification to derive hash from secret.
3. Compare derived hash to `commitment_hash`.
4. Recompute `ask_id` and compare to published value.

Pass:
- Commitment check succeeds.
- Ask-id check succeeds.

Note:
- For `nostr_keypair_v1`, verify `sha256(sk_i) == commitment_hash` where `sk_i` is decoded from delivered `nsec`.

## 6.7 `TC-MS02-007` Challenge Verification

Requirement:
- Provider challenge is verified using capability control proof.

Steps:
1. Buyer submits `capability_ref` to provider.
2. Provider sends challenge nonce.
3. Buyer proves control with scheme-specific method.
4. Provider verifies proof.

Pass:
- Valid proof accepted.
- Invalid proof variant rejected.

## 6.8 `TC-MS02-008` Single-Use Enforcement

Requirement:
- Second redemption attempt fails after first success.

Steps:
1. Complete one successful redemption for capability `capability_ref`.
2. Repeat redemption attempt with same capability.

Pass:
- First attempt succeeds.
- Second attempt fails with spent/used response.

---

## 7. Class Certification Summary

| Class | Mandatory Tests | Result |
|-------|------------------|--------|
| `MS02-Seller` | `001,002,003,004,005` | |
| `MS02-Buyer` | `006` | |
| `MS02-Provider` | `007,008` | |
| `MS02-Observer` | Audit evidence traceability across all tests | |

---

## 8. Evidence Minimums

Record at minimum:
- Ask event id
- Published `ask_id`
- Published `commitment_hash`
- Published `capability_scheme`
- Published `capability_ref`
- Settlement receipt ids used for winner decision
- Capability delivery evidence id (DM event id or secure channel log id)
- Redemption transaction id / provider request id
- Spent-marker evidence for single-use enforcement

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
| `1.0` | 2026-03-05 | Initial conformance checklist for MS-02 capability market lifecycle. |
| `1.1` | 2026-03-05 | Aligned checklist terminology and pass criteria to generic capability model (`capability_scheme/ref/secret`), RFC 8785 ask determinism, and deterministic tie-break semantics. |
