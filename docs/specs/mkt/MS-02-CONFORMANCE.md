# MS-02 Conformance Checklist
**Spec**: `MS-02`  
**Version**: `1.0`  
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
- Relay setup stable enough for ask publication, zaps, and DM delivery.

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
| Spec version under test | 1.0 |
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

## 6.1 `TC-MS02-001` Fresh Capability Keypair

Requirement:
- Each entitlement uses a unique redemption keypair/`npub`.

Steps:
1. Prepare two capabilities for two entitlements.
2. Publish two asks from seller.
3. Extract `npub` values from ask payloads/tags/content.

Pass:
- `npub` values are distinct.

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
2. Recompute deterministic id using canonical serialization.
3. Compare with published `ask_id`.

Pass:
- Exact match.

## 6.4 `TC-MS02-004` Winner Selection

Requirement:
- First sender reaching required amount wins settlement.

Steps:
1. Buyer A sends partial zaps.
2. Buyer B sends zaps and reaches total first (or vice versa).
3. Seller finalizes settlement for first fully funded sender.

Pass:
- Winner is the first sender at `sum(sender_zaps) == price_sats`.
- Capability delivered only to winner.

## 6.5 `TC-MS02-005` Expiry Enforcement

Requirement:
- No settlement after `expiry`.

Steps:
1. Create ask with short expiry.
2. Wait until expired.
3. Attempt additional zap and settlement completion.

Pass:
- Ask is treated closed; no new winner; no capability delivery post-expiry.

## 6.6 `TC-MS02-006` Capability Verification

Requirement:
- Delivered `nsec` verifies against published commitment and ask binding.

Steps:
1. Winning buyer receives `nsec` via DM/secure channel.
2. Decode `nsec -> sk`.
3. Compute `sha256(sk)` and compare to `commitment_hash`.
4. Recompute `ask_id` and compare to published value.

Pass:
- Both commitment and ask-id checks succeed.

## 6.7 `TC-MS02-007` Signature Challenge Verification

Requirement:
- Provider challenge is signed by capability key and verified.

Steps:
1. Buyer submits `npub` to provider.
2. Provider sends challenge nonce.
3. Buyer signs challenge with capability key.
4. Provider verifies signature.

Pass:
- Valid signature accepted.
- Invalid signature variant rejected.

## 6.8 `TC-MS02-008` Single-Use Enforcement

Requirement:
- Second redemption attempt fails after first success.

Steps:
1. Complete one successful redemption for capability `npub`.
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
- Zap receipt ids used for winner decision
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

# 2) Check zaps for ask event
curl -sS \
  -H "X-Access-Key: ${SELLER_KEY}" \
  "${BASE_URL}/agent/nostr/zap_receipts?event_id=<ASK_EVENT_ID>&limit=100"
```

---

## 10. Revision History

| Version | Date | Notes |
|---------|------|-------|
| `1.0` | 2026-03-05 | Initial conformance checklist for MS-02 capability market lifecycle. |
