# MS-01 Conformance Checklist
**Spec**: `MS-01`  
**Version**: `1.1`  
**Date**: `2026-03-04`  
**Primary Spec**: `docs/specs/mkt/MS-01-coupon-market.md`

---

## 1. Purpose

Provide an executable checklist for validating implementation conformance against MS-01 using Safebox Agent API endpoints.

This checklist maps directly to normative test cases:
- `TC-MS01-001` ... `TC-MS01-022`

---

## 2. Test Environment

Required:
- A running Safebox instance with market endpoints deployed.
- At least 3 wallets:
  - `ISSUER`
  - `BUYER_A`
  - `BUYER_B` (or replay actor)
- Valid `X-Access-Key` for each wallet.
- Relay setup stable enough for market posts, zaps, and DMs.

Suggested environment variables:

```bash
BASE_URL="https://safebox.dev"
ISSUER_KEY="..."
BUYER_A_KEY="..."
BUYER_B_KEY="..."
PAY_TO_A="buyer-a@safebox.dev"
```

---

## 3. Conformance Classes

- `MS01-Issuer`
- `MS01-Trader`
- `MS01-Observer`

Pass rule:
- A class is `PASS` only if all mandatory test cases for that class pass.

---

## 4. Global Run Ledger

Fill once per run:

| Field | Value |
|------|-------|
| Run ID | |
| Runner | |
| Date/Time (UTC) | |
| Base URL | |
| Relay set | |
| Spec version under test | 1.1 |
| Notes | |

---

## 5. Test Case Checklist

Use `PASS`, `FAIL`, or `N/A` in the Result column.

| Test ID | Class | Enforcement | Result | Evidence (event ids / tx ids / logs) | Notes |
|---------|-------|-------------|--------|----------------------------------------|-------|
| `TC-MS01-001` | Issuer | Protocol | | | |
| `TC-MS01-002` | Issuer | Protocol | | | |
| `TC-MS01-003` | Issuer | Protocol | | | |
| `TC-MS01-004` | Issuer | Protocol | | | |
| `TC-MS01-005` | Issuer | Protocol | | | |
| `TC-MS01-006` | Issuer | Protocol | | | |
| `TC-MS01-007` | Trader | Protocol | | | |
| `TC-MS01-008` | Trader | Protocol | | | |
| `TC-MS01-009` | Trader | Policy | | | |
| `TC-MS01-010` | Observer | Protocol | | | |
| `TC-MS01-011` | Observer | Protocol | | | |
| `TC-MS01-012` | Issuer/Trader | Protocol | | | |
| `TC-MS01-013` | Trader | Protocol | | | |
| `TC-MS01-014` | Trader | Protocol | | | |
| `TC-MS01-015` | Trader | Protocol | | | |
| `TC-MS01-016` | Trader | Protocol | | | |
| `TC-MS01-017` | Trader/Observer | Protocol | | | |
| `TC-MS01-018` | Issuer | Protocol | | | |
| `TC-MS01-019` | Issuer/Trader | Protocol | | | |
| `TC-MS01-020` | Issuer/Trader | Protocol | | | |
| `TC-MS01-021` | Trader/Observer | Protocol | | | |
| `TC-MS01-022` | Issuer/Observer | Protocol | | | |

---

## 6. Execution Steps by Test Case

## 6.1 `TC-MS01-001` Coupon ID Format

Requirement:
- `coupon_id` matches `#COUP[A-Z2-9]{6}`.

Steps:
1. Create issuance order content with coupon id.
2. Publish via `POST /agent/market/order`.
3. Verify format in published content.

Pass:
- Coupon identifier matches required pattern.

## 6.2 `TC-MS01-002` Canonical Anchor

Requirement:
- Returned issuance `event_id` is retained and reused as canonical anchor.

Steps:
1. Capture `event_id` from issuance response.
2. Use it in redemption DM `event_id=...`.
3. Use it for public settlement reply threading.

Pass:
- Same canonical id appears in all lifecycle evidence.

## 6.3 `TC-MS01-003` Secret Confidentiality

Requirement:
- Redemption secret is DM-only.

Steps:
1. Complete one sale.
2. Inspect public posts/replies for secret string.
3. Confirm secret appears only in DM payload.

Pass:
- Secret absent from all public content.

## 6.4 `TC-MS01-004` Identity Source Correctness

Requirement:
- Buyer identity derived from `zapper_npub` / `zapper_pubkey`, not receipt signer identity.

Steps:
1. Query `GET /agent/nostr/zap_receipts?event_id=<issuance_event>`.
2. Validate identity fields used for buyer resolution.

Pass:
- Mention/identity target uses zapper fields only.

## 6.5 `TC-MS01-005` First-Valid-Claim Finality

Requirement:
- First valid redeem claim wins; duplicates fail.

Steps:
1. Buyer A sends valid redeem DM.
2. Issuer pays Buyer A and publishes `REDEEMED`.
3. Buyer B (or replay actor) submits duplicate claim.
4. Issuer rejects duplicate with `already_redeemed`.

Pass:
- Exactly one payout event for coupon id.

## 6.6 `TC-MS01-006` Public Settlement Evidence

Requirement:
- Successful redemption is announced publicly as reply to canonical event.

Steps:
1. Complete successful redemption.
2. Confirm `REDEEMED #COUP...` post exists.
3. Confirm reply threading targets canonical issuance event.

Pass:
- Public settlement post exists and is properly anchored.

## 6.7 `TC-MS01-007` Secondary Risk Disclosure

Requirement:
- Secondary asks contain explicit risk disclosure.

Steps:
1. Post secondary sale ask.
2. Inspect content for required secondary disclosure language.

Pass:
- Disclosure is present and unambiguous.

## 6.8 `TC-MS01-008` Redemption Request Format

Requirement:
- DM includes `REDEEM`, `code`, `pay_to`, and `event_id`.

Steps:
1. Send redemption DM.
2. Inspect message body fields.

Pass:
- All required fields present.

## 6.9 `TC-MS01-009` Post-Resale Behavior

Requirement:
- Reseller does not redeem after resale.

Steps:
1. Resell coupon to another buyer.
2. Attempt local redeem from previous holder.

Pass:
- Attempt blocked or skipped by policy/state.
- Record this test as `Policy Pass` (not cryptographic/protocol enforcement).

## 6.10 `TC-MS01-010` Discovery Filtering

Requirement:
- Discovery query returns only matching market orders.

Steps:
1. Query:
   `GET /agent/market/orders?asset=coupon&market=MS-01`
2. Validate results belong to coupon asset + MS-01 namespace.

Pass:
- Returned entries satisfy query filters.

## 6.11 `TC-MS01-011` Lifecycle Tracing

Requirement:
- Observer can derive terminal state.

Steps:
1. Follow coupon lifecycle from issuance.
2. Determine terminal state (`REDEEMED` or `EXPIRED`) from public evidence.

Pass:
- Terminal state determinable without private data.

## 6.12 `TC-MS01-012` Invalid Claim Handling

Requirement:
- Invalid code does not trigger payout.

Steps:
1. Submit redemption DM with incorrect code.
2. Observe issuer response and transaction history.

Pass:
- `REDEMPTION FAILED` DM sent and no payout executed.

## 6.13 `TC-MS01-013` Self-Trade Prevention

Requirement:
- Agent MUST NOT buy its own ask or sell into its own bid.

Steps:
1. Have trader post an ask order.
2. Attempt to execute purchase from the same trader identity (same wallet/access key).
3. Observe settlement behavior and DM delivery.

Pass:
- Trade is rejected/skipped by policy.
- No redemption secret is delivered.
- No settlement transition for the attempted self-trade.

## 6.14 `TC-MS01-014` Fill Amount Validation

Requirement:
- Fill requires exact ask price by default.

Steps:
1. Post ask with known `ask_price_sats`.
2. Attempt payment with a different amount.
3. Observe delivery and settlement.

Pass:
- Order is not marked filled.
- No secret delivery occurs for non-exact payment.

## 6.15 `TC-MS01-015` Public Fill Evidence

Requirement:
- Successful sale emits one public `FILLED` reply on order event.

Steps:
1. Complete valid purchase with exact price.
2. Inspect public thread for fill evidence.

Pass:
- Exactly one `FILLED` reply exists for that order fill.
- Reply anchors to order event id.

## 6.16 `TC-MS01-016` Delivery Idempotency

Requirement:
- Duplicate/replayed paid signals must not cause duplicate delivery.

Steps:
1. Complete one valid fill and capture delivered DM.
2. Replay same settlement signal (or reprocess same receipt).
3. Inspect outbound delivery count.

Pass:
- Secret is delivered once only for (`coupon_id`,`order_event_id`,`buyer_identifier`).

## 6.17 `TC-MS01-017` Stale Order Handling

Requirement:
- Expired/cancelled orders are not fillable.

Steps:
1. Mark order expired/cancelled by policy and publish status.
2. Attempt to fill stale order after terminal status.
3. Inspect settlement state.

Pass:
- Fill rejected.
- Order terminal state remains non-open.

## 6.18 `TC-MS01-018` Hash-Lock Commitment

Requirement:
- Issuance includes `secret_hash` and `hash_alg=sha256`.

Steps:
1. Create issuance ask.
2. Inspect order content and stored coupon metadata.
3. Confirm commitment fields are present.

Pass:
- `secret_hash` exists.
- `hash_alg` is exactly `sha256`.

## 6.19 `TC-MS01-019` Preimage Match Settlement

Requirement:
- Redemption succeeds only when preimage hash matches canonical `secret_hash`.

Steps:
1. Capture canonical issuance with `secret_hash`.
2. Submit redemption DM with correct preimage.
3. Verify issuer recomputation path and payout.

Pass:
- Redemption succeeds and payout occurs only for matching preimage.

## 6.20 `TC-MS01-020` Preimage Mismatch Rejection

Requirement:
- Incorrect preimage is rejected without payout.

Steps:
1. Submit redemption DM with incorrect preimage.
2. Observe issuer response and tx history.

Pass:
- `REDEMPTION FAILED` with `invalid_code`.
- No payout executed.

## 6.21 `TC-MS01-021` Secondary Hash Continuity

Requirement:
- Secondary listing reuses canonical `secret_hash`/`hash_alg`.

Steps:
1. Create canonical issuance and note commitment fields.
2. Post secondary listing for same coupon.
3. Compare secondary fields against canonical issuance.

Pass:
- Secondary listing preserves same `secret_hash` and `hash_alg`.

## 6.22 `TC-MS01-022` Lock Expiry Enforcement

Requirement:
- Orders/redemptions after `lock_expiry` are rejected.

Steps:
1. Create coupon with short `lock_expiry`.
2. Wait until expiry.
3. Attempt new fill and redemption.

Pass:
- Expired lock is rejected for settlement.
- No new payout or valid fill occurs after expiry.

---

## 7. Optional Curl Templates

Issue order:

```bash
curl -sS -X POST \
  -H "X-Access-Key: ${ISSUER_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "side":"sell",
    "asset":"coupon",
    "price_sats":21,
    "hash_alg":"sha256",
    "secret_hash":"<sha256-hex>",
    "lock_expiry":"2026-12-31T23:59:59Z",
    "content":"COUPON ISSUED #COUPX7K9QR ... #MS-01 #coupon"
  }' \
  "${BASE_URL}/agent/market/order"
```

Read zap receipts:

```bash
curl -sS \
  -H "X-Access-Key: ${ISSUER_KEY}" \
  "${BASE_URL}/agent/nostr/zap_receipts?event_id=${ISSUANCE_EVENT_ID}&limit=20"
```

Send secure DM:

```bash
curl -sS -X POST \
  -H "X-Access-Key: ${BUYER_A_KEY}" \
  -H "Content-Type: application/json" \
  -d "{
    \"recipient\":\"issuer@safebox.dev\",
    \"message\":\"REDEEM #COUPX7K9QR\ncode=SECRET\npay_to=${PAY_TO_A}\nevent_id=${ISSUANCE_EVENT_ID}\"
  }" \
  "${BASE_URL}/agent/secure_dm"
```

---

## 8. Class Certification Summary

| Class | Mandatory Tests | Result |
|------|------------------|--------|
| `MS01-Issuer` | `001,002,003,004,005,006,012,018,019,020,022` | |
| `MS01-Trader` | `007,008,009,012,013,014,015,016,017,019,020,021` | |
| `MS01-Observer` | `010,011,021,022` | |

Final declaration:
- `MS01-Issuer`: `PASS` / `FAIL`
- `MS01-Trader`: `PASS` / `FAIL`
- `MS01-Observer`: `PASS` / `FAIL`

Policy note:
- A class may pass with policy-enforced checks (for example `TC-MS01-009`) only if those checks are explicitly marked `Policy` in the run ledger and notes.

---

## 9. Sign-Off

| Role | Name | Signature/Handle | Date |
|------|------|------------------|------|
| Test Runner | | | |
| Reviewer | | | |
| Approver | | | |
