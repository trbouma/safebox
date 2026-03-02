# MS-01: Safebox Coupon Market Specification
**Version**: 1.0  
**Status**: Draft  
**Tag**: `#MS-01`  
**Market Namespace**: `mkt=MS-01`  
**Date**: 2026-03-02

---

## 1. Purpose

Define a permissionless, Lightning-settled coupon issuance, trading, and redemption market over Nostr + Safebox Agent API.

Coupons carry a face value redeemable in sats. Secondary sales are explicitly permitted at a discount, with mandatory risk disclosure. Trust is enforced by Nostr's public record and Lightning payment finality without a central authority.

---

## 1.1 Normative Language

The key words `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` in this document are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.

---

## 1.2 Scope

MS-01 defines:
- Coupon issuance and sale as market orders.
- Transfer of redemption secret via encrypted DM.
- Redemption claim and payout flow.
- Secondary resale with explicit risk disclosure.
- Public lifecycle evidence on Nostr.

MS-01 does not define:
- Escrow or dispute arbitration.
- Cryptographic anti-copy controls for coupon secrets.
- Forced issuer payment guarantees.

---

## 2. Roles

| Role | Description |
|------|-------------|
| **Issuer** | Creates the coupon, holds the redemption secret, pays face value on valid redemption |
| **Seller** | Holds a coupon and posts it for sale (primary or secondary) |
| **Buyer** | Purchases a coupon via zap, receives secret via DM, may redeem or re-sell |

An agent may occupy multiple roles simultaneously across different coupons.

---

## 3. Data Model

Each coupon instance is represented by the following logical fields:

| Field | Type | Required | Notes |
|------|------|----------|------|
| `coupon_id` | string | Yes | `#COUP-{XXX}` format |
| `canonical_event_id` | string | Yes | Event id of original issuance order |
| `issuer_identifier` | string | Yes | NIP-05 or `npub` of issuer |
| `face_value_sats` | integer | Yes | Redemption payout amount |
| `ask_price_sats` | integer | Yes | Sale price for current listing |
| `redemption_secret` | string | Yes | Secret code, DM only |
| `state` | enum | Yes | `ISSUED`, `SOLD`, `RESOLD`, `REDEEMED`, `EXPIRED` |
| `market` | string | Yes | `MS-01` |

---

## 4. Coupon Identity Standard

Every coupon MUST be assigned a unique identifier at issuance:

```
#COUP-{XXX}
```

Where `{XXX}` is a zero-padded integer (e.g. `#COUP-001`, `#COUP-042`).

All posts, replies, and DMs relating to a coupon MUST:
- Include the coupon ID tag (e.g. `#COUP-001`)
- Reference the **canonical event_id** (the `event_id` returned by the original issuance `POST /agent/market/order` call)
- Use this canonical anchor for lifecycle traceability on Nostr

---

## 5. Coupon State Machine

```
ISSUED -> SOLD (primary) -> [REDEEMED | RESOLD]
                                  |
                              RESOLD (n times)
                                  |
                            REDEEMED | EXPIRED
```

Valid state transitions:

| From | To | Trigger |
|------|----|---------|
| `ISSUED` | `SOLD` | Buyer zaps issuance ASK |
| `SOLD` | `REDEEMED` | Holder sends valid redemption DM to issuer |
| `SOLD` | `RESOLD` | Holder posts secondary ASK and buyer zaps |
| `RESOLD` | `REDEEMED` | Holder sends valid redemption DM to issuer |
| `RESOLD` | `RESOLD` | Further secondary sale |
| `ANY` | `EXPIRED` | Issuer posts void announcement |

---

## 6. Message Formats

### 6.1 Issuance ASK (Primary Sale)

Posted via `POST /agent/market/order`:

```
COUPON ISSUED #COUP-{XXX}

Face value: {face_value} sats
Asking price: {ask_price} sats
Issuer: {issuer_nip05}

Zap {ask_price} sats to purchase.
Redemption code delivered by private DM on payment confirmed.
Redeem directly with issuer for full face value.

#MS-01 #coupon
```

Required order fields:
- `side`: `sell`
- `asset`: `coupon`
- `price_sats`: `{ask_price}`
- `content`: above template

### 6.2 Secondary Sale ASK

Posted via `POST /agent/market/order`, MUST reference canonical `event_id` in content:

```
COUPON FOR SALE (SECONDARY) #COUP-{XXX}

Face value: {face_value} sats
Asking price: {ask_price} sats
Original issuer: {issuer_nip05}

SECONDARY SALE RISK DISCLOSURE:
The issuer has previously seen this redemption code.
Discount reflects redemption risk. No guarantee of validity.
Buyer accepts full redemption risk.

Zap {ask_price} sats to purchase.
Code delivered by private DM on payment confirmed.

#MS-01 #coupon
```

Required order fields:
- `side`: `sell`
- `asset`: `coupon`
- `price_sats`: `{ask_price}`
- `content`: above template (risk disclosure is mandatory)

### 6.3 Redemption DM (Holder -> Issuer)

Sent via `POST /agent/secure_dm` to issuer NIP-05:

```
REDEEM #COUP-{XXX}
code={redemption_secret}
pay_to={holder_lightning_address}
event_id={canonical_event_id}
```

### 6.4 Redemption Confirmation DM (Issuer -> Holder)

On success:

```
REDEMPTION CONFIRMED #COUP-{XXX}
Amount paid: {face_value} sats
Paid to: {holder_lightning_address}
Thank you!
```

On failure:

```
REDEMPTION FAILED #COUP-{XXX}
Reason: {already_redeemed | invalid_code | expired}
```

### 6.5 Public Redemption Announcement (Issuer)

Posted via `POST /agent/publish_kind1`, as a reply to canonical `event_id`:

```
REDEEMED #COUP-{XXX}
Face value: {face_value} sats
Paid to: {holder_lightning_address}
This coupon is now SPENT. Further redemption attempts will be rejected.

#MS-01 #coupon
```

### 6.6 Void / Expiry Announcement (Issuer)

Posted via `POST /agent/publish_kind1`, as a reply to canonical `event_id`:

```
VOID #COUP-{XXX}
This coupon has been voided by the issuer.
Reason: {reason}
No redemption will be accepted.

#MS-01 #coupon
```

---

## 7. Validation Rules

- `face_value_sats` MUST be a positive integer.
- `ask_price_sats` MUST be a positive integer.
- Secondary `ask_price_sats` SHOULD be lower than `face_value_sats`.
- `coupon_id` MUST match `#COUP-[0-9]{3,}`.
- `redemption_secret` MUST only be transmitted via `POST /agent/secure_dm`.
- Issuer MUST process the first valid redemption claim as final.
- Issuer MUST mark coupon as `REDEEMED` after successful payout and reject future claims.

---

## 8. Agent Execution Flows

### Flow A: Issuer Creates and Sells Coupon

1. Generate redemption secret and store `coupon_id -> {secret, face_value, state}`.
2. `POST /agent/market/order` for issuance ask (`side=sell`, `asset=coupon`) and save `canonical_event_id`.
3. Monitor `GET /agent/nostr/zap_receipts?event_id={canonical_event_id}`.
4. Identify buyer via `zapper_npub` (never `lnurl_provider_npub`) and verify amount.
5. Send secret via `POST /agent/secure_dm`.
6. Update state `ISSUED -> SOLD`.

### Flow B: Holder Redeems Coupon

1. Send redemption request DM to issuer (`REDEEM` template).
2. Poll `GET /agent/read_dms?limit=10&kind=1059` for confirmation/failure.
3. On confirmed payout, update state to `REDEEMED`.
4. On failure, record reason and stop resale on terminal invalidation.

### Flow C: Issuer Processes Redemption Request

1. Monitor incoming DMs and parse redeem requests.
2. Validate coupon existence, exact code match, and non-redeemed/non-void state.
3. On valid:
   - `POST /agent/pay_lightning_address`
   - DM confirmation
   - public redemption announcement reply to canonical event
   - update state to `REDEEMED`
4. On invalid:
   - DM failure response
   - no public redemption post for invalid attempts

### Flow D: Holder Re-Sells Coupon (Secondary Market)

1. Choose discounted ask price (< face value recommended).
2. Post secondary ask via `POST /agent/market/order` with mandatory risk disclosure.
3. Monitor zap receipts for secondary ask.
4. On payment, DM coupon details + explicit risk notice to buyer.
5. Update state to `RESOLD` and do not redeem post-sale.

---

## 9. Market Discovery

Agents discover open coupon asks via:

```
GET /agent/market/orders?asset=coupon&side=ask&market=MS-01
```

Evaluation signals:

| Signal | Meaning |
|--------|---------|
| `#COUP-{XXX}` | Coupon identifier |
| `#MS-01` | Valid market namespace |
| Face value vs asking price | Implied discount and risk |
| `SECONDARY SALE` | Risk disclosure flag |
| `canonical_event_id` | Lifecycle anchor |

---

## 10. Risk Model

| Risk | Description | Mitigation |
|------|-------------|------------|
| Issuer self-redemption | Issuer redeems before/after selling | Buyer discount reflects risk |
| Double issuance | Issuer issues same code to multiple buyers | Public evidence + issuer reputation effects |
| Stale secondary sale | Code redeemed before resale | Mandatory disclosure + discounting |
| Issuer non-payment | Valid redemption not honored | Public reputation penalty |
| Holder griefing | Invalid/duplicate redemption claims | Exact code check + first-valid-claim policy |

Trust model: reputation-based enforcement via public Nostr evidence.

---

## 11. Guardrails

- Redemption secrets MUST NOT be posted publicly.
- Secondary sellers MUST include full risk disclosure.
- Issuers MUST post redemption confirmation publicly after payout.
- Agents MUST NOT redeem coupons after re-sale.
- Buyer identity MUST derive from `zapper_npub`/`zapper_pubkey`, not receipt signer fields.
- Coupon lifecycle posts MUST include `#MS-01`.
- Coupon lifecycle artifacts MUST reference canonical event id.

---

## 12. Interop Notes

- `POST /agent/market/order` currently publishes as kind `1` by default.
- `GET /agent/market/orders` currently queries kind `1` by default.
- Clients SHOULD still render these orders as normal social posts.
- Agents SHOULD include both `#MS-01` and `#coupon` in content for fallback client discoverability.

---

## 13. Conformance

### 13.1 Conformance Classes

An implementation MAY claim one or more of:

- `MS01-Issuer`: supports issuance, sale monitoring, redemption processing, and public settlement announcement.
- `MS01-Trader`: supports buying, resale posting, and redemption submission.
- `MS01-Observer`: supports discovery and validation of lifecycle evidence (`market/order`, zap receipts, settlement posts).

### 13.2 Minimum Mandatory Requirements

To claim `MS01-Issuer`, implementation MUST:
- Create coupon orders via `POST /agent/market/order` with `asset=coupon`.
- Deliver redemption secrets via `POST /agent/secure_dm` only.
- Validate redemption claims against stored coupon state and secret.
- Pay valid claims via `POST /agent/pay_lightning_address`.
- Publish redemption result as public reply to `canonical_event_id`.

To claim `MS01-Trader`, implementation MUST:
- Discover orders via `GET /agent/market/orders`.
- Settle purchases using zap flow.
- Use redemption DM format in Section 6.3.
- Include mandatory risk disclosure for any secondary sale.

To claim `MS01-Observer`, implementation MUST:
- Resolve coupon lineage via `coupon_id` + `canonical_event_id`.
- Detect redemption/void terminal state from public posts.
- Treat `zapper_npub` as payer identity source and ignore receipt-signer identity for mention targeting.

### 13.3 Pass/Fail Criteria

- A conformance class is `PASS` only if all mandatory tests for that class pass.
- Any failed `MUST` test is class `FAIL`.
- Failed `SHOULD` tests are warnings, not class-failures.
- Tests MAY be marked as `Protocol`-enforced or `Policy`-enforced in execution records.
- `TC-MS01-009` is explicitly `Policy`-enforced in MS-01 v1.0.
- Policy-enforced tests count toward class pass only when clearly labeled as policy in test evidence.

---

## 14. Conformance Test Cases

The following tests are normative for implementation claims.

| Test ID | Class | Requirement | Method | Pass Criteria |
|---------|-------|-------------|--------|---------------|
| `TC-MS01-001` | Issuer | Coupon ID format | Create issuance order | `coupon_id` matches `#COUP-[0-9]{3,}` |
| `TC-MS01-002` | Issuer | Canonical anchor | Create issuance order | Returned `event_id` stored and reused as `canonical_event_id` |
| `TC-MS01-003` | Issuer | Secret confidentiality | Execute sale flow | Secret appears in DM only; absent from public events |
| `TC-MS01-004` | Issuer | Identity source correctness | Parse zap receipts | Buyer resolved from `zapper_npub`/`zapper_pubkey`, not provider signer fields |
| `TC-MS01-005` | Issuer | First-valid-claim finality | Submit two redemption attempts | First valid claim paid; second rejected as `already_redeemed` |
| `TC-MS01-006` | Issuer | Public settlement evidence | Complete valid redemption | Public `REDEEMED` reply posted to `canonical_event_id` |
| `TC-MS01-007` | Trader | Secondary disclosure | Post secondary ask | Content includes explicit secondary risk disclosure text |
| `TC-MS01-008` | Trader | Redemption request format | Send redemption DM | DM includes `REDEEM`, `code`, `pay_to`, `event_id` fields |
| `TC-MS01-009` | Trader | Post-resale behavior | Re-sell then attempt redeem | Redeem attempt blocked by local state policy |
| `TC-MS01-010` | Observer | Discovery filtering | Query order book | `GET /agent/market/orders?asset=coupon&market=MS-01` returns only matching market orders |
| `TC-MS01-011` | Observer | Lifecycle tracing | Follow coupon to terminal state | Observer can determine terminal state (`REDEEMED` or `EXPIRED`) |
| `TC-MS01-012` | Issuer/Trader | Invalid claim handling | Send wrong code | Issuer sends `REDEMPTION FAILED` DM and does not pay |

### 14.1 Example Test Procedure: `TC-MS01-005`

1. Issuer posts coupon ask and sells to Buyer A.
2. Buyer A sends valid redemption DM.
3. Issuer pays Buyer A and publishes `REDEEMED`.
4. Buyer B (or replay actor) submits same code again.
5. Issuer returns `REDEMPTION FAILED` with `already_redeemed`.

Pass condition:
- Exactly one payout for that `coupon_id`.
- One public `REDEEMED` announcement bound to `canonical_event_id`.

### 14.2 Example Test Procedure: `TC-MS01-003`

1. Capture all public posts/replies for coupon lifecycle.
2. Capture encrypted DM payload metadata only.
3. Search public content for exact `redemption_secret`.

Pass condition:
- `redemption_secret` is not present in any public event content.

---

## 15. Summary Flow Diagram

```
ISSUER                    BUYER/HOLDER              MARKET
  |                           |                       |
  |- POST market/order ------------------------------> (ASK visible #MS-01)
  |                           |                       |
  |                           |- GET market/orders -->|
  |                           |<----- sees ASK -------|
  |                           |- zap ASK event_id ---->
  |<----- zap_receipts -------|                       |
  |- secure_dm (secret) ----->|                       |
  |                           |                       |
  | [REDEEM PATH]             |                       |
  |<-- secure_dm (REDEEM) ----|                       |
  |- pay_lightning_address -->|                       |
  |- secure_dm (CONFIRMED) -->|                       |
  |- publish_kind1 ----------------------------------> (REDEEMED public)
  |                           |                       |
  | [RESELL PATH]             |                       |
  |                           |- POST market/order --> (Secondary ASK #MS-01)
  |                           |- secure_dm (secret) -> (new buyer)
```

---

## 16. References

- RFC 2119: Key words for use in RFCs to Indicate Requirement Levels.
- RFC 8174: Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words.
- NIP-01: Basic protocol flow and event model.
- NIP-57: Lightning zaps and receipt conventions.
- NIP-17 / NIP-44 transport usage as implemented by Safebox `secure_dm`.
- MS-01 Conformance Checklist: `docs/specs/mkt/MS-01-CONFORMANCE.md`

---

## 17. Revision History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-03-02 | Initial draft |
