# Safebox Security Test Plan (Pre-Production)

## 1. Purpose

This plan defines the major security validations required before promoting Safebox to production. It focuses on preventing fund loss, unauthorized access, record disclosure, and integrity regressions across core wallet, NFC, POS, relay, and blob workflows.

## 2. Security Objectives

Before go-live, demonstrate:

- Confidentiality:
  - Sensitive payloads are not exposed in transport logs, browser UI artifacts, or backend traces.
- Integrity:
  - Payment and record operations are cryptographically verifiable and tamper-resistant.
- Availability with safety:
  - Failures degrade safely (explicit errors, rollback/recovery), not silently.
- Access control:
  - Protected routes and wallet-bound operations cannot be invoked cross-session.
- Recoverability:
  - Uncertain payment states are detectable and recoverable (no silent proof loss).

## 3. Scope

In scope:

- Authentication/session paths (`welcome`, `login`, protected APIs)
- Wallet operations (invoice, payment, ecash send/accept, swaps)
- NFC card operations (issue, rotate, card-status, payment, proof, offer)
- POS operations (invoice, NFC payment, websocket status/notify)
- Record offer/request/present flows
- Relay/NWC messaging and decryption paths
- Blossom blob transfer and original-record handling
- Database initialization, constraints, and migration posture

Out of scope (track separately):

- External relay/blossom provider internal security controls
- Endpoint network perimeter controls (WAF, IDS) beyond integration tests

## 4. Threat Model Checklist

Validate controls for these high-risk classes:

- Stolen/rotated NFC card replay
- Forged payload/signature attempts
- Session hijack/CSRF/token misuse
- Payment race conditions and double-spend edge cases
- Delivery interruption after token issuance (proof-loss window)
- Websocket disconnect/reconnect inconsistency
- Mixed-content and downgrade risks behind reverse proxy
- Cross-tenant branding/host confusion issues
- DB concurrency/startup race causing data corruption

## 5. Test Environment Requirements

- Staging environment with production-equivalent:
  - worker count
  - reverse proxy behavior
  - TLS termination pattern
  - database backend (Postgres target preferred)
- Separate test identities:
  - payer wallet
  - payee wallet
  - NFC card variants (active, rotated, invalid)
- Isolated relay and blossom endpoints for fault injection

## 6. Security Test Matrix

### 6.1 Auth and Session Security

Tests:

1. Access protected route without cookie/token.
2. Reuse expired/invalid token.
3. CSRF missing/invalid token on sensitive form/API posts.
4. Attempt cross-wallet access by swapping tokens/cookies.

Pass criteria:

- Unauthorized requests are rejected with explicit 401/403 behavior.
- No protected data returned on failed auth.
- CSRF enforcement active on intended endpoints.

### 6.2 NFC Card Security and Revocation

Tests:

1. Active card succeeds for NFC login/payment/record flows.
2. Rotate secret, then retry old card payload.
3. Validate `/.well-known/card-status` for active vs rotated cards.
4. PIN mismatch path for proof flow (cancel vs continue behavior).

Pass criteria:

- Rotated cards fail immediately and consistently.
- Active cards continue to function.
- Failure messages are clear and non-leaky.

### 6.3 Payment Settlement Integrity (Critical)

Tests:

1. NFC request payment happy-path completion.
2. Interrupt network/refresh during in-flight ecash send.
3. Verify sender/receiver balances after interruption.
4. Validate rollback path (self-accept) on delivery failure.
5. Validate `ecash-recovery-*` record creation when rollback is uncertain.

Pass criteria:

- No silent proof loss.
- Settlement state is accurate (`PENDING` vs terminal status).
- Recovery artifact exists for unresolved delivery uncertainty.

### 6.4 POS Security and Status Correctness

Tests:

1. POS route access requires authenticated wallet session.
2. POS NFC flow does not mark complete on initial request acceptance.
3. Completion only on notify terminal events.
4. Decimal amount and wallet currency handling correctness.

Pass criteria:

- POS status transitions match backend settlement lifecycle.
- No false positive “paid” states.

### 6.5 Record Transfer and Blob Security

Tests:

1. Offer/request/present with valid signatures and expected transmittal.
2. Tamper with signed/encoded payload in transit.
3. Blob retrieval/decryption integrity checks.
4. Missing blob, stale reference, or transfer interruption.

Pass criteria:

- Invalid/tampered payloads are rejected.
- Blob verification failures are explicit and non-destructive.

### 6.6 NWC and Messaging Security

Tests:

1. Attempt NWC event decrypt using unmapped/non-active secret.
2. Sender/target mapped-secret mismatch event.
3. Replay previously handled event IDs.

Pass criteria:

- Unmapped/mismatched events rejected.
- Replay suppression works.
- No fallback to legacy direct wallet-key paths where disabled.

### 6.7 Transport and Reverse Proxy Security

Tests:

1. HTTPS page attempts insecure websocket (`ws://`) in proxied environment.
2. Host-header/forwarded-host behavior for branding and token host binding.
3. Localhost behavior remains functional without weakening production paths.

Pass criteria:

- Production paths enforce secure websocket/TLS semantics.
- No mixed-content regression.
- Host-based routing/branding does not leak across domains.

### 6.8 Database and Startup Safety

Tests:

1. Multi-worker concurrent startup against fresh DB.
2. Currency/init seed idempotency under concurrency.
3. Uniqueness constraints for wallet identity fields.
4. Migration baseline and drift checks.

Pass criteria:

- No startup race corruption.
- No duplicate key crashes on normal init.
- Schema initialization deterministic.

### 6.9 Logging and Secret Hygiene

Tests:

1. Verify logs do not expose:
   - private keys
   - raw NFC decrypted secrets
   - full ecash token values in normal level logs
2. Verify exception logs preserve traceability without leaking secrets.

Pass criteria:

- Sensitive values redacted/omitted.
- Operational diagnostics remain actionable.

## 7. Abuse and Negative Testing

Run targeted abuse tests:

- malformed JSON/oversized payloads
- high-rate invalid signature submissions
- repeated invalid PIN attempts
- websocket flood/reconnect churn
- stale token replay after rotation

Pass criteria:

- bounded resource usage
- clean rejection paths
- no worker crash or stuck task backlog

## 8. Go-Live Security Gates

Production release should be blocked unless all are true:

1. Critical tests in sections 6.2, 6.3, 6.4 pass in staging.
2. No open Critical/High vulnerabilities from current test cycle.
3. Rollback/recovery behavior for interrupted ecash delivery validated.
4. Authentication/CSRF/session controls validated post-deploy config.
5. Observability in place for settlement and recovery alerts.

## 9. Evidence Package (Required)

For sign-off, collect:

- test run ID, commit SHA, environment config
- pass/fail matrix by scenario
- key logs for settlement/rollback/recovery paths
- before/after balance reconciliation outputs
- list of residual risks and accepted exceptions

## 10. Post-Go-Live Security Cadence

- Weekly:
  - focused regression of NFC payment + POS settlement status
- Monthly:
  - full security smoke across auth/payment/record paths
- Quarterly:
  - adversarial replay/tamper campaign and failover security drill

## 11. Immediate Priority Run (Recommended)

Execute this first before next production rollout:

1. NFC request payment interruption test (refresh/network cut mid-transaction).
2. POS NFC status lifecycle correctness test (`PENDING` to terminal).
3. Rotated-card rejection test across login/payment/proof.
4. Recovery artifact verification (`ecash-recovery-*`) under forced delivery failure.

Expected result:

- No silent proof loss, no premature completion signals, and deterministic revocation behavior.
