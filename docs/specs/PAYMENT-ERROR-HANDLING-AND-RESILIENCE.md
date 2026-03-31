# Payment Error Handling and Resilience Requirements

## Overview

This specification defines required error-handling and resilience behavior for Safebox payment methods.
It is the normative reliability contract for monetary state transitions across:

- Lightning invoice payment
- Lightning-address payment
- ecash issue/accept and Safebox-to-Safebox ecash delivery
- zap payment paths
- NFC/POS initiated payment flows that call the same wallet mutation methods

This document is intentionally implementation-close because payment reliability is safety-critical for Safebox.

## Scope

In scope:

- Error classes and required API/runtime behavior
- Locking, proof mutation safety, and rollback requirements
- Uncertain-settlement handling and recovery artifacts
- Observability and conformance requirements

Out of scope:

- UX copy specifics
- cryptographic primitive definitions
- operator legal/compliance obligations

## Normative Language

The key words `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, and `MAY` are to be interpreted as described in RFC 2119.

## Payment Methods Covered

Core methods and surfaces:

- Agent API: `/agent/pay_invoice`, `/agent/pay_lightning_address`, `/agent/issue_ecash`, `/agent/accept_ecash`, `/agent/zap`
- Web wallet routes that invoke wallet payment methods: `/safebox/payaddress`, `/safebox/payinvoice`, `/safebox/requestnfcpayment`, `/safebox/paytonfctag`
- NWC/NFC instruction paths for `pay_invoice`, `pay_ecash`, and related settlement callbacks

All of the above are REQUIRED to obey the same mutation safety model for proofs and balance.

## Reliability State Model

Payment-capable flows MUST implement or emulate the following lifecycle:

1. `ACCEPTED`: request syntax/auth passed, no monetary mutation yet
2. `PROCESSING`: external dependency call in-flight (mint, relay, LNURL/LN invoice, delivery)
3. `SETTLED`: monetary mutation committed and verified
4. `NOTIFIED`: completion signal emitted to client/consumer channel
5. `FAILED`: terminal failure before settlement
6. `UNCERTAIN`: external side-effect may have happened, local finality not confirmed

Rules:

- A flow MUST NOT report success before `SETTLED`.
- A flow in `UNCERTAIN` MUST emit recovery metadata sufficient for reconciliation.
- `NOTIFIED` is not itself settlement; it is post-settlement signaling.

## Error Taxonomy

Safebox payment methods MUST map failures into one of these classes:

- `AUTH_INVALID`: missing/invalid credentials
- `INPUT_INVALID`: malformed payload, unsupported amount/currency, missing required fields
- `DEPENDENCY_TIMEOUT`: upstream service timed out (mint/relay/vault/LN provider)
- `DEPENDENCY_REJECTED`: upstream returned deterministic rejection (insufficient route, invalid invoice, spent token)
- `LOCK_CONTENTION`: lock could not be acquired within bounds without safe recovery
- `PROOF_AUDIT_FAILED`: preflight proof integrity failed
- `PERSISTENCE_VERIFY_FAILED`: proof write/readback verification failed
- `DELIVERY_UNCERTAIN`: transport failed after local debit/issuance and rollback could not be confirmed
- `INTERNAL_ERROR`: unexpected runtime fault

API responses SHOULD expose stable `detail` text and SHOULD include a machine-friendly reason code where possible.

## Locking and Concurrency Requirements

For any operation that mutates proofs or balance:

- The runtime MUST use wallet-level serialization (lock).
- Lock acquire/release MUST be wrapped by `try/finally` semantics.
- Locking SHOULD support re-entrant acquisition for the same in-process actor/task to avoid self-contention.
- Excessive lock seizing events MUST be treated as an operational incident candidate and investigated.
- Read-only prechecks SHOULD avoid lock-heavy wallet load paths when a safe cached source exists
  (for example card-balance and payment preflight checks).

### Read-Only Precheck Rule

For operations that do not mutate monetary state:

1. Implementations SHOULD use cached balance/state sources when available.
2. Implementations MUST NOT treat cached reads as settlement confirmation.
3. Final mutation paths MUST continue to perform authoritative checks under lock.
4. If cached state is unavailable, implementation MAY fall back to full wallet load.

This reduces lock contention and lowers risk of forced-lock recovery behavior during
high-frequency POS/NFC interactions.

## Proof Mutation Safety Requirements

Before destructive proof operations (swap/consolidate/delete-rewrite):

- A proof safety audit MUST run.
- If audit reports unsafe state, operation MUST fail closed (`PROOF_AUDIT_FAILED`).

During mutation:

- The runtime MUST NOT delete existing proof events until non-empty replacement proofs are confirmed ready.
- The runtime MUST NOT overwrite in-memory or persisted proofs with an empty replacement set unless the expected target state is explicitly empty.
- Payment assembly routines MUST NOT destructively mutate the selected working proof set before swap/melt success is confirmed.
- Proof selection for payment SHOULD operate on a copy of the candidate keyset proof list and only commit back into wallet state after successful settlement commit.
- If no proofs are present, mutation routines MUST no-op (not crash wallet load paths).
- Implementations SHOULD avoid deferring all proof normalization to spend time alone; receive-side proof maintenance MAY be used to keep long-lived wallets below fragmentation thresholds.

### Receive-Side Maintenance Guidance

Where proof-bearing receive paths exist, implementations SHOULD support best-effort receive-side maintenance triggered by configurable thresholds such as:

- total proof count
- per-keyset proof count

Recommended behavior:

1. receive succeeds first
2. maintenance runs only when thresholds are exceeded
3. maintenance failure is logged but MUST NOT retroactively mark the receive as failed

This reduces the likelihood that a wallet accumulates large fragmented proof sets and only discovers proof-state problems during a later payment attempt.

After mutation:

- Proof persistence MUST be verified by reload/readback.
- If verification fails, runtime MUST attempt restore/recovery or fail closed with `PERSISTENCE_VERIFY_FAILED`.

## ecash Delivery and Rollback Requirements

For ecash send paths where issuance/debit can occur before remote delivery confirmation:

- On delivery failure, runtime SHOULD attempt best-effort rollback (`accept_token` of undelivered token).
- If rollback cannot be confirmed, runtime MUST persist a recovery artifact (for example `ecash-recovery-*`) containing enough metadata for reconciliation.
- Runtime MUST classify the result as `DELIVERY_UNCERTAIN`, not success.

## Dependency Failure Behavior

Mint/relay/LN dependency failures:

- Retries MUST be bounded.
- Timeout values MUST be explicit and configurable.
- Terminal timeout MUST surface as explicit error, not silent hang.
- Retry loops MUST avoid unbounded resource amplification.

### Mint Unavailability Semantics

Payment implementations MUST distinguish at least two mint-failure phases:

1. `PRE_COMMIT_DEPENDENCY_FAILURE`
   - quote/checkstate/key fetch/swap request fails before melt commit is accepted,
   - payment MUST fail closed,
   - existing proofs MUST remain unchanged in memory and in persistence.

2. `POST_SUBMISSION_UNCERTAIN`
   - melt submission may have been accepted remotely but client loses final confirmation,
   - payment MUST be surfaced as uncertain rather than success,
   - implementation MUST preserve existing wallet proofs unless authoritative confirmation supports replacement,
   - operator/user recovery MAY require reconciliation against mint state and payment hash/preimage evidence.

### Swap Retry Policy

- Automatic retry-after-swap SHOULD be limited to proof-shape or proof-state failures
  (for example fragmented proof sets, stale local proof composition, or deterministic "swap recommended" conditions).
- Generic mint unavailability or transport failures MUST NOT enter unbounded swap/retry loops.
- When a retry-after-swap path is attempted and fails, the final surfaced error SHOULD preserve the underlying mint/keyset context.

Client-visible behavior:

- `FAILED` and `UNCERTAIN` MUST be distinguishable.
- Upstream detail SHOULD be propagated when safe (no secret leakage).

## Session/Auth Failure Interaction

When authentication decryption/validation fails for browser-session based callers:

- Server SHOULD treat it as auth failure and force session reset (cookie invalidation) so the user can re-login.
- This MUST NOT be represented as successful payment status.

## Observability Requirements

Payment methods MUST emit structured logs for:

- operation name
- wallet handle/npub (non-secret)
- lifecycle status transitions
- lock wait/hold timing
- dependency endpoint class and latency outcome
- error class/reason
- recovery artifact identifiers when generated

The system MUST NOT log:

- access keys
- nsec/seed material
- full ecash token values
- full invoice strings unless explicitly redacted/hashed policy allows

## Conformance Requirements

A payment implementation is conformant only if all checks below pass:

1. Empty-proof mutation no-op:
   - swap/consolidate on empty wallet MUST not throw and MUST preserve stable wallet load.
2. Destructive guard:
   - replacement proof set empty -> existing proofs MUST NOT be deleted.
3. Proof audit gate:
   - unknown keyset mapping or invalid proof -> destructive mutation blocked.
4. Persistence verification:
   - post-write reload mismatch -> restore/fail-closed behavior occurs.
5. ecash uncertain delivery:
   - simulated transport failure after issue -> rollback attempt and/or recovery record required.
6. Lock safety:
   - lock always released after exceptions in mutation paths.
7. Explicit timeout:
   - dependency timeout returns terminal error class, not indefinite pending.
8. Auth invalidation:
   - stale invalid session cookie leads to logout/reset behavior, not repeated server exception loops.
9. Pre-commit mint outage:
   - quote/checkstate/swap outage MUST leave proofs unchanged.
10. Zero-proof replacement guard:
   - swap/consolidate/async-swap MUST refuse destructive replacement when no new proofs were produced.
11. Post-submission uncertainty:
   - melt submission failure after remote side-effect may be possible MUST surface uncertain wording, not success.

## Implementation References

- `safebox/acorn.py`
- `app/tasks.py`
- `app/routers/safebox.py`
- `app/routers/agent.py`
- `app/nwc.py`
- `app/main.py`
- `safebox/cli_agent.py`
