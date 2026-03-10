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

## Proof Mutation Safety Requirements

Before destructive proof operations (swap/consolidate/delete-rewrite):

- A proof safety audit MUST run.
- If audit reports unsafe state, operation MUST fail closed (`PROOF_AUDIT_FAILED`).

During mutation:

- The runtime MUST NOT delete existing proof events until non-empty replacement proofs are confirmed ready.
- The runtime MUST NOT overwrite in-memory or persisted proofs with an empty replacement set unless the expected target state is explicitly empty.
- If no proofs are present, mutation routines MUST no-op (not crash wallet load paths).

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

## Implementation References

- `safebox/acorn.py`
- `app/tasks.py`
- `app/routers/safebox.py`
- `app/routers/agent.py`
- `app/nwc.py`
- `app/main.py`
- `safebox/cli_agent.py`
