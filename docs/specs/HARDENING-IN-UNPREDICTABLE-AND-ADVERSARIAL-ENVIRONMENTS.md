# Hardening in Unpredictable and Adversarial Environments

## Overview

Safebox operates in a distributed runtime where browser sessions, websocket channels, relays, vault endpoints, mint services, and blob stores can all fail independently. In practice, this means successful operation depends less on single-request correctness and more on defensive flow design.

This document defines the shared hardening posture used across QR, NFC, records, and payment paths. It is intended to help operators and contributors understand why Safebox uses explicit guards, bounded retries, fail-closed crypto checks, and rollback/recovery patterns.

## Scope

This specification covers:

- Common operating hazards across all Safebox flow families.
- Shared guard and fallback patterns used in production code paths.
- Failure semantics: when to fail closed, when to degrade gracefully.
- Rollback/recovery expectations under partial completion conditions.

This document does not replace protocol-specific specs. It defines cross-cutting hardening principles.

## Operating Environment

Safebox assumes the following conditions are normal, not exceptional:

- Relay history is noisy, delayed, reordered, and may contain stale events.
- Browser refresh/reconnect behavior can duplicate submissions.
- Websocket clients may disconnect without orderly close frames.
- Cross-instance deployments can drift in relay and KEM visibility.
- Third-party services may timeout, return partial data, or briefly disagree.
- Storage providers may be reachable but policy-constrained (for example delete unauthorized).

Under these conditions, optimistic flows are unsafe. Safebox uses explicit session binding and staged completion to prevent false success.

## Threat and Failure Classes

### 1. Timing and Ordering Instability

- Same-kind events from prior sessions can appear before current session events.
- Strict `since` filters can miss valid same-second events.
- Asynchronous callbacks can arrive out-of-order.

### 2. Session Drift and Replay-Like Effects

- Stale `nauth` responses can be selected if listeners are not nonce-bound.
- Multi-card usage can trigger wrong-token/wrong-kind confusion that resembles protocol failure.

### 3. Cross-Instance KEM and Relay Drift

- Browser-captured KEM state may be absent at submit time.
- Relay host identity and recipient service host may diverge.
- Incompatible KEM assumptions can produce decrypt failures (`invalid MAC`-class behavior).

### 4. Partial External Failure

- Blob source delete may fail while transfer succeeds.
- Preflight checks can fail while authoritative path remains healthy.
- Notification channels may fail after successful backend commit.

### 5. Adversarial or Noisy Channels

- Bootstrap channels (QR/NFC) can be observed, replayed, or scanned incorrectly.
- Transport intermediaries may expose metadata or reorder delivery.

## Shared Hardening Patterns

### A. Session Binding and Candidate Selection

Auth/listener pickup should be constrained to active session context:

- Require nonce match for auth response selection.
- Apply transmittal target checks where route semantics support it (`transmittal_pubhex`).
- Prefer `nauth:nembed` candidates over plain `nauth` when both are present.

Purpose:

- Prevent stale-history event pickup.
- Reduce cross-session contamination.

### B. Two-Tier Validation Model

- Preflight checks are advisory for resiliency.
- Authoritative checks occur at the boundary that owns policy/state (vault, signature, key resolution, storage authority).

Purpose:

- Avoid false negatives from transient preflight failures.
- Preserve integrity by enforcing trust decisions only at authoritative points.

### C. Fail-Closed Crypto Boundaries

For required quantum-safe exchange:

- Use peer-provided KEM material bound to active session.
- Do not silently substitute local/default KEM for peer KEM in cross-party encryption paths.
- If valid peer KEM cannot be resolved, require re-authentication/retry.

Purpose:

- Preserve cryptographic correctness under drift and replay conditions.

### D. Graceful Degradation for Non-Critical Legs

When failure does not invalidate core record/payment correctness:

- Continue flow with explicit warnings (for example source blob cleanup failure).
- Preserve accepted data and surface advisory status.

Purpose:

- Avoid unnecessary user-facing hard failures while keeping auditability.

### E. Bounded Waiting and Explicit Terminal States

- No indefinite polling loops.
- Timeouts must emit explicit terminal messages (`OK`, `ERROR`, `TIMEOUT`, advisory warning).
- Completion semantics should reflect actual backend commit stage.

Purpose:

- Prevent hanging UI and ambiguous operator state.

### F. Compatibility-Path Discipline

- Primary routes carry strict hardening first.
- Legacy/compatibility routes should be aligned gradually and must not break valid established flows.

Purpose:

- Prevent regressions during hardening rollout.

### G. Frontend Trigger Integrity and Safe Diagnostics

- Auto-send/auto-transmit flows MUST not depend on optional UI elements.
- Logging helpers used in critical paths MUST degrade safely when UI log targets are absent.
- Recipient-initiated mode semantics SHOULD be normalized server-side to avoid stale query-state drift.
- Route normalization MUST land on handshake-capable pages for stage-1 auth and stage-2 transmit.

Purpose:

- Prevent silent client-side exceptions from aborting protocol steps.
- Avoid dead-end states where handshake succeeds but transmit never executes.
- Keep flow behavior deterministic across refresh/referer/browser restore conditions.

Observed failure class:

- Handshake completed (`presenter_nauth` + KEM exchange) but no records appeared on transmittal kind.
- Root cause was a frontend exception in a logging helper on a page without a log container, plus stale mode/routing interactions.
- Corrective hardening included: safe logging fallback, forced recipient auto-send mode for offer-request scans, and routing normalization to handshake-capable offer pages.

### H. Scanner Navigation and URL-Exposure Controls

- Scanner-driven sensitive handoffs SHOULD use browser-navigation POST (not fetch-only API calls) when downstream flow requires full-page transition.
- Scanner intake handlers SHOULD accept both JSON and form payloads to tolerate client transport differences.
- For recipient-initiated offer intake, bootstrap values (`nauth`, recipient mode flags) SHOULD be passed through scanner-only POST endpoints instead of query-string redirects.

Purpose:

- Prevent scanner pages from appearing stuck due to non-navigating fetch responses.
- Reduce accidental exposure of bootstrap/session parameters in browser URL surfaces.
- Keep scanner and non-scanner paths interoperable without duplicating flow logic.

### I. Receive-Offer Persistence Semantics

- In `offer_request`/`receive_offer` mode, verified incoming records MUST be persisted, not just rendered.
- When original-record transfer metadata is present, blob transfer SHOULD be attempted and non-fatal failures surfaced as warnings.

Purpose:

- Align user-visible success with durable grant storage outcomes.
- Prevent false-positive completion where records appear in-session but are not stored.

## HTTPS/REST/API Surface in Current Flows

Safebox flows currently touch HTTPS/REST/API endpoints for specific control-plane needs, including:

- preflight checks,
- service metadata lookup (for example KEM discovery),
- card/vault orchestration boundaries,
- user-initiated browser actions.

These endpoints are a necessary bridge in the current architecture, but they are also high-risk surfaces under adversarial conditions (spoofing, replay, probing, routing manipulation, and policy interference).

### Current Security Posture

- HTTPS/REST/API calls are treated as constrained control-plane helpers, not authoritative end-to-end trust channels by default.
- Authoritative flow state should remain bound to session-scoped signed/validated messaging.
- Websocket channels must be scoped and restricted to their corresponding client/session and should not be treated as shared open buses.

### Direction of Travel

Safebox’s target posture is:

- execute full interaction flows through NWC-like message exchange and relay-bound session semantics,
- keep HTTPS/REST/API endpoints primarily for end-user interaction entrypoints and operational compatibility,
- minimize protocol-critical dependence on HTTP callbacks or host-specific lookup behavior.

### Transitional Constraint

Even in relay-first operation, underlying relay, mint, and blob services still commonly depend on HTTPS and DNS infrastructure. This introduces unavoidable transport dependencies in current deployments.

Long-term objective:

- migrate toward Nostr-native addressing and communication capabilities so network identity, routing, and session exchange are less dependent on conventional HTTPS/DNS control planes.

## Fallback Strategy Matrix

Safebox uses three fallback classes:

1. **Selection fallback** (choose current valid candidate from noisy history)
- Example: nonce-bound auth candidate scan with preference for KEM-bearing payloads.

2. **Transport fallback** (alternative channel/lookup when primary channel is missing)
- Example: server-side KEM resolution when browser state is absent.

3. **Outcome fallback** (continue with warning when non-critical post-step fails)
- Example: blob source delete unauthorized after successful transfer.

Rule:

- Fallbacks are allowed only when they do not weaken required security guarantees.

## Graceful Failure and Rollback Principles

### Principle 1: Never claim completion before committed state

- UI success must map to backend commit completion, not request acceptance.

### Principle 2: Preserve recoverability over optimistic forward progress

- On uncertain intermediate state, retain enough data to retry or reconcile.

### Principle 3: Distinguish fatal vs non-fatal failures

- Fatal: signature/key/session integrity failure, required KEM missing, invalid auth binding.
- Non-fatal: post-commit cleanup failure, auxiliary rendering failure, advisory preflight outage.

### Principle 4: Keep rollback explicit and bounded

- Release locks in `finally`-style paths.
- Do not mutate final state on partial cryptographic validation.
- Emit machine-parseable diagnostics for reconciliation.

## Operator Guidance

- Treat stale-event behavior as expected in shared relay environments and validate nonce-binding first.
- Keep relay/KEM configuration aligned across web and worker services.
- After config changes, restart all relevant processes before concluding flow regressions.
- Include multi-card and cross-instance cases in every regression run.
- Track warning classes separately from hard failures to avoid false incident escalation.

## Why This Matters

Safebox is built for environments that are intermittently connected, operationally heterogeneous, and occasionally adversarial. Hardening is not an optimization layer; it is required for correctness and trust.

In this operating model:

- graceful degradation protects continuity,
- fail-closed boundaries protect integrity,
- rollback/recovery protects assets and records when dependencies are unreliable.

## Implementation References

- `app/routers/records.py`
- `app/routers/safebox.py`
- `app/tasks.py`
- `safebox/acorn.py`
- `docs/specs/ACORN-RESILIENCY-AND-GUARDS.md`
- `docs/specs/NFC-FLOWS-AND-SECURITY.md`
- `docs/specs/OFFERS-AND-GRANTS-FLOWS.md`
