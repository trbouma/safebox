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

## Field Discoveries and Applied Fixes (2026-02)

This section captures concrete issues observed during live QR/NFC flow testing, and
the hardening changes applied so far.

### Discovery 1: scanner handoffs produced `Method Not Allowed`

Observed behavior:

- QR scanner redirects/handoffs hit routes with unsupported method combinations.
- Flows failed intermittently depending on browser navigation behavior.

Applied changes:

- Added compatibility POST/GET entrypoints for scanner-facing routes:
  - `POST /records/offerlist`
  - `GET /records/offerlist-scan`
  - `POST /records/accept`
  - `POST /records/present`
- Scanner now uses POST handoff pages for sensitive `nauth` transfers where possible.

Result:

- Reduced route/method mismatch failures across device/browser variants.

### Discovery 2: `nauth` context loss during Offer-by-QR receive path

Observed behavior:

- Receiver logs showed `scope: None grant: None` in `/records/ws/accept`.
- Receiver emitted auth response with random nonce.
- Presenter listener correctly rejected response due to nonce mismatch, causing
  auth loops and no check-mark completion.

Applied changes:

- For `scope` containing `offer`, scanner now posts `nauth` to `/records/accept`
  via form POST instead of query redirect.
- Receiver websocket startup now tolerates missing `nauth` without crashing, but
  continues to require valid nonce binding for handshake success.

Result:

- Offer-by-QR handshake now preserves session context and nonce continuity.

### Discovery 3: strict KEM gating blocked auth completion

Observed behavior:

- Auth response arrived (`nauth:nembed`), but KEM parse mismatch/absence caused
  presenter-side websocket loop (`kem_public_key: None`, repeated polling).
- UI did not advance to check-mark state even though auth traffic existed.

Applied changes:

- Added tolerant KEM extraction logic for multiple `nembed` forms.
- Added server-side KEM lookup fallback where applicable.
- Removed hard UI-stage block on embedded KEM in auth completion path; transmittal
  path resolves KEM with fail-closed behavior if still unavailable.

Result:

- Auth stage can complete deterministically; cryptographic enforcement remains in
  transmittal boundary.

### Discovery 4: receiver redirect built `record_kind=undefined`

Observed behavior:

- Receiver UI redirected to `/records/grantlist?record_kind=undefined`.
- Backend returned integer parsing error (`int_parsing`).

Applied changes:

- Receiver page (`acceptrecord`) now redirects only on valid numeric kind.
- Timeout/non-terminal messages no longer trigger redirect.
- Backend completion payload includes both `grant_kind` and `record_kind` for
  compatibility.

Result:

- Removed undefined-kind redirect failures and parsing exceptions.

### Discovery 5: transitional POST bridge pages caused white flash

Observed behavior:

- Scanner POST handoff pages briefly flashed white on mobile/desktop.

Applied changes:

- Unified POST bridge renderer with dark Safebox transition card/spinner.
- Shortened transition text for single-line mobile readability.

Result:

- Reduced visual instability during scanner-driven flow transitions.

## Remaining Fragility and Risk Concentration

Despite improvements, the following fragility points still require attention.

### 1. Relay eventual consistency and stale-history ambiguity

- Same-kind historical events remain a source of mis-selection risk.
- Current nonce binding reduces risk but does not eliminate all race windows when
  multiple active sessions share relay surfaces.

Needed hardening:

- Explicit session IDs in control messages (in addition to nonce).
- Stronger candidate ordering rules and duplicate suppression by session key.

### 2. Legacy route divergence

- Compatibility routes exist to avoid regressions, but behavior may drift from
  primary paths over time.

Needed hardening:

- Define one canonical handshake/transmittal route family.
- Add parity tests that assert identical outcomes between canonical and compat routes.

### 3. Mixed payload contracts (`nauth`, `nauth:nembed`, structured JSON)

- Multiple payload shapes increase parse complexity and error surface.

Needed hardening:

- Formalize message-type registry and envelope contract per kind.
- Add strict schema validation before state transitions.

### 4. Browser dependency in bootstrap sequencing

- Scanner and websocket behavior still depends on browser navigation semantics.
- Mobile browser differences can still expose timing-sensitive race conditions.

Needed hardening:

- Add deterministic client state machine with explicit phase transitions.
- Add browser-matrix regression tests for scan -> auth -> transmittal flows.

### 5. External HTTPS dependency for KEM metadata

- KEM fallback currently uses `/.well-known/kem` lookups over HTTPS.
- This remains a control-plane dependency that can be disrupted or poisoned.

Needed hardening:

- Prefer relay-native/session-bound KEM exchange where available.
- Keep HTTPS KEM lookup as bounded compatibility fallback with clear telemetry.

### 6. UI success signaling before end-to-end confirmation

- Some views still infer completion from intermediate websocket states.

Needed hardening:

- Standardize terminal states and only show success after durable commit and/or
  verifiable receipt conditions.

## Immediate Hardening Backlog

1. Add automated integration tests for:
   - Offer by QR (same-instance and cross-instance)
   - Offer by NFC (same-instance and cross-instance)
   - Request by QR/NFC
   - Scanner POST bridge handoffs (method and parameter preservation)
2. Introduce session-id tag in auth/transmittal control messages and bind all
   stage transitions to `(nonce, session_id)`.
3. Define and enforce a message schema registry per event kind in backend entrypoints.
4. Consolidate legacy websocket paths onto canonical routes with deprecation gates.
5. Add explicit telemetry counters for:
   - nonce mismatch rejections
   - KEM parse fallback usage
   - HTTPS KEM fallback usage
   - timeout terminal states by flow type

## Operator Quick Checklist (QR/NFC Flow Triage)

Use this checklist during incident triage before deep debugging.

### A. Confirm active branch/config parity

1. Verify service and worker processes are running the same branch/build.
2. Confirm `AUTH_KIND`, `RECORD_TRANSMITTAL_KIND`, and relay settings match expected environment.
3. Restart app processes after changing config or branch.

### B. Validate scanner handoff integrity

1. Confirm scanner route used POST handoff for internal `nauth` flows.
2. Verify receiver route logs include expected `scope` and `grant` (not `None`).
3. If `scope/grant` are `None`, treat as handoff context loss first, not cryptographic failure.

### C. Validate auth stage completion

1. On presenter side, verify websocket listener resolves auth params and expected nonce.
2. Check for nonce mismatch warnings.
3. If auth messages are present but UI does not progress, inspect client-side errors first.

### D. Validate KEM material handling

1. Check whether auth payload includes `nauth:nembed` with KEM fields.
2. If missing, confirm fallback KEM resolution attempts/logs.
3. If KEM remains unavailable at transmittal boundary, fail closed and re-authenticate.

### E. Validate transmittal stage

1. Confirm record send invoked with expected kinds (`originating_kind`, `final_kind`).
2. Confirm recipient is listening on expected transmittal kind and relay set.
3. Distinguish “no incoming records” from decrypt/storage failures.

### F. Validate receive/store stage

1. Confirm receiver websocket sends terminal payload (`OK`, `ERROR`, `TIMEOUT`).
2. Confirm redirect parameters include valid numeric `record_kind`/`grant_kind`.
3. Confirm grant persisted in recipient store, not only rendered in-session.

### G. Minimum log bundle for escalation

Capture these lines together for each failed attempt:

1. scanner handoff target and method
2. receiver `scope/grant` line
3. presenter `ws_listen_for_nauth resolved auth params ...`
4. first `listen for request ...` payload block
5. KEM parse/fallback lines
6. final terminal state line (`OK`/`ERROR`/`TIMEOUT`)

### H. Fast decision tree

1. `scope/grant None` on receiver:
   scanner handoff loss; fix transport path first.
2. nonce mismatch warnings:
   stale or cross-session auth event selected; rebind session and retry.
3. auth received but no check-mark:
   client-side transition exception or over-strict UI gate.
4. check-mark shown but no record:
   transmittal/recipient listener mismatch or transmittal kind drift.
5. record visible but not stored:
   persistence path issue; verify receive-offer persistence semantics.

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

## Comparison to Existing Tap-and-Pay Systems

Safebox QR/NFC flows overlap with traditional tap-and-pay in user interaction shape (scan/tap -> authorize -> complete), but they differ materially in trust boundaries, transport assumptions, and failure handling.

### Baseline comparison

| Dimension | Conventional tap-and-pay (EMV/tokenized wallet rails) | Safebox QR/NFC record-payment model |
|---|---|---|
| Primary trust anchor | Scheme/network + acquirer/issuer authorization path | Session-bound cryptographic exchange (`nauth`/`nembed`) + wallet-held keys |
| Message transport | Mostly managed card-network paths with strong central orchestration | Relay/websocket/event paths with eventual consistency and heterogeneous infra |
| Session continuity | Terminal/acquirer state machines under scheme rules | Explicit nonce/session binding at application layer |
| Data minimization at edge | PAN/tokenization standards and terminal policy | Minimal bootstrap payload policy (handshake parameters only) |
| Failure semantics | Network- and issuer-defined decline/error codes | Application-defined terminal states (`OK`, `ERROR`, `TIMEOUT`) plus fallback classes |
| Recovery model | Scheme dispute/reversal workflows | Retry/reconcile with signed state and verifiable record transfer evidence |
| Custody/control posture | Typically custodial or institution-gated | End-user/agent-controlled safebox instances with revocable delegates |

### Where Safebox is stronger (given current assumptions)

1. Protocol-level session binding can be made explicit and inspectable by operators.
2. Record and payment flow evidence can be retained as independently verifiable events.
3. Hardening can be applied at the app/protocol edge without waiting for network-rail changes.

### Where conventional rails are currently stronger

1. Operational uniformity across terminals/acquirers (fewer transport variants).
2. Mature decline/dispute ecosystems and standardized issuer/acquirer recovery procedures.
3. Lower exposure to relay/eventual-consistency edge cases in typical retail payment scenarios.

### Practical implication

Safebox should not assume card-rail reliability characteristics by default. The hardening model in this document exists specifically because Safebox operates in a more open and variable environment. The design goal is not to mimic centralized rails, but to achieve comparable user trust outcomes through explicit cryptographic session controls, resilient fallbacks, and auditable flow states.

## Implementation References

- `app/routers/records.py`
- `app/routers/safebox.py`
- `app/tasks.py`
- `safebox/acorn.py`
- `docs/specs/ACORN-RESILIENCY-AND-GUARDS.md`
- `docs/specs/NFC-FLOWS-AND-SECURITY.md`
- `docs/specs/OFFERS-AND-GRANTS-FLOWS.md`
