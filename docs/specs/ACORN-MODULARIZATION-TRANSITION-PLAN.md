# Acorn Modularization Transition Plan

## Overview

Acorn currently acts as a high-centrality runtime object that owns many concerns at once: wallet state, proof lifecycle, record flows, relay IO, mint IO, locking, and operational logging. This has enabled rapid feature delivery, but it now creates growing complexity and risk.

This design note defines a safe transition path from the current "god-class" shape to a compartmentalized architecture with clearer boundaries, testability, and lower regression risk.

## Problem Statement

Current symptoms of excessive centralization:

- Large surface area with mixed responsibilities in a single class.
- Cross-cutting side effects (network IO + state mutation + UI signaling assumptions).
- Harder fault isolation under concurrency and partial failure.
- Limited unit-test granularity due to coupled behavior.
- Higher change risk because unrelated features share the same execution core.

## Goals

- Separate concerns into modules with explicit contracts.
- Preserve current runtime behavior during migration.
- Minimize API breakage for routers/tasks/CLI.
- Improve observability around each subsystem.
- Enable future extraction of Acorn into a standalone package.

## Non-Goals

- Full rewrite.
- Immediate replacement of all call sites.
- Breaking existing NFC/QR/payment/record flows.

## Target Component Model

### 1. Identity and Context

Owns:

- key material references (not necessarily generation),
- wallet handle/address identity,
- static config snapshot (relay, mint preferences, currency).

Purpose:

- provide immutable request/runtime context for downstream services.

### 2. Wallet State Repository

Owns:

- wallet info record reads/writes,
- state normalization and serialization logic,
- version/shape compatibility adapters.

Purpose:

- isolate persistence/read-model behavior from business operations.

### 3. Lock and Concurrency Coordinator

Owns:

- lock acquisition/release,
- contention policy and timing instrumentation,
- guarded execution helpers.

Purpose:

- centralize critical-section safety and remove duplicated lock handling patterns.

### 4. Mint/Proof Service

Owns:

- quote checking,
- mint/redeem/swap workflows,
- proof compaction and consolidation,
- proof integrity invariants.

Purpose:

- make payment-state mechanics independent from routing and UI concerns.

### 5. Relay/Event Service

Owns:

- relay query/publish operations,
- event decoding/validation,
- retry and timeout policy for relay IO.

Purpose:

- isolate transport variability from domain logic.

### 6. Record and Blob Transfer Service

Owns:

- SafeboxRecord handling,
- offer/grant/request transfer orchestration,
- blob retrieval/transfer/decryption boundaries.

Purpose:

- decouple record exchange from payment and wallet core code paths.

### 7. Orchestration Facade (Compatibility Layer)

Owns:

- current Acorn-compatible public methods,
- delegation to modular services,
- legacy API stability during migration.

Purpose:

- allow progressive decomposition without breaking external callers.

## Contract-First Refactor Approach

Before moving logic, define narrow interfaces for each new service:

- inputs/outputs,
- error taxonomy,
- idempotency expectations,
- side-effect boundaries.

Then:

- move implementation behind interfaces,
- keep Acorn method signatures stable,
- replace internals with delegation.

## Migration Phases

### Phase 0: Baseline and Guardrails

- Freeze key behavior with smoke/regression tests for:
  - payment flows (Lightning, NFC, token acceptance),
  - record flows (offer/grant/request),
  - lock contention and recovery paths.
- Add lightweight timing/operation telemetry where missing.

### Phase 1: Extract Concurrency and IO Primitives

- Extract lock coordinator first (lowest coupling, highest safety impact).
- Extract relay IO wrapper and mint HTTP wrapper.
- Keep Acorn methods as pass-through delegates.

### Phase 2: Extract Domain Services

- Move proof/mint logic into `MintProofService`.
- Move record/blob flows into `RecordTransferService`.
- Move wallet-info serialization into repository layer.

### Phase 3: Thin Acorn Facade

- Acorn becomes orchestration/composition root only.
- Legacy method names retained for compatibility.
- Internal state fields reduced to context + service references.

### Phase 4: Package Readiness

- Isolate framework-specific dependencies from core domain services.
- Provide stable import surface and semantic versioning policy.
- Prepare PyPI packaging once test and API stability targets are met.

## Safety Constraints

- No behavioral drift in externally visible statuses without explicit migration note.
- All lock-guarded operations must preserve `finally` release semantics.
- Rollback behavior must remain conservative: no "success" without settlement confirmation.
- Keep failure mode explicit and structured for operators.

## Testing Strategy During Refactor

- Golden-path integration tests for existing critical flows.
- Fault-injection tests (timeout, disconnect, stale relay data).
- Contract tests per extracted service.
- Compatibility tests ensuring existing routers/tasks/CLI calls still function.

## Suggested Module Skeleton

- `safebox/acorn/context.py`
- `safebox/acorn/repository.py`
- `safebox/acorn/lock_coordinator.py`
- `safebox/acorn/mint_proof_service.py`
- `safebox/acorn/relay_service.py`
- `safebox/acorn/record_transfer_service.py`
- `safebox/acorn/facade.py` (or keep `acorn.py` as facade)

Note: filenames are illustrative; actual paths can be adjusted to current project layout conventions.

## Risks and Mitigations

- Risk: Hidden coupling causes regressions.
  - Mitigation: phase-by-phase delegation with compatibility tests.
- Risk: Refactor stalls due to broad scope.
  - Mitigation: prioritize high-value extractions (lock + IO) first.
- Risk: Performance regression from indirection.
  - Mitigation: track latency metrics before/after each phase.

## Implementation References

- `safebox/acorn.py`
- `app/tasks.py`
- `app/routers/safebox.py`
- `app/routers/records.py`
- `safebox/cli_acorn.py`
