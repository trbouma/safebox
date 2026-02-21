# Production Change Summary (Latest Main Merge)

## Overview

This document summarizes the major enhancements, fixes, and architectural changes delivered in the latest substantial merge to `main` (the NFC/record-flow stability and hardening wave), plus immediate follow-on hardening and operational updates applied afterward.

It is written for production operators and integrators who need to understand behavior changes, risk reductions, and rollout implications.

## Major Enhancements

### 1) NFC Card Model Moved to Active Secret Mapping

- NFC/NWC token handling was moved to a mapped secret model (`NWCSecret`) rather than deriving secrets directly from wallet private keys.
- Card issuance supports rotation semantics:
  - one active secret set per wallet
  - multiple physical cards can exist
  - rotation invalidates older card payloads
- Result:
  - immediate revocation capability
  - lower blast radius for card compromise
  - clearer lifecycle control for operators and users

### 2) NFC Payment and Record Flow Stability

- NFC request/offer/proof flows were hardened to reduce transport-induced false failures.
- Card preflight validation (`/.well-known/card-status`) is now used consistently for fast-fail revocation checks.
- Record request/offer routes were stabilized for mixed browser/proxy environments.
- Result:
  - fewer broken cross-device NFC interactions
  - better user-visible error semantics for invalid/rotated cards

### 3) POS Flow Modernization

- POS now uses the logged-in wallet session directly (protected route behavior).
- POS invoice lifecycle and status signaling improved:
  - top-of-screen invoice QR
  - paid-state checkmark and completion UX
  - explicit asynchronous settlement signaling
- POS now uses wallet currency context:
  - wallet-selected currency defaults on POS
  - symbol-aware display
  - decimal amount entry (2dp)
- Result:
  - better operator usability
  - fewer mistaken “paid” assumptions
  - less currency-entry friction in real-world deployment

## Critical Reliability and Funds-Safety Fixes

### 4) Ecash Delivery Rollback and Recovery Safeguards

- Addressed a critical risk window where ecash token issuance could occur before confirmed delivery.
- Added delivery-confirmation-aware safeguards in NFC/NWC ecash send paths:
  - best-effort local rollback via token self-accept when delivery fails
  - persistent recovery artifacts (`ecash-recovery-*`) when rollback cannot be confirmed
- Result:
  - reduced probability of silent proof/funds loss during network interruption or refresh timing races
  - improved operator recoverability for uncertain edge cases

### 5) Correct Settlement Status Semantics

- NFC request acceptance no longer implies completion.
- Payment APIs and POS UI now separate:
  - request accepted (`PENDING`)
  - processing
  - terminal settlement (`OK`/`ADVISORY`/`ERROR`)
- Result:
  - improved transactional accuracy in frontend/operator workflows
  - reduced risk of business logic or user actions based on premature “success” states

## Security and Hardening Work

### 6) Exception and Runtime Hardening

- Broad sweep replacing fragile exception handling in critical paths.
- Improved logging/traceability for auth, payment, and record-transmission flows.
- Async/network path cleanup reduced blocking behavior in async execution contexts.
- Result:
  - better operational observability
  - lower latent failure risk under concurrency/load

### 7) Listener and Shutdown Robustness

- NWC/listener shutdown behavior hardened to suppress expected websocket close noise and avoid misleading fatal traces.
- Result:
  - cleaner shutdown behavior
  - easier incident triage and lower alert fatigue

## Platform and Operations

### 8) Database Hardening for PostgreSQL Readiness

- Centralized DB engine handling and startup behavior.
- Added uniqueness safeguards and startup race protections (including concurrent init/currency seed race handling).
- Added Alembic baseline migration scaffolding and operational guidance.
- Result:
  - safer startup in multi-worker environments
  - improved portability from SQLite to PostgreSQL

### 9) Domain-Based Branding Architecture

- Hostname-aware branding lookup with default fallback/bootstrap.
- Branding directory auto-seeding for first-run experience.
- Deployment-friendly volume mapping patterns for container environments.
- Result:
  - multi-domain branding on one service instance with minimal operational overhead

### 10) Build and Container Hardening

- Build/runtime cleanup to reduce context size and tighten image behavior.
- `.dockerignore` and Docker runtime improvements were incorporated in related hardening passes.
- Result:
  - leaner deploy artifacts
  - more predictable build behavior

## User-Visible Behavior Changes (Production)

- NFC cards can be revoked via rotation; old cards fail immediately.
- NFC/POS flows now show explicit pending/processing states before final settlement.
- POS amounts are currency-aware and accept two-decimal input.
- Some invalid/legacy card payload behaviors now fail fast by design.
- Recovery and onboarding paths include stronger error responses and safer failure handling.

## Operator Action Items

1. Review NFC issuance/rotation operational policy with support staff.
2. Monitor logs for `ecash-recovery-*` artifacts and define a recovery playbook.
3. Validate POS behavior in your production browser/device mix (desktop, mobile, NFC-capable clients).
4. If migrating to PostgreSQL, follow migration baseline guidance and test startup under multi-worker mode.
5. Configure and version-control branding files per production hostname.

## Related Specs

- `NFC-FLOWS-AND-SECURITY.md`
- `NWC-NFC-VAULT-EXTENSION.md`
- `PAYMENTS-SAFEBOX-CASHU-LIGHTNING-FALLBACK.md`
- `DATABASE-BACKENDS-AND-MIGRATIONS.md`
- `BRANDING-AND-HOST-RESOLUTION.md`
