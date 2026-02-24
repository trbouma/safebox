# Safebox Incremental Change Hardening Strategy

## Purpose
This document defines the DevOps strategy used to evolve Safebox safely while production-like services remain active. The core goal is to reduce blast radius, shorten diagnosis cycles, and improve reliability of NFC, QR, payment, and record flows without large risky rewrites.

## Operating Principle
Treat every change as if we are modifying a live aircraft in flight:
- isolate one failure mode at a time
- make the smallest defensible patch
- verify behavior in controlled environments before promotion
- keep rollback paths available

## Environment Model
Use clear separation of environments and data stores:
- local dev: fast iteration, isolated database (for example `safeboxdev`)
- test/staging server: production-like network and latency validation
- production: only promoted changes that passed targeted and sanity checks

Environment parity requirements:
- explicit `HOME_RELAY`, `HOME_MINT`, and `DATABASE`
- avoid cross-environment database reuse
- avoid hidden defaults for relay topology during flow debugging

## Change Workflow
1. Reproduce a single issue with logs and minimal steps.
2. Confirm scope (UI, websocket, relay, NWC, database, mint, or mixed).
3. Apply narrow patch (no opportunistic refactors).
4. Run local sanity checks:
   - syntax/compile checks
   - flow-specific smoke test (only impacted path)
5. Deploy to test/staging.
6. Run post-deploy sanity matrix.
7. Promote only after targeted success.

## Patch Discipline
Apply these rules for each fix:
- one intent per patch
- preserve existing successful paths
- prefer additive guards/fallbacks over broad behavior rewrites
- remove temporary debug code before promotion
- do not combine protocol changes with unrelated UI cleanup in same patch

## Reliability Priorities for Flow Work
For NFC/QR and record/payment flows, prioritize:
- deterministic sequencing (listener before sender where race is possible)
- explicit timeout and terminal statuses
- null/empty/"None" safe parsing for protocol fields
- consistent source-of-truth for kind/scope/grant values
- user-visible failure messages that are actionable

## Database and Migration Safety
- initialize schema with Alembic before app boot when using PostgreSQL
- keep migration baseline current in source control
- do not rely on runtime `create_all` in multi-worker production startup
- validate migration against a clean database before deployment

## Deployment Guardrails
Before deploying:
- confirm clean git state
- verify intended branch and commit
- confirm environment variables for target instance
- confirm relay reachability from inside container

During deployment:
- run migrations first
- start service
- monitor startup logs for schema, relay, websocket, and mint errors

After deployment:
- run post-deploy sanity checks in `docs/devops/post-deploy-sanity-check.md`
- verify at least one full happy-path per critical flow

## Observability and Triage
When investigating failures, capture:
- last 20-50 relevant lines from service logs
- request path and method
- flow step where stall occurs
- effective environment values (relay/mint/database target)

Classify incidents by layer:
- protocol/auth mismatch
- websocket lifecycle/race
- relay reachability/latency
- mint connectivity/DNS
- database/migration/state

## Rollback Strategy
If a patch degrades reliability:
- revert only the minimal offending commit(s)
- preserve unrelated hardening already validated
- redeploy and rerun targeted sanity checks
- document root cause and retained mitigations

## Release Gating for Critical Flows
A change is production-ready only when all pass on test/staging:
- Offer record: QR and NFC
- Request record: QR and NFC
- Payment receive path (invoice + NFC where applicable)
- Completion status signaling in UI/websocket
- Recovery from timeout/cancel paths

## Continuous Improvement Loop
After each incident or fragile flow discovery:
1. add or refine guard/fallback
2. add a corresponding sanity-check step
3. update the relevant spec/runbook
4. keep changes small and composable

This discipline is intentionally conservative. It trades speed of large rewrites for predictable service behavior and faster long-term delivery.
