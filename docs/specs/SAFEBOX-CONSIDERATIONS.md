# Safebox Considerations

## Overview

This document provides a compact decision framework for Safebox design, implementation, and operations. It is intended as a practical checklist for product, engineering, security, and operations teams.

## Scope

This document covers:

- wallet and key custody assumptions,
- agent and human flow parity,
- protocol and transport boundaries,
- market behavior and abuse controls,
- operational resiliency and incident readiness.

This document does not replace detailed protocol specs. It summarizes cross-cutting concerns and points to authoritative specs.

## Core Considerations

### 1. Identity, Custody, and Recovery

- Define whether each flow is self-custodial, operator-assisted, or hybrid.
- Treat `access_key`, `nsec`, `seed_phrase`, and emergency material as distinct secret classes.
- Enforce immediate secure persistence after onboarding before any social or payment actions.
- Require tested recovery paths for lost-device and key-rotation scenarios.

### 2. Human and Agent Flow Parity

- Keep one protocol surface for human and agent execution where possible.
- Avoid browser-only assumptions in machine workflows (cookies, CSRF session coupling).
- Provide CLI and API parity for critical operations: onboarding, payments, DMs, posts, market actions.
- Document explicit fallback behavior (websocket stream -> GET polling).

### 3. Profile and Address Integrity

- Require complete social profile bootstrap early in lifecycle.
- Keep `nip05` and `lud16` aligned for discoverability and payment interoperability.
- Prefer deterministic avatar generation for unattended agent onboarding.
- Validate profile completeness before DM-centric or social-market flows.

### 4. Transport, Relay, and Discovery Model

- Prefer websocket streaming for low-latency event handling.
- Maintain equivalent polling endpoints for constrained environments.
- Be explicit about relay selection, home relay defaults, and cross-instance behavior.
- Define follow-list semantics clearly for discovery and feed endpoints.

### 5. Payment and Settlement Safety

- Treat zap/invoice failures as expected distributed-system events, not exceptional edge cases.
- Add idempotency and reconciliation checks for non-idempotent payment actions.
- Validate settlement evidence before state transitions (`FILLED`, `REDEEMED`, etc.).
- Prevent self-trading and self-settlement loops at policy and implementation levels.

### 6. Market Integrity and Abuse Controls

- Require canonical lifecycle anchors for market objects.
- Use explicit market namespaces and conformance identifiers.
- Enforce anti-self-trade, stale-order handling, and exact-fill rules.
- Separate protocol-enforced controls from policy-enforced controls in conformance reporting.

### 7. Security and Threat Posture

- Define threat boundaries for wallet core, API layer, relays, and external mints.
- Fail closed on identity mismatch, authority mismatch, and malformed proofs.
- Minimize secret exposure in logs, traces, and analytics systems.
- Maintain explicit incident runbooks for key compromise, replay attempts, and relay degradation.

### 8. Observability and Operations

- Instrument endpoint-level success/failure metrics for payment, DM, market, and stream paths.
- Capture structured error context for external dependency failures (mint, relay, LNURL providers).
- Establish SLOs for API latency, stream freshness, and settlement confirmation windows.
- Run conformance tests continuously for critical market and agent workflows.

### 9. Change Management

- Ship protocol and API changes incrementally with rollback criteria.
- Require compatibility notes for each contract change (`/agent/*`, CLI commands, market tags).
- Version specs and conformance tests together.
- Preserve backwards-compatible fallbacks where feasible.

## Release Gate Checklist

Before production rollout, confirm:

- Identity bootstrap and secret persistence are tested end-to-end.
- Profile completeness checks are active for social and DM flows.
- Websocket and GET fallback paths are both validated.
- Payment and zap failure handling includes retries and reconciliation.
- Market controls (anti-self-trade, stale orders, settlement evidence) are enforced.
- Incident, backup, and recovery runbooks are current and rehearsed.

## Authoritative References

- `docs/specs/AGENT-API.md`
- `docs/specs/AGENT-FLOWS.md`
- `docs/specs/WS-CONFORMANCE.md`
- `docs/specs/mkt/MS-01-coupon-market.md`
- `docs/specs/mkt/MS-01-CONFORMANCE.md`
- `docs/specs/THREAT-MODEL.md`
- `docs/specs/INCIDENT-RESPONSE-AND-KEY-COMPROMISE-RUNBOOK.md`
- `docs/specs/TOIP-ARCHITECTURE-IMPLEMENTATION-CONSIDERATIONS.md`
