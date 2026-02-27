# Baseline Synopsis v0.1.0-hardening-baseline

## Purpose

This document summarizes the hardening wave completed for Safebox and captured by tag:

- `v0.1.0-hardening-baseline`

The goal of this baseline was to make QR and NFC record/payment flows reliable under real deployment conditions, including relay jitter, cross-instance mismatch, asynchronous timing races, and partial upstream failures.

## Executive Summary

Safebox moved from "feature-complete but timing-fragile" to "operationally resilient" for core interaction flows. The main outcomes were:

- stable QR and NFC offer/request record flows
- improved POS/NFC payment reliability semantics
- explicit fail-closed behavior for quantum-safe KEM requirements
- reduced stale-event replay behavior in async listeners
- improved cross-instance compatibility and diagnostics
- clearer production runbooks/specification coverage for operators

## Core Problems Identified

### 1) Race Conditions in Browser/Websocket Coordination

Observed behavior:

- browser submitted before recipient-auth KEM material was available
- websocket listeners were sometimes closed too early
- flows reported completion while backend processing still continued

Impact:

- false "not quantum-safe yet" failures
- stalled UX or premature completion state

### 2) Stale Relay Record Selection

Observed behavior:

- listeners and NWC ingestion could pick older records of the same kind
- stale records triggered wrong payloads and wrong blob references

Impact:

- false completions
- blob transfer warnings like `source_blob_missing`
- validation confusion in request/present flows

### 3) Cross-Instance KEM and Relay Drift

Observed behavior:

- QR path worked while NFC path stalled
- sender/worker used different effective relay sets
- KEM was occasionally unavailable at NFC submit time

Impact:

- auth waits with repeated empty polls
- flow stalls despite otherwise healthy services

### 4) Payload Normalization Overreach

Observed behavior:

- NWC offer ingestion normalized structured payloads too aggressively
- signed event envelopes were flattened to plain text

Impact:

- downstream verification showed `Plain Text Cannot Validate`

## Hardening Changes Implemented

## A. Frontend Flow Guards

- offer page now resets per-attempt channel state
- added bounded wait for quantum-ready channel before hard failure
- NFC submit path can proceed without browser KEM when server-side resolution is available
- offer auth websocket now closes cleanly after successful auth/transmit trigger
- request flow listener lifecycle corrected to avoid premature shutdown before first NFC submit

## B. Backend Listener and Polling Controls

- `listen_for_request` hardened with robust payload parsing (`split(":", 1)`)
- auth candidate selection hardened with session binding:
  - nonce matching required for auth response pickup
  - optional transmittal target binding (`transmittal_pubhex`) where applicable
  - candidate preference for `nauth:nembed` over plain `nauth`
- strict live-window behavior enforced for active QR request/presentation listeners
- fallback broad-history polling made explicit/controlled rather than implicit everywhere
- NWC `offer_record` polling hardened with:
  - reverse ordering
  - bounded retries
  - selective fallback behavior
  - stale record filtering by initiator endorsement + active time window

## C. Quantum-Safe Channel Integrity

- retained fail-closed rule for missing/invalid peer KEM in required flows
- removed unsafe local-default KEM substitution in cross-party exchange paths
- added server endpoint for recipient KEM metadata:
  - `GET /.well-known/kem`
- NFC offer acceptance can resolve recipient KEM server-side when browser state is missing

## D. NWC Transport Reliability

- NWC listener now subscribes across all configured `NWC_RELAYS` (not only index 0)
- added explicit auth/transmittal relay-resolution logs for diagnosis
- reduced ambiguous extra signaling (removed trailing duplicate auth resend in NFC offer ingest path)

## E. Validation and Content Integrity

- event verification gated to true signed-event payloads
- signed event payloads are preserved through NWC offer ingestion
- non-event payload normalization remains for user-friendly rendering

Result:

- request-by-NFC verification works without regressing plain text handling

## F. Blob Transfer Safety

- original blob transfer remains non-fatal when source blob is missing
- flow continues with available record data instead of aborting entire exchange

This protects flow continuity while surfacing actionable warnings in logs.

## Operational Behavior After Hardening

Expected steady-state behavior:

- QR offer/request waits for live records, not stale history
- NFC offer/request behaves consistently with QR semantics
- cross-instance flows succeed when relay/KEM configs are aligned
- warnings are diagnostic, not silent failures
- user-visible states track actual transaction phases more accurately

## Deployment and Configuration Requirements

For production parity with this baseline:

1. Align relay settings between web app and NWC worker:
   - `AUTH_RELAYS`
   - `NWC_RELAYS`
   - record transmittal relay settings where used
2. Restart both web and worker processes after relay/KEM config changes.
3. Keep KEM material configured and consistent with runtime policy.
4. Verify DNS/network reachability to relays, mint, and blob services from inside containers.

## Recommended Post-Deploy Validation (Minimum)

1. Same-instance:
   - Offer by QR (text + image)
   - Offer by NFC (text + image)
   - Request by QR
   - Request by NFC
2. Cross-instance (both directions):
   - QR offer/request
   - NFC offer/request
3. Confirm logs show:
   - resolved relay/kind diagnostics
   - no indefinite auth polling loops
   - no stale immediate completion on request listeners
4. Stale-history replay guard:
   - keep prior auth DMs in relay history and run fresh NFC offer session
   - confirm listener selects current nonce-bound candidate instead of stale auth payload

## Architectural Outcome

The baseline did not rely on large rewrites. Instead, it applied incremental, targeted changes at failure boundaries:

- browser orchestration boundaries
- relay polling boundaries
- NWC ingress boundaries
- KEM negotiation boundaries
- payload verification boundaries

This preserved existing feature behavior while removing major fragility paths.

## Status

`v0.1.0-hardening-baseline` is a suitable stable base for:

- cross-instance operator testing
- release candidate validation
- feature branching (for example agent recipient-first offer workflow)
