# nAuth Extensible Handshake

## Overview

This document defines a flexible, step-driven handshake model for `nauth` so Safebox can add, remove, or reorder security and transport steps without breaking existing flows.

The goal is to support:

- QR-initiated and NFC-initiated interactions
- optional and required security steps (including PQC exchange)
- resumable handshakes under relay/network delay
- backward compatibility across protocol versions

## Problem Statement

Current `nauth` sequences can become rigid when new checks are introduced (for example, extra challenge/response, pin policy, or trust-list checks).  
A fixed sequence increases breakage risk when adding capabilities.

An extensible handshake allows the protocol to evolve while preserving interoperability.

## Design Principles

- Versioned envelopes (`protocol`, `version`)
- Explicit step state (`next_step`, `status`)
- Capability negotiation before mandatory cryptographic operations
- Signed transcript chaining between steps
- Timeouts and retry semantics per step
- Graceful downgrade only when policy allows

## Handshake Envelope

All handshake messages use a common envelope:

```json
{
  "protocol": "nauth",
  "version": 1,
  "flow_type": "record_offer",
  "session_id": "uuid-or-random-id",
  "initiator": "npub1...",
  "responder": "npub1...",
  "capabilities": ["pqc_kem", "sig_verify", "blob_xfer"],
  "policy": {
    "require_pqc": true,
    "require_sig_verify": true,
    "allow_downgrade": false
  },
  "step": {
    "id": "pqc_kem_init",
    "seq": 2,
    "required": true,
    "timeout_s": 20,
    "status": "ok",
    "next_step": "record_meta"
  },
  "payload": {},
  "transcript_hash_prev": "hex-or-null",
  "signature": "hex"
}
```

## Step Model

Each step has:

- `id`: stable step name
- `seq`: logical sequence index
- `required`: whether flow must stop on failure
- `timeout_s`: step-level timeout
- `status`: `ok`, `pending`, `failed`, `skipped`
- `next_step`: explicit pointer, supports branching

Recommended base step IDs:

- `hello`
- `capability_negotiation`
- `pqc_kem_init`
- `pqc_kem_ack`
- `auth_challenge`
- `auth_response`
- `record_meta`
- `blob_transfer`
- `verification`
- `finalize`

## Transcript Chaining

Each step should bind to prior state:

- `transcript_hash_prev` = hash of prior accepted envelope
- Step payload signed by sender key
- Receiver validates signature and chain continuity before advancing

Benefits:

- Detects replay/reordering
- Enables robust resume after disconnect
- Preserves auditability

## Capability and Policy Negotiation

1. Initiator advertises capabilities and baseline policy.
2. Responder replies with supported capabilities and effective policy.
3. Flow resolves required steps:
   - if `require_pqc=true` and peer lacks PQC capability -> fail
   - if downgrade allowed -> route to configured fallback path

Policy knobs:

- `require_pqc`
- `require_pin`
- `require_trust_anchor`
- `max_step_retries`
- `allow_downgrade`

## Flexible Sequence Examples

### A) Record Offer (QR) with PQC

1. `hello`
2. `capability_negotiation`
3. `pqc_kem_init`
4. `pqc_kem_ack`
5. `record_meta`
6. `blob_transfer`
7. `verification`
8. `finalize`

### B) Record Request (NFC) with PIN Gate

1. `hello`
2. `capability_negotiation`
3. `auth_challenge`
4. `auth_response` (PIN-derived proof/policy check)
5. `pqc_kem_init`
6. `pqc_kem_ack`
7. `record_meta`
8. `blob_transfer`
9. `finalize`

### C) Downgrade-Allowed Compatibility Path

1. `hello`
2. `capability_negotiation`
3. PQC unavailable
4. if `allow_downgrade=true` -> `record_meta` with existing secure channel
5. `finalize`

## State Machine Behavior

Engine requirements:

- Step handlers are registered by `id`.
- Unknown optional steps are skipped.
- Unknown required steps fail closed.
- Retry bounded by policy.
- Resume starts from last accepted step by `session_id`.

Suggested status terminal states:

- `COMPLETED`
- `FAILED_POLICY`
- `FAILED_TIMEOUT`
- `FAILED_VERIFICATION`

## Error Handling

Per-step error object:

```json
{
  "code": "FAILED_TIMEOUT",
  "step_id": "pqc_kem_ack",
  "retryable": true,
  "detail": "ack not received within 20s"
}
```

Rules:

- Required-step failure aborts flow.
- Optional-step failure marks `skipped` and continues if policy allows.
- Timeouts emit explicit step-level failure, not generic transport error.

## Security Considerations

- No silent downgrade when `require_pqc=true`.
- Bind each step to transcript hash to prevent splice/replay.
- Include nonce/challenge in auth steps to prevent reflection.
- Enforce strict timeout and retry ceilings to reduce DoS amplification.
- Keep transport TLS as channel protection; treat payload security as primary.

## Implementation Strategy (Non-Breaking)

1. Introduce envelope and step registry behind existing nauth entry points.
2. Map current fixed flows into step handlers with identical behavior.
3. Enable negotiated optional steps (feature flags/policy switches).
4. Migrate QR/NFC handlers to read `next_step` from protocol state.
5. Add regression tests for current flow parity before enabling new steps.

## Implementation References

- `app/nwc.py`
- `app/routers/records.py`
- `app/routers/lnaddress.py`
- `app/utils.py`
- `docs/specs/NAUTH-PROTOCOL.md`
- `docs/specs/RECORD-PRESENTATION-NAUTH-STRATEGY.md`
