# Protocol Normalization Patch Spec (Relay-First KEM)

## Overview

This patch defines a control-plane normalization strategy for record exchange
flows where:

- QR payloads remain compact (no forced data-plane expansion).
- KEM exchange is relay/session bound by default.
- HTTPS KEM discovery is demoted to optional compatibility fallback.

The goal is to reduce protocol fragility from mixed ingress formats and
cross-instance host drift while preserving existing QR/NFC data-plane behavior.

## Scope

In scope:

- Control-plane normalization for offer/request/grant orchestration.
- Canonical envelope contract for relay messages.
- Relay-first KEM acquisition and binding rules.
- Compatibility/migration strategy for existing `nauth` and `nembed` usage.

Out of scope:

- Replacing existing data-plane encryption primitives.
- Re-encoding large data into QR.
- Redesigning wallet storage or blob cryptography semantics.

## Current Problem

Backend ingress currently sees a mix of:

- raw `nauth` strings
- `nembed` payload strings
- partially decoded dict/list objects

This increases branch complexity and can cause:

- parsing ambiguity (`nauth` vs `nembed` vs plain payload)
- repeated listener loops when payload shape is misclassified
- KEM resolution drift across cross-instance deployments

## Target Contract

### 1) Control/Data separation

- `nauth` remains the session/auth identity primitive.
- `nembed` remains the transport/data envelope.
- Control messages SHOULD use a canonical envelope that can carry `nauth` and
  typed control payload together.

### 2) Canonical control envelope

All new relay control messages SHOULD normalize to a typed envelope:

```json
{
  "v": 1,
  "message_type": "offer_auth|offer_record|request_record|kem_update|...",
  "nauth": "nauth1...",
  "body": {},
  "meta": {
    "ts": 1770000000,
    "nonce": "session-nonce",
    "sender_npub": "npub1..."
  }
}
```

Envelope transport MAY be `nembed` encoded for consistency where practical.

### 3) QR minimality rule

QR payloads MUST remain compact:

- QR carries `nauth` or compact session pointer only.
- KEM material MUST NOT be embedded in QR.
- Large payloads remain on relay/data channels.

## Relay-First KEM Policy

### Primary path

KEM material is obtained from relay-authenticated session messages bound to:

- `nauth` nonce
- peer `npub`
- active time window

KEM considered valid only if binding checks pass.

### Compatibility path (optional)

HTTP KEM lookup (`/.well-known/kem`) is compatibility fallback only:

- disabled by default in strict mode
- enabled by flag for transitional deployments
- never authoritative over valid in-session relay KEM

### Fail-closed rules

- If required peer KEM is unresolved, stop and require re-authentication.
- Never substitute local/default service KEM for peer KEM.
- Never downgrade to plaintext.

## Ingress Normalization Pipeline

Introduce one shared ingress classifier/normalizer for request/listener paths:

1. decode input shape once (`string|dict|list`)
2. classify deterministically:
   - `nauth` control
   - `nembed` encoded payload
   - structured object envelope
3. validate schema + session bindings
4. route by `message_type`

No endpoint should perform ad hoc chained parsing logic after normalization.

## Transitional Contract Implemented

Current implementation (pre-full envelope normalization) now enforces:

- verifier/requester `nauth` generation can inherit nonce from initiating
  `source_nauth` for presenter-initiated flows.
- callback auth payload format uses `nauth:nembed(kem_public_key, kemalg)`.
- requester stage-gate remains nonce-bound; presenter announce must occur before
  or with transmittal to avoid auth-loop deadlock.

This preserves current QR compactness while aligning runtime behavior with the
relay-first binding model.

## Backward Compatibility

Transitional support remains for legacy paths:

- legacy `nauth`-only messages accepted
- legacy `nembed` string payloads accepted
- normalized envelope emitted for new flows

Deprecation plan:

1. add metrics on legacy path usage
2. migrate sender paths to canonical envelope
3. disable HTTP KEM fallback in strict mode
4. remove legacy parse branches once usage is near-zero

## Proposed Config Flags

- `RELAY_FIRST_KEM=true|false` (default `true`)
- `ALLOW_HTTP_KEM_FALLBACK=true|false` (default `false`)
- `STRICT_ENVELOPE_MODE=true|false` (default `false` during migration)

## Sequence (Normalized Control Plane)

1. recipient advertises compact `nauth` (QR/NFC entrypoint).
2. sender establishes session and subscribes for relay control messages.
3. recipient sends bound KEM update on relay.
4. sender validates nonce/npub/time-window binding.
5. sender transmits grant/record using validated peer KEM.
6. receiver acknowledges completion through normalized control envelope.

## Message-Type Registry (v1)

### Envelope requirements (all message types)

Required top-level fields:

- `v` (must be `1`)
- `message_type` (string from registry)
- `nauth` (string, `nauth1...`)
- `body` (object)
- `meta.ts` (unix timestamp seconds)
- `meta.nonce` (must match `nauth` nonce)
- `meta.sender_npub` (sender identity)

Validation gates (all message types):

- reject if `meta.nonce` does not match `nauth` nonce
- reject if `meta.ts` outside active window
- reject if `meta.sender_npub` does not match authenticated sender
- reject unknown `v` or unknown `message_type` in strict mode

### Registry table

| `message_type` | Purpose | Required `body` fields | Producer | Consumer |
| --- | --- | --- | --- | --- |
| `offer_request` | Recipient requests sender offer flow start | `grant_kind` | recipient wallet/agent | sender wallet |
| `offer_auth` | Acknowledge recipient channel and bind recipient identity | `recipient_npub`, `auth_relays` | recipient wallet/service | sender wallet |
| `kem_update` | Provide peer KEM material bound to current session | `kem_public_key`, `kemalg` | recipient wallet/service | sender wallet |
| `offer_record` | Sender transmits selected offer/grant payload | `record_kind`, `record_payload` | sender wallet/service | recipient wallet/service |
| `offer_ack` | Receiver confirms accepted/stored offer | `record_id`, `status` | recipient wallet/service | sender wallet |
| `request_record` | Requester asks presenter for a record | `grant_kind`, `request_kind` | requester wallet | presenter wallet |
| `request_auth` | Presenter auth response for request flow | `presenter_npub`, `auth_relays` | presenter wallet/service | requester wallet |
| `present_record` | Presenter sends record presentation payload | `record_kind`, `record_payload` | presenter wallet/service | requester wallet/service |
| `present_ack` | Requester confirms presentation ingest | `record_id`, `status` | requester wallet/service | presenter wallet |
| `error` | Structured flow error with retry hint | `code`, `detail` | any | any |

### Message-specific rules

`offer_request`:

- MUST NOT include KEM material.
- Used to bootstrap recipient-initiated flow only.

`kem_update`:

- MUST be session-bound (`nauth` nonce + sender/recipient npub binding).
- Last valid in-window `kem_update` wins for the session.
- If absent, sender may use compatibility HTTP KEM only when enabled.

`offer_record` and `present_record`:

- `record_payload` may be:
  - encoded `nembed` string, or
  - normalized object containing encrypted/plain fields.
- Consumer normalization MUST accept both during migration.

`error`:

- `code` SHOULD be machine-stable (for example `KEM_UNAVAILABLE`,
  `NONCE_MISMATCH`, `WINDOW_EXPIRED`).
- `detail` SHOULD include operator-actionable guidance.

### Legacy mapping (migration)

- legacy raw `nauth` handshake -> normalize to `offer_request` or
  `request_record` based on scope.
- legacy auth reply with inline KEM fields -> normalize to `offer_auth` +
  `kem_update`.
- legacy plain record payload objects -> normalize to `offer_record` or
  `present_record` with object `record_payload`.
- legacy `nembed` payload strings -> normalize to `offer_record` or
  `present_record` with string `record_payload`.

## Security Considerations

- Binding KEM to session nonce and peer identity limits replay/substitution.
- Relay-first KEM reduces dependence on host resolution and HTTP topology.
- Keeping QR compact reduces data leakage and parsing burden at scan edge.
- Fail-closed behavior preserves quantum-safe guarantees under uncertainty.

## Implementation References

- `/Users/trbouma/projects/safebox-2/app/routers/records.py`
- `/Users/trbouma/projects/safebox-2/app/nwc.py`
- `/Users/trbouma/projects/safebox-2/app/utils.py`
- `/Users/trbouma/projects/safebox-2/docs/specs/OFFERS-AND-GRANTS-FLOWS.md`
- `/Users/trbouma/projects/safebox-2/docs/specs/NFC-FLOWS-AND-SECURITY.md`
