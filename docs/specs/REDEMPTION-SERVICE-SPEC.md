# Redemption Service Specification
**Version**: `0.1`  
**Status**: Draft  
**Date**: 2026-03-06

---

## Overview

This specification defines a generic challenge/response redemption service for provider-managed secret records.

A provider registers one or more secret records with the service. Each record is bound to a Nostr public key (`npub`) and can be redeemed a limited number of times. A client must complete a challenge signed by the corresponding key before the service releases the secret.

This spec is intended for future implementation and is independent from market-specific settlement flows.

## Scope

This specification defines:

- provider registration of secret records
- optional service-side keypair generation when provider `npub` is not supplied
- redemption database record requirements
- two-step redemption flow (`challenge` then `verify/redeem`)
- decrement and exhaustion behavior for `redemptions_left`
- error behavior for verification failure and exhausted records

This specification does not define:

- settlement logic or payment rails
- provider business policy beyond redemption counter enforcement
- downstream entitlement execution after secret release

## Normative Language

The key words `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` in this document are to be interpreted as described in RFC 2119 and RFC 8174.

## Data Model

### Registered Secret Record

Each registered record MUST persist at least:

- `record_id`: service-generated stable identifier
- `npub`: Nostr public key bound to the record
- `secret`: provider secret value to release on successful redemption
- `secret_description`: human-readable description of the secret
- `current_challenge`: latest issued challenge value (nullable before first challenge)
- `challenge_expires_at`: expiry of `current_challenge` (nullable before first challenge)
- `redemptions_left`: remaining successful redemption count
- `created_at`: creation timestamp
- `updated_at`: last update timestamp

`redemptions_left` MUST be initialized from provider registration input and MUST be a non-negative integer.

## API Contract

### 1. Register Records

`POST /redemption/v1/register`

Registers one or more secret records.

Request:

```json
{
  "provider_npub": "npub1...",
  "records": [
    {
      "secret": "string",
      "secret_description": "string",
      "redemptions": 3
    }
  ]
}
```

Rules:

- `records` MUST contain at least one entry.
- `redemptions` MUST be `>= 0`.
- If `provider_npub` is present, all records in this request are bound to that `npub`.
- If `provider_npub` is omitted, service MUST generate a fresh Nostr keypair and bind all records in this request to the generated `npub`.
- If generated, service MUST return both generated `nsec` and `npub` in the response.
- Generated `nsec` MUST be returned only at registration time; service MUST NOT return it again from any endpoint.

Response:

```json
{
  "provider_npub": "npub1...",
  "generated": true,
  "provider_nsec": "nsec1...",
  "registered": [
    {
      "record_id": "rec_...",
      "secret_description": "string",
      "redemptions_left": 3
    }
  ]
}
```

If `provider_npub` is provided, `generated` is `false` and `provider_nsec` MUST be absent.

### 2. Request Challenge

`POST /redemption/v1/challenge`

Creates and stores a fresh challenge for a specific record.

Request:

```json
{
  "record_id": "rec_..."
}
```

Rules:

- Service MUST fail if `record_id` does not exist.
- Service MUST fail if `redemptions_left == 0`.
- Service MUST generate a fresh unpredictable challenge for each request.
- Service MUST replace `current_challenge` with the new challenge and set `challenge_expires_at`.

Response:

```json
{
  "record_id": "rec_...",
  "npub": "npub1...",
  "challenge": "base64url_nonce_or_string",
  "challenge_expires_at": "2026-03-06T18:20:00Z"
}
```

### 3. Verify Response and Redeem

`POST /redemption/v1/redeem`

Verifies client proof against the stored challenge and returns secret when valid.

Request:

```json
{
  "record_id": "rec_...",
  "challenge": "base64url_nonce_or_string",
  "signature": "hex_or_bech32_signature",
  "signature_scheme": "nostr_sig_v1"
}
```

Rules:

- Service MUST fail if `record_id` does not exist.
- Service MUST fail if `redemptions_left == 0`.
- Service MUST fail if no active `current_challenge` exists.
- Provided `challenge` MUST match stored `current_challenge`.
- Service MUST fail if challenge is expired.
- Service MUST verify `signature` against stored record `npub` and challenge payload.
- On verification failure, service MUST return an authorization error and MUST NOT decrement `redemptions_left`.
- On success, service MUST atomically:
  - decrement `redemptions_left` by exactly 1
  - clear or rotate `current_challenge`
  - return the secret payload

Success response:

```json
{
  "record_id": "rec_...",
  "secret": "string",
  "secret_description": "string",
  "redemptions_left": 2
}
```

## Signature and Verification Profile

Default profile for v0.1:

- `signature_scheme`: `nostr_sig_v1`
- message to sign: exact `challenge` string as issued
- verification key: stored record `npub`

Implementations MAY support additional signature schemes, but MUST require explicit `signature_scheme` identification when multiple schemes are enabled.

## State and Concurrency Rules

- Redemption verification and decrement MUST be atomic to prevent double redemption under concurrency.
- Challenge issuance SHOULD invalidate prior challenge for the same `record_id`.
- A challenge SHOULD have a short TTL (recommended 60-300 seconds).
- Services SHOULD rate-limit challenge and redeem endpoints per `record_id` and client identity.

## Error Semantics

The service MUST return machine-readable error codes. Minimum required:

- `record_not_found`
- `redemptions_exhausted`
- `challenge_required`
- `challenge_mismatch`
- `challenge_expired`
- `signature_invalid`
- `invalid_request`

Behavioral requirements:

- `redemptions_exhausted` MUST be returned whenever `redemptions_left == 0`.
- `signature_invalid` MUST be returned when signature verification against record `npub` and challenge fails.

## Security Considerations

- Stored `secret` values are highly sensitive and SHOULD be encrypted at rest.
- Generated `nsec` is highly sensitive and MUST only be returned once over TLS.
- Service logs MUST NOT include `nsec`, raw `secret`, or raw signature material.
- Challenge values MUST be unpredictable and single-use.
- Implementations SHOULD include audit logs for registration, challenge issuance, redemption success/failure, and counter transitions.

## Implementation References

Planned implementation touchpoints:

- provider/agent registration surface (future)
- redemption service router and persistence layer (future)
- signature verification helper (`npub` + challenge + signature)
- transactional decrement guard in database
