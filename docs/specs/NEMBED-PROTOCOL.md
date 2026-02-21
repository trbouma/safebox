# nembed Protocol

## Overview

`nembed` is a Safebox extension that packages arbitrary JSON payloads into a Bech32-encoded Nostr-style object.  
It follows the same high-level pattern as other NIP-19 entities (`npub`, `nsec`, `note`, `nprofile`, `nauth`) by using:

- a human-readable prefix (HRP): `nembed`
- Bech32 data payload (5-bit groups)
- Bech32 checksum for error detection

In Safebox, `nembed` is used as a transport envelope for compact payload exchange in QR, NFC, and text-based flows.

## Scope

This specification defines:

- the `nembed` encoding model used by Safebox
- supported plain and compressed payload variants
- rationale for Bech32 selection in noisy channels

This specification does not define:

- business-level authorization policy for each payload type
- encryption schemes layered above/below `nembed`

## How nembed Extends Bech32 Nostr Objects

Standard NIP-19 entities typically encode fixed key/event structures, often with TLV fields.  
`nembed` extends this model by encoding a JSON payload directly (or compressed JSON) under a new HRP:

- `nembed1...`

Safebox supports two variants:

1. `create_nembed(json_obj)`
- accepts a JSON object (`dict`)
- serializes to JSON bytes
- converts 8-bit bytes to 5-bit groups
- Bech32-encodes with HRP `nembed`

2. `create_nembed_compressed(json_obj)`
- accepts a JSON object or list
- gzip-compresses serialized JSON first
- converts compressed bytes to 5-bit groups
- Bech32-encodes with HRP `nembed`

Decoding is the inverse:

- `parse_nembed(...)` for plain JSON payloads
- `parse_nembed_compressed(...)` for gzip-compressed payloads

## Typical Payloads in Safebox

`nembed` is intentionally payload-agnostic. In current Safebox flows, examples include:

- NFC payment token payloads (`h`, `k`, `a`, optional `n`)
  - `h`: host
  - `k`: encrypted vault token
  - `a`: default amount
  - `n`: optional NFC mode/default flag
- record transfer payload bundles
- transmittal helper material in record and wallet-connect workflows

This lets Safebox use one portable wrapper across multiple features without creating a new encoding per feature.

## Why Bech32 (vs Base58 or Base64)

Safebox expects encoded payloads to be passed through insecure and/or noisy channels:

- camera QR scans under poor lighting
- NFC interactions with partial reads/retries
- manual copy/paste, messaging apps, logs, and redirects

In that environment, robust error detection is critical.

Bech32 is preferred because:

- it includes an integrated checksum optimized for catching common transcription/scanning errors
- its character set is restricted to reduce confusion and improve human handling
- it is case-normalized in practice (typically lowercase), reducing case-related corruption
- it cleanly separates type with HRP (`nembed`) from payload data

Compared alternatives:

- Base64:
  - not self-checking by default
  - includes symbols (`+`, `/`, `=`) that are awkward in URLs, shells, and some text channels
  - case-sensitive and easier to mangle in transit
- Base58:
  - better human readability than Base64 but no mandatory built-in checksum at the encoding layer
  - less aligned with Nostr’s existing Bech32 object ecosystem

For Safebox, Bech32 provides stronger operational reliability where channel noise and accidental mutation are expected.

## Security Considerations

- `nembed` is an encoding envelope, not encryption by itself.
- Sensitive fields should be encrypted before embedding (for example with NIP-44 and/or ML-KEM-derived keys in relevant flows).
- Always validate decoded payload structure and required keys before acting on it.
- Treat checksum failures as hard parse errors, not soft warnings.

## Design Intent

`nembed` keeps payload exchange:

- portable (QR/NFC/text)
- type-identifiable (`nembed` HRP)
- resilient to channel noise (Bech32 checksum)
- flexible enough for evolving JSON payload schemas

That makes it a practical extension to the Nostr Bech32 object family for Safebox-specific transmittal needs.

## Implementation References

- `app/utils.py`
