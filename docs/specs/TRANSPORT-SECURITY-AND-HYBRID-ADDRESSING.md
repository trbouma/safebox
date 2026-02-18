# Transport Security and Hybrid Addressing in Safebox

## Overview

Safebox treats HTTPS/TLS and WSS as transport-level protections, not as the only security boundary.  
Payload-level protection is applied on top because end-to-end TLS cannot be assumed across all real-world paths.

## Scope

This specification covers:

- transport-level security posture (HTTPS/TLS/WSS)
- payload-level security layering rationale
- hybrid addressing model (DNS-friendly identifiers + `npub` endpoints)

This specification does not define cipher-suite configuration or infrastructure hardening baselines.

## Layer 1: Transport Security (HTTPS, TLS, WSS)

Safebox uses encrypted transports for network hops:

- HTTPS for web/API endpoints (for example LNURL and `.well-known` discovery)
- WSS for websocket and Nostr relay communication

Examples in code:

- LNURL discovery: `/.well-known/lnurlp/{name}`
- Safebox metadata discovery: `/.well-known/safebox.json/{name}`
- Relay/websocket URLs configured as `wss://...`

This protects traffic in transit between adjacent peers/hops.

## Why Transport Security Is Not Enough

Safebox assumes TLS may terminate or be observed at intermediate infrastructure layers:

- reverse proxies/load balancers
- relay operators and third-party infra
- cross-domain discovery and callback chains
- DNS-based redirection/trust ambiguities

Because of that, Safebox does not rely on TLS alone for sensitive data confidentiality.

## Layer 2: Payload Security on Top

Safebox applies application-layer cryptographic protection to payloads:

- NIP-44 encryption for wallet/record content
- Gift-wrapped secure transmittal for Nostr message transport (`secure_transmittal`)
- Extended NIP-44 usage for larger structured payloads where needed
- ML-KEM derived shared-secret encryption for quantum-safe record payload paths

So even if transport is terminated or replayed through intermediaries, sensitive payload fields remain cryptographically protected.

## Minimizing DNS Dependency with npub Endpoints

Safebox aims to reduce hard dependency on DNS names by using `npub`/pubkey identities as addressable endpoints for actual secure transmittal.

Pattern:

1. user-facing input often starts with DNS-friendly identifiers (for example Lightning address)
2. Safebox resolves metadata (`.well-known` endpoints)
3. Safebox obtains public-key identity + relay data
4. communication pivots to key-addressed Nostr transport (`npub`/hex pubkey + relay list)

Relevant behavior appears in:

- Safebox metadata endpoint: `/.well-known/safebox.json/{name}`
- conversion utilities (`hex_to_npub`, `npub_to_hex`)
- secure transmittal methods that target recipient public keys

## Hybrid Approach for Adoption

Safebox intentionally uses a hybrid model:

- Human-friendly identifiers for onboarding and usability:
  - Lightning addresses (`name@domain`)
- Key-native addressing for secure machine-to-machine operations:
  - `npub` + relay-directed transmittal

This balances ease of use with stronger cryptographic endpoint identity.

## NWC Extension in Practice

Safebox extends Nostr Wallet Connect patterns for application flows (including ecash transfer operations):

- NWC URI form is used (`nostr+walletconnect://...`)
- Safebox publishes and processes NWC instructions over Nostr events
- extended methods include flows such as `pay_ecash`
- payloads are carried in encrypted messages and often wrapped in compact `nembed` objects

This allows a familiar Lightning-like UX while moving actual Safebox-native settlement and transmittal to pubkey-addressed secure messaging when available.

## Operational Summary

- HTTPS/TLS/WSS: required baseline for hop security.
- Payload crypto: required for end-to-end confidentiality and integrity assumptions.
- DNS names: used for discovery and user convenience.
- `npub` identities: preferred for final addressing and secure transmittal.

Safebox is therefore neither “DNS-only” nor “key-only”; it is deliberately hybrid to maximize usability and interoperability without giving up cryptographic control at the payload layer.

## Implementation References

- `/Users/trbouma/projects/safebox-2/app/main.py`
- `/Users/trbouma/projects/safebox-2/app/routers/lnaddress.py`
- `/Users/trbouma/projects/safebox-2/safebox/acorn.py`
- `/Users/trbouma/projects/safebox-2/app/nwc.py`
