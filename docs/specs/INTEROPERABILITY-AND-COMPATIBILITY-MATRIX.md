# Interoperability and Compatibility Matrix

## Overview
This document tracks supported environments, protocol integrations, and fallback behavior across Safebox clients and services.

## Scope
- Browser and device compatibility
- Relay/blob service interoperability
- NFC and QR initiation paths
- Payment interoperability (Safebox-to-Safebox and Lightning fallback)

## Compatibility Dimensions
- Browser families and versions (desktop/mobile)
- TLS/WSS proxy topologies (direct, reverse proxy, VPN edge)
- NFC-enabled device classes and reader behavior
- Legacy rendering behavior for media/PDF records

## Protocol Interoperability
- Nostr event/signature compatibility
- Cashu mint diversity and proof handling
- NWC extension compatibility for vault/payment/record operations
- nAuth envelope interoperability for record presentation

## Fallback Strategy
- If secure websocket path is unavailable, fail explicitly with actionable status.
- If advanced rendering unsupported, use legacy file/link fallback.
- If peer is non-Safebox Lightning address, use Lightning payment path.

## Test Matrix Guidance
- Maintain matrix for each release candidate.
- Mark pass/fail with notes, build identifiers, and known limitations.

## Security Considerations
- Treat compatibility downgrades as security-sensitive; avoid silent degradation.
- Require explicit user-visible status when falling back from secure flows.

## Implementation References
- `docs/specs/OFFERS-AND-GRANTS-FLOWS.md`
- `docs/specs/PAYMENTS-SAFEBOX-CASHU-LIGHTNING-FALLBACK.md`
- `docs/specs/NFC-FLOWS-AND-SECURITY.md`
