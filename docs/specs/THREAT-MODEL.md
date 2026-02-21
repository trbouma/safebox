# Threat Model

## Overview
This document identifies key Safebox threats, trust boundaries, and mitigations across wallet, payment, NFC, and record workflows.

## Scope
- Web app, API, websocket channels
- NWC/NFC vault operations
- Cashu proof lifecycle and transfer
- Record offer/grant/request flows
- Relay and blob storage dependencies

## Assets
- User private keys and derived authorization secrets
- Cashu proofs and ecash transfer tokens
- Encrypted record payloads and blob keys
- Session state, onboarding tokens, and service credentials

## Trust Boundaries
- Browser/client to application service
- Application service to relay and blossom servers
- Insecure trigger channels (QR/NFC) to secure transfer channels
- Operator infrastructure to third-party dependencies

## Primary Threats
- Key compromise and secret exfiltration
- Replay/reuse of stale NFC credentials
- Payment delivery race/failure causing asset inconsistency
- Unauthorized record disclosure via weak access controls
- Websocket interruption leading to false UI state
- Abuse/DoS against relay, blob, or API paths

## Mitigations
- Single-active-secret model with explicit rotation/revocation
- Strong signature/decryption verification on all inbound flows
- Delivery confirmation and rollback/recovery records for ecash transfer failures
- Structured exception handling and traceable operational logging
- Explicit status lifecycle in UI (pending/processing/final)
- Segmented infrastructure, backup relay/blob endpoints, and rate controls

## Residual Risks
- Endpoint compromise on user devices
- Regulatory misuse independent of protocol safeguards
- Third-party dependency outages outside operator control

## Security Considerations
- Threat model must be reviewed after significant protocol/flow changes.
- Security tests must map directly to threat categories and residual risks.

## Implementation References
- `docs/specs/NFC-FLOWS-AND-SECURITY.md`
- `docs/specs/SECURITY-TEST-PLAN.md`
- `docs/specs/RECORD-PRESENTATION-NAUTH-STRATEGY.md`
