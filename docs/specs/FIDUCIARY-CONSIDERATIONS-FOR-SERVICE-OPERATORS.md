# Fiduciary Considerations for Safebox Service Operators

## Overview

Safebox is designed to support sovereign user control of funds and records through private-key-based security and application-layer encrypted payloads. This design reduces reliance on centralized financial and information intermediaries. It does **not** remove legal obligations for users or operators.

This document outlines operator-level fiduciary and compliance considerations for production deployments.

## Core Position

1. User privacy is paramount.
2. Legal compliance remains mandatory.
3. Safebox is not a law-enforcement engine and does not itself adjudicate legality.
4. Operators should run Safebox in a way that demonstrates non-complicity in unlawful conduct.

## Payments: Regulatory and Fiduciary Considerations

Safebox payment flows (including Cashu and Lightning-interoperable paths) may still trigger local obligations, depending on jurisdiction and business model.

Operators should assume that private payment messaging can still be subject to:

- financial services regulation
- anti-money-laundering and sanctions regimes
- recordkeeping and reporting requirements
- consumer protection obligations

### Operator Guidance

- Determine whether your service model is custodial, non-custodial, or hybrid in each jurisdiction.
- Maintain policy documentation for:
  - prohibited uses
  - sanctions/blocked-party response
  - suspicious activity escalation
  - lawful process handling
- Keep auditable operational evidence that can show:
  - what the platform did
  - what it did not do
  - where user-controlled cryptographic authority begins and ends

## Records and Data Stewardship Considerations

Safebox supports transfer and storage of sensitive records. Even encrypted/private records may be governed by local privacy and information stewardship law.

Operators should assume applicability (as relevant) of:

- privacy and data protection statutes
- health, financial, or sector-specific confidentiality rules
- breach notification and incident response obligations
- retention/deletion and lawful access requirements

### Operator Guidance

- Define a data classification and stewardship policy for:
  - metadata
  - encrypted payload references
  - logs and diagnostics
- Minimize retention of personally identifying metadata where feasible.
- Implement role-based access and least-privilege controls for operator staff.
- Document incident response for unauthorized disclosure, key compromise, and service abuse.

## System Independence Does Not Authorize Illegal Use

Safebox architecture is intentionally independent of legacy financial and information authorities. This architectural independence is a technical property, not a legal exemption.

Operators and users should treat this as a strict principle:

- The system must not be marketed, configured, or operated as a tool to evade lawful obligations.
- Terms of service and acceptable use policies should explicitly prohibit illegal activity.
- Enforcement should focus on account/session controls and lawful process compliance, not mass surveillance.

## Private Key Responsibility Model

Safebox vests security authority in private keys.

### User Responsibility

- Users are expected to protect private keys and recovery material with strong operational discipline.
- Loss or compromise of private keys can result in loss of control over funds and records.

### Operator Responsibility

- Make key-risk implications clear in UX and operator communications.
- Provide secure defaults and guidance for:
  - key backup
  - secret rotation
  - card/token revocation
- Protect service-side keys (`SERVICE_NSEC`, signing keys, deployment secrets) with strong secret management controls.

## Lawful Process and Non-Complicity

Operators should expect and prepare to respond to lawful requests from competent authorities.

### Recommended Controls

- Maintain a documented lawful request workflow:
  - intake
  - jurisdiction and validity review
  - scope minimization
  - response logging
- Preserve tamper-evident operational logs that show:
  - request/response timing
  - status transitions
  - failure/recovery paths
  - access decisions
- Separate business/operator metadata from user-controlled encrypted payloads whenever possible.
- Ensure staff can explain architectural boundaries:
  - what operators can see
  - what remains cryptographically user-controlled

These controls help demonstrate the operator was not complicit in unlawful transactions while preserving principled privacy boundaries.

## Operational Baseline Before Production

At minimum, operators should establish:

1. Jurisdiction-specific legal review of payment and record flows.
2. Written acceptable use policy and enforcement process.
3. Lawful request handling and evidence retention procedure.
4. Key/security operating procedures (rotation, revocation, incident response).
5. Security, resiliency, and compliance test plans with documented sign-off.

## Final Statement

Safebox can support strong privacy and user sovereignty, but lawful operation depends on responsible behavior by both users and operators. The platform design does not replace legal compliance; it requires disciplined governance, transparent operational controls, and demonstrable good-faith stewardship.
