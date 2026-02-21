# Specs Index

Safebox is a sovereign wallet-and-records platform built on Nostr, Cashu, and related open protocols. It is designed to let users hold funds and sensitive records under their own cryptographic control while still supporting practical, user-friendly workflows such as Lightning-address payments, NFC card interactions, and secure record sharing.

The core problem Safebox is addressing is the gap between convenience and sovereignty: most mainstream systems are easy to use but depend on centralized custodians and weak user control, while many self-sovereign tools are hard to operate at scale. Safebox uses a hybrid approach to reduce this tradeoff by combining familiar interfaces with end-user key ownership and application-layer payload security.

This index lists the specification documents in this folder.

Section convention used across current Safebox specs:

- `Overview`
- `Scope`
- `Security Considerations`
- `Implementation References`

- [TRANSPORT-SECURITY-AND-HYBRID-ADDRESSING.md](./TRANSPORT-SECURITY-AND-HYBRID-ADDRESSING.md) - Transport model, TLS assumptions, and hybrid npub/address routing.
- [FIDUCIARY-CONSIDERATIONS-FOR-SERVICE-OPERATORS.md](./FIDUCIARY-CONSIDERATIONS-FOR-SERVICE-OPERATORS.md) - Operator fiduciary/compliance considerations for payments, records stewardship, private-key responsibility, and lawful process handling.
- [BRANDING-AND-HOST-RESOLUTION.md](./BRANDING-AND-HOST-RESOLUTION.md) - Host-based branding lookup, fallback/bootstrap behavior, and deployment guidance.
- [AGENT-API.md](./AGENT-API.md) - Header-authenticated machine API for automation clients (OpenClaw-style agents) using wallet access keys instead of browser cookies.
- [DATABASE-BACKENDS-AND-MIGRATIONS.md](./DATABASE-BACKENDS-AND-MIGRATIONS.md) - SQLite/PostgreSQL backend support, centralized engine behavior, and Alembic migration workflow.
- [ACCEPTANCE-MODEL.md](./ACCEPTANCE-MODEL.md) - Trust and acceptance rules for inbound records and events.
- [THREAT-MODEL.md](./THREAT-MODEL.md) - Safebox threat boundaries, key risks, mitigations, and residual risk considerations.
- [NAUTH-PROTOCOL.md](./NAUTH-PROTOCOL.md) - Authorization envelope used to coordinate cross-party record flows.
- [RECORD-PRESENTATION-NAUTH-STRATEGY.md](./RECORD-PRESENTATION-NAUTH-STRATEGY.md) - Generalized record presentation over QR/NFC with separate secure transfer channels.
- [NEMBED-PROTOCOL.md](./NEMBED-PROTOCOL.md) - Compact bech32 extension format for embedded secure payloads.
- [NWC-NFC-VAULT-EXTENSION.md](./NWC-NFC-VAULT-EXTENSION.md) - NWC extensions used for NFC wallet, payment, and record operations.
- [NFC-FLOWS-AND-SECURITY.md](./NFC-FLOWS-AND-SECURITY.md) - Card issuance, rotation, NFC payment/record flows, and security controls.
- [OFFERS-AND-GRANTS-FLOWS.md](./OFFERS-AND-GRANTS-FLOWS.md) - End-to-end offer/grant lifecycle over QR and NFC, including legacy rendering fallback.
- [PAYMENTS-SAFEBOX-CASHU-LIGHTNING-FALLBACK.md](./PAYMENTS-SAFEBOX-CASHU-LIGHTNING-FALLBACK.md) - Payment routing between Safebox wallets and Lightning interoperability behavior.
- [CARD-TOKENIZATION-AND-NFC-PAYMENT-STRATEGY.md](./CARD-TOKENIZATION-AND-NFC-PAYMENT-STRATEGY.md) - Design strategy for NFC card virtualization and tokenized payment authorization model.
- [CASHU-STORAGE-AND-MULTI-MINT.md](./CASHU-STORAGE-AND-MULTI-MINT.md) - Proof storage/retrieval model and multi-mint normalization behavior.
- [WALLET-RECORD-STORAGE-PLAINTEXT-AND-SAFEBOXRECORD.md](./WALLET-RECORD-STORAGE-PLAINTEXT-AND-SAFEBOXRECORD.md) - Record persistence formats for plaintext and structured signed records.
- [BLOSSOM-BLOB-STORAGE-AND-TRANSFER.md](./BLOSSOM-BLOB-STORAGE-AND-TRANSFER.md) - Blob encryption, transfer semantics, and original-record exchange behavior.
- [QUANTUM-SAFE-CRYPTOGRAPHY.md](./QUANTUM-SAFE-CRYPTOGRAPHY.md) - ML-KEM integration and quantum-safe payload encryption model.

## Operations

- [INCIDENT-RESPONSE-AND-KEY-COMPROMISE-RUNBOOK.md](./INCIDENT-RESPONSE-AND-KEY-COMPROMISE-RUNBOOK.md) - Incident classification, containment, recovery, and key-compromise response procedures.
- [BACKUP-AND-RECOVERY-PLAN.md](./BACKUP-AND-RECOVERY-PLAN.md) - Backup tiers, restore validation, and disaster recovery operating model.
- [DATA-RETENTION-AND-DELETION-POLICY.md](./DATA-RETENTION-AND-DELETION-POLICY.md) - Data minimization, retention classes, deletion lifecycle, and legal-hold alignment.
- [MONITORING-AND-ALERTING-PLAN.md](./MONITORING-AND-ALERTING-PLAN.md) - Telemetry signals, alert severities, escalation routing, and runbook linkage.
- [OPERATIONAL-SLO-SLA.md](./OPERATIONAL-SLO-SLA.md) - Reliability objectives, service commitments, error budgets, and response targets.
- [CHANGE-MANAGEMENT-AND-RELEASE-PROCESS.md](./CHANGE-MANAGEMENT-AND-RELEASE-PROCESS.md) - Change lifecycle, release gates, risk tiers, and rollback expectations.
- [INTEROPERABILITY-AND-COMPATIBILITY-MATRIX.md](./INTEROPERABILITY-AND-COMPATIBILITY-MATRIX.md) - Browser/device/proxy/protocol compatibility matrix and fallback expectations.

## Governance and Compliance

- [OPERATOR-COMPLIANCE-PLAYBOOK.md](./OPERATOR-COMPLIANCE-PLAYBOOK.md) - Practical compliance controls for operators covering governance, policy, evidence, and legal readiness.
- [COMMUNITY-GOVERNANCE-TEMPLATE-PACK.md](./COMMUNITY-GOVERNANCE-TEMPLATE-PACK.md) - Reusable governance templates for community chartering, trust, stewardship, and dispute handling.

## Release Notes

- [PRODUCTION-CHANGE-SUMMARY-LATEST-MAIN-MERGE.md](./PRODUCTION-CHANGE-SUMMARY-LATEST-MAIN-MERGE.md) - Production-focused summary of major enhancements, reliability fixes, and architectural changes from the latest major merge wave.

## Test Plans

- [SCALABILITY-TEST-PLAN.md](./SCALABILITY-TEST-PLAN.md) - Load, stress, soak, and failure-injection strategy for Safebox HTTP, websocket, NFC, and POS flows.
- [RESILIENCY-TEST-PLAN.md](./RESILIENCY-TEST-PLAN.md) - Data-protection and failover validation plan for relay/Blossom outages, DoS scenarios, and recovery integrity checks.
- [SECURITY-TEST-PLAN.md](./SECURITY-TEST-PLAN.md) - Pre-production security validation plan covering auth/session controls, NFC/POS/payment integrity, rollback/recovery behavior, and go-live security gates.
- [COMMUNITY-ACCEPTANCE-TEST-PLAN.md](./COMMUNITY-ACCEPTANCE-TEST-PLAN.md) - CLRK-oriented acceptance framework for community governance fit, stewardship workflows, trust validation, and production readiness.
- [NEW-WALLET-CHECKLIST.md](./NEW-WALLET-CHECKLIST.md) - Operational checklist for creating and validating a new wallet in a fresh or migrated environment.
