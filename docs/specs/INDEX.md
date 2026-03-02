# Specs Index

Safebox is a sovereign wallet-and-records platform built on Nostr, Cashu, and related open protocols. It is designed to let users hold funds and sensitive records under their own cryptographic control while still supporting practical, user-friendly workflows such as Lightning-address payments, NFC card interactions, and secure record sharing.

The core problem Safebox is addressing is the gap between convenience and sovereignty: most mainstream systems are easy to use but depend on centralized custodians and weak user control, while many self-sovereign tools are hard to operate at scale. Safebox uses a hybrid approach to reduce this tradeoff by combining familiar interfaces with end-user key ownership and application-layer payload security.

Safebox is designed for both human-operated and agent-operated wallets. Current sequencing is deliberate: human interaction flows are hardened first, then agent flows are aligned to the same contracts and semantics so interactions between human-controlled and agent-controlled Safeboxes remain consistent and predictable.

Headline context document:

- [Human-First Approach](./HUMAN-FIRST-APPROACH.md)

This is the primary framing document for the spec set. It defines the human-first principle, the human-then-agent hardening sequence, and bootstrap-data minimization policy for QR/bech32 handshake channels. Read this first.
It also defines the explicit Human-Agent Flow Parity Principle: one interoperable protocol surface across human and agent operation.

Architectural companion:

- [Safebox Alternative Ecosystem Approach](./SAFEBOX-ALTERNATIVE-ECOSYSTEM-APPROACH.md)

This companion document explains broader ecosystem rationale, trust/compliance boundaries, and protocol posture in relation to other wallet ecosystems.

This index lists the specification documents in this folder.

Section convention used across current Safebox specs:

- `Overview`
- `Scope`
- `Security Considerations`
- `Implementation References`

## Market Specifications

- [Market Specifications Index](./mkt/INDEX.md) - Numbered market specifications (`MS-*`) for permissionless trading models and agent execution flows.

- [Transport Security and Hybrid Addressing](./TRANSPORT-SECURITY-AND-HYBRID-ADDRESSING.md) - Transport model, TLS assumptions, and hybrid npub/address routing.
- [Human-First Approach](./HUMAN-FIRST-APPROACH.md) - Headline policy document defining human-agency baseline, agent extension model, QR/bech32 bootstrap strategy, and handshake-data minimization constraints.
- [Web Wallet User Considerations](./WEB-WALLET-USER-CONSIDERATIONS.md) - User-experience principles and interaction decisions for the web wallet, intended as the baseline for future mobile UX once field-stable.
- [Mobile App Development Strategy](./MOBILE-APP-DEVELOPMENT-STRATEGY.md) - Flutter-first Android strategy with iOS-ready architecture, mobile UX principles, phased delivery plan, and NFC/payment/record flow parity goals.
- [Hypermedia and HATEOAS Application State](./HYPERMEDIA-AND-HATEOAS-APPLICATION-STATE.md) - Hypermedia-first application state strategy (HATEOAS), component mapping, and UI stability/jitter mitigation guidance.
- [Fiduciary Considerations for Service Operators](./FIDUCIARY-CONSIDERATIONS-FOR-SERVICE-OPERATORS.md) - Operator fiduciary/compliance considerations for payments, records stewardship, private-key responsibility, and lawful process handling.
- [Branding and Host Resolution](./BRANDING-AND-HOST-RESOLUTION.md) - Host-based branding lookup, fallback/bootstrap behavior, and deployment guidance.
- [Agent API](./AGENT-API.md) - Header-authenticated machine API for automation clients (OpenClaw-style agents) using wallet access keys instead of browser cookies.
- [Database Backends and Migrations](./DATABASE-BACKENDS-AND-MIGRATIONS.md) - SQLite/PostgreSQL backend support, centralized engine behavior, and Alembic migration workflow.
- [Acorn Resiliency and Guards](./ACORN-RESILIENCY-AND-GUARDS.md) - Runtime guard model for Acorn under unreliable/adversarial conditions, including lock safety, failure handling, and rollback strategy.
- [Hardening in Unpredictable and Adversarial Environments](./HARDENING-IN-UNPREDICTABLE-AND-ADVERSARIAL-ENVIRONMENTS.md) - Cross-cutting hardening model covering shared failure modes, fallback classes, fail-closed boundaries, and graceful rollback/recovery patterns across all flow families.
  - Includes `Field Discoveries and Applied Fixes (2026-02)` and `Remaining Fragility and Risk Concentration` sections documenting recent QR/NFC handshake issues, applied remediations, and the immediate hardening backlog.
- [Acorn Modularization Transition Plan](./ACORN-MODULARIZATION-TRANSITION-PLAN.md) - Design note for evolving Acorn from a god-class into compartmentalized services with phased migration and compatibility safeguards.
- [Acceptance Model](./ACCEPTANCE-MODEL.md) - Trust and acceptance rules for inbound records and events.
- [Threat Model](./THREAT-MODEL.md) - Safebox threat boundaries, key risks, mitigations, and residual risk considerations.
- [nAuth Protocol](./NAUTH-PROTOCOL.md) - Authorization envelope used to coordinate cross-party record flows.
- [nAuth Extensible Handshake](./NAUTH-EXTENSIBLE-HANDSHAKE.md) - Step/state handshake model for adding PQC and policy-driven sequence extensions without breaking flow compatibility.
- [Protocol Normalization: Relay-First KEM](./PROTOCOL-NORMALIZATION-RELAY-FIRST-KEM.md) - Patch spec for control-plane normalization, relay-first KEM acquisition, compact QR policy, and fail-closed compatibility migration.
- [Record Presentation nAuth Strategy](./RECORD-PRESENTATION-NAUTH-STRATEGY.md) - Generalized record presentation over QR/NFC with separate secure transfer channels.
- [nEmbed Protocol](./NEMBED-PROTOCOL.md) - Compact bech32 extension format for embedded secure payloads.
- [NWC NFC Vault Extension](./NWC-NFC-VAULT-EXTENSION.md) - NWC extensions used for NFC wallet, payment, and record operations.
- [Agent Flows](./AGENT-FLOWS.md) - Automation-oriented wallet flow model aligned with NFC and QR pathways.
- [Agent Offer Recipient-First Flow](./AGENT-OFFER-RECIPIENT-FIRST-FLOW.md) - Recipient-first agent offer flow where the recipient presents QR handshake data and the sender scans/transmits using existing record-send pathways.
- [Emergent Markets Over Safebox](./EMERGENT-MARKETS-OVER-SAFEBOX.md) - Market pattern specification for decentralized bid/ask intent publication, NIP-57 zap settlement, private fulfillment delivery, and public settlement confirmation across human and agent flows.
- [NFC Flows and Security](./NFC-FLOWS-AND-SECURITY.md) - Card issuance, rotation, NFC payment/record flows, and security controls.
- [Offers and Grants Flows](./OFFERS-AND-GRANTS-FLOWS.md) - End-to-end offer/grant lifecycle over QR and NFC, including legacy rendering fallback.
- [Payments: Safebox/Cashu/Lightning Fallback](./PAYMENTS-SAFEBOX-CASHU-LIGHTNING-FALLBACK.md) - Payment routing between Safebox wallets and Lightning interoperability behavior.
- [Card Tokenization and NFC Payment Strategy](./CARD-TOKENIZATION-AND-NFC-PAYMENT-STRATEGY.md) - Design strategy for NFC card virtualization and tokenized payment authorization model.
- [nEmbed Coexistence with Tokenized Card Rails](./NEMBED-COEXISTENCE-WITH-TOKENIZED-CARD-RAILS.md) - Comparative model and phased coexistence strategy for running `nembed` alongside incumbent tokenized card payment rails.
- [Cashu Storage and Multi-Mint](./CASHU-STORAGE-AND-MULTI-MINT.md) - Proof storage/retrieval model and multi-mint normalization behavior.
- [Wallet Record Storage: Plaintext and SafeboxRecord](./WALLET-RECORD-STORAGE-PLAINTEXT-AND-SAFEBOXRECORD.md) - Record persistence formats for plaintext and structured signed records.
- [Blossom Blob Storage and Transfer](./BLOSSOM-BLOB-STORAGE-AND-TRANSFER.md) - Blob encryption, transfer semantics, and original-record exchange behavior.
- [Quantum-Safe Cryptography](./QUANTUM-SAFE-CRYPTOGRAPHY.md) - ML-KEM integration and quantum-safe payload encryption model.
- [Historical Context: Law Merchant and Digital Exchange](./HISTORICAL-CONTEXT-LAW-MERCHANT-AND-DIGITAL-EXCHANGE.md) - Non-normative historical context linking law merchant instrument/register mechanics to Safebox's digital exchange model.
- [Portable Record Format (PRF)](./PORTABLE-RECORD-FORMAT-PRF.md) - Unified PRF specification (context + normative profile): artifact anchoring, NIP-01-aligned envelope, human-readable canonical form, compact encoding rules, and long-term archivability intent.

KEM fallback quick reference:

- `/records/transmit` KEM fallback contract, recipient-host hint resolution, and fail-closed rules: [Offers and Grants Flows](./OFFERS-AND-GRANTS-FLOWS.md)
- Cross-instance/NFC KEM guardrails (authoritative host selection, relay mismatch handling): [NFC Flows and Security](./NFC-FLOWS-AND-SECURITY.md)

## Operations

- [Incremental Change Hardening Strategy](../devops/incremental-change-hardening-strategy.md) - Incremental in-flight hardening strategy for isolating failures, applying narrow patches, validating in dev/test, and promoting safely.
- [Recipient Offer Incremental Execution Checklist](../devops/recipient-offer-incremental-execution-checklist.md) - One-page execution checklist for recipient-first offer development with mandatory regression gates, slice-by-slice rollout, and rollback criteria.
- [Configuration and Key Material Inventory](../devops/config-parameters-and-key-material-inventory.md) - Enumerated runtime config defaults, precedence rules, and key generation/storage lifecycle (`data/default.conf`, DB mappings, and rotation points).
- [Zero-Config Docker Bootstrap and Production Path](../devops/zero-config-docker-bootstrap-and-production-path.md) - Defines instant up-and-running Docker goals for testing and the recommended production transition to operator-controlled Postgres, relays, mints, blossom services, and secrets.
- [Incident Response and Key Compromise Runbook](./INCIDENT-RESPONSE-AND-KEY-COMPROMISE-RUNBOOK.md) - Incident classification, containment, recovery, and key-compromise response procedures.
- [Backup and Recovery Plan](./BACKUP-AND-RECOVERY-PLAN.md) - Backup tiers, restore validation, and disaster recovery operating model.
- [Data Retention and Deletion Policy](./DATA-RETENTION-AND-DELETION-POLICY.md) - Data minimization, retention classes, deletion lifecycle, and legal-hold alignment.
- [Monitoring and Alerting Plan](./MONITORING-AND-ALERTING-PLAN.md) - Telemetry signals, alert severities, escalation routing, and runbook linkage.
- [Operational SLO/SLA](./OPERATIONAL-SLO-SLA.md) - Reliability objectives, service commitments, error budgets, and response targets.
- [Change Management and Release Process](./CHANGE-MANAGEMENT-AND-RELEASE-PROCESS.md) - Change lifecycle, release gates, risk tiers, and rollback expectations.
- [Interoperability and Compatibility Matrix](./INTEROPERABILITY-AND-COMPATIBILITY-MATRIX.md) - Browser/device/proxy/protocol compatibility matrix and fallback expectations.

## Governance and Compliance

- [Operator Compliance Playbook](./OPERATOR-COMPLIANCE-PLAYBOOK.md) - Practical compliance controls for operators covering governance, policy, evidence, and legal readiness.
- [Community Governance Template Pack](./COMMUNITY-GOVERNANCE-TEMPLATE-PACK.md) - Reusable governance templates for community chartering, trust, stewardship, and dispute handling.

## Release Notes

- [Production Change Summary (Latest Main Merge)](./PRODUCTION-CHANGE-SUMMARY-LATEST-MAIN-MERGE.md) - Production-focused summary of major enhancements, reliability fixes, and architectural changes from the latest major merge wave.

## Test Plans

- [Scalability Test Plan](./SCALABILITY-TEST-PLAN.md) - Load, stress, soak, and failure-injection strategy for Safebox HTTP, websocket, NFC, and POS flows.
- [Resiliency Test Plan](./RESILIENCY-TEST-PLAN.md) - Data-protection and failover validation plan for relay/Blossom outages, DoS scenarios, and recovery integrity checks.
- [Security Test Plan](./SECURITY-TEST-PLAN.md) - Pre-production security validation plan covering auth/session controls, NFC/POS/payment integrity, rollback/recovery behavior, and go-live security gates.
- [Community Acceptance Test Plan](./COMMUNITY-ACCEPTANCE-TEST-PLAN.md) - CLRK-oriented acceptance framework for community governance fit, stewardship workflows, trust validation, and production readiness.
- [New Wallet Checklist](./NEW-WALLET-CHECKLIST.md) - Operational checklist for creating and validating a new wallet in a fresh or migrated environment.
