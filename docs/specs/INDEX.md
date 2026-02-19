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
- [ACCEPTANCE-MODEL.md](./ACCEPTANCE-MODEL.md) - Trust and acceptance rules for inbound records and events.
- [NAUTH-PROTOCOL.md](./NAUTH-PROTOCOL.md) - Authorization envelope used to coordinate cross-party record flows.
- [NEMBED-PROTOCOL.md](./NEMBED-PROTOCOL.md) - Compact bech32 extension format for embedded secure payloads.
- [NWC-NFC-VAULT-EXTENSION.md](./NWC-NFC-VAULT-EXTENSION.md) - NWC extensions used for NFC wallet, payment, and record operations.
- [NFC-FLOWS-AND-SECURITY.md](./NFC-FLOWS-AND-SECURITY.md) - Card issuance, rotation, NFC payment/record flows, and security controls.
- [OFFERS-AND-GRANTS-FLOWS.md](./OFFERS-AND-GRANTS-FLOWS.md) - End-to-end offer/grant lifecycle over QR and NFC, including legacy rendering fallback.
- [PAYMENTS-SAFEBOX-CASHU-LIGHTNING-FALLBACK.md](./PAYMENTS-SAFEBOX-CASHU-LIGHTNING-FALLBACK.md) - Payment routing between Safebox wallets and Lightning interoperability behavior.
- [CASHU-STORAGE-AND-MULTI-MINT.md](./CASHU-STORAGE-AND-MULTI-MINT.md) - Proof storage/retrieval model and multi-mint normalization behavior.
- [WALLET-RECORD-STORAGE-PLAINTEXT-AND-SAFEBOXRECORD.md](./WALLET-RECORD-STORAGE-PLAINTEXT-AND-SAFEBOXRECORD.md) - Record persistence formats for plaintext and structured signed records.
- [BLOSSOM-BLOB-STORAGE-AND-TRANSFER.md](./BLOSSOM-BLOB-STORAGE-AND-TRANSFER.md) - Blob encryption, transfer semantics, and original-record exchange behavior.
- [QUANTUM-SAFE-CRYPTOGRAPHY.md](./QUANTUM-SAFE-CRYPTOGRAPHY.md) - ML-KEM integration and quantum-safe payload encryption model.
