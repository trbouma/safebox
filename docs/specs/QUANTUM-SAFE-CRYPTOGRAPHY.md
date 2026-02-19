# Quantum-Safe Cryptography in Safebox (ML-KEM)

## Overview

This page describes how Safebox incorporates post-quantum cryptography and how ML-KEM is used to protect sensitive payloads during record exchange.

## What Is Used

Safebox uses `liboqs` (via `python-oqs`) for post-quantum primitives.

- KEM: `ML-KEM-512` by default (`PQC_KEMALG`)
- Signature support is also present (`PQC_SIGALG`), but this page focuses on ML-KEM payload confidentiality

Configuration lives in `app/config.py`. Key settings include:

- `PQC_KEMALG`
- `PQC_KEM_PUBLIC_KEY`
- `PQC_KEM_SECRET_KEY`

`ConfigWithFallback` auto-generates and persists the KEM keypair if missing.

## Scope

This specification covers ML-KEM usage for record payload confidentiality in Safebox.

This specification does not cover:

- all classical cryptography in Safebox
- full signature lifecycle design (beyond references to configured PQC signature support)

## Why ML-KEM Is Used

Safebox uses ML-KEM to derive a per-exchange shared secret between sender and intended recipient. That shared secret is then used to encrypt sensitive record data before transmittal.

This provides quantum-resistant confidentiality for protected fields, even if transport-level or long-term classical assumptions weaken in the future.

## Sensitive Payload Fields Protected

In record exchange payloads, Safebox protects:

- `pqc_encrypted_payload`: encrypted record content
- `pqc_encrypted_original`: encrypted original/blob metadata (optional)

And includes KEM exchange metadata:

- `ciphertext`: ML-KEM encapsulation ciphertext
- `kemalg`: algorithm identifier (for example, `ML-KEM-512`)

## End-to-End ML-KEM Flow

### 1. Requester shares KEM material

The requester includes:

- `kem_public_key`
- `kemalg`

This is exchanged in record request/auth coordination payloads (for example via `nauth`/`nembed` paths).

### 2. Sender encapsulates and encrypts

In record send paths (for example `app/routers/records.py`):

1. Sender reads requester `kem_public_key` and `kemalg`
2. Sender creates a KEM context with configured local key material:
   - `oqs.KeyEncapsulation(record_parms.kemalg, bytes.fromhex(config.PQC_KEM_SECRET_KEY))`
3. Sender runs encapsulation against requester public key:
   - `kem_ciphertext, kem_shared_secret = pqc.encap_secret(requester_pubkey)`
4. Sender derives an application encryption key from `kem_shared_secret`
5. Sender encrypts sensitive fields:
   - `pqc_encrypted_payload`
   - optional `pqc_encrypted_original`
6. Sender emits payload including `ciphertext`, `kemalg`, and encrypted fields

### 3. Receiver decapsulates and decrypts

In receive/decode paths (`app/routers/records.py`, `app/nwc.py`):

1. Receiver reads `ciphertext` and `kemalg`
2. Receiver decapsulates using local KEM secret key:
   - `pqc = oqs.KeyEncapsulation(record_kemalg, bytes.fromhex(config.PQC_KEM_SECRET_KEY))`
   - `shared_secret = pqc.decap_secret(bytes.fromhex(record_ciphertext))`
3. Receiver derives the same app key from `shared_secret`
4. Receiver decrypts:
   - `pqc_encrypted_payload` -> usable sensitive content
   - `pqc_encrypted_original` -> optional original transfer metadata

Only the holder of the matching ML-KEM private key can decapsulate and recover the shared secret.

## Where This Appears in Safebox

- Key material generation/fallback: `app/config.py`
- KEM publish in service/status responses: `app/main.py`
- Record send/receive encapsulation and decapsulation: `app/routers/records.py`
- NWC record receive/decrypt path: `app/nwc.py`

## Security Considerations

- Protect `PQC_KEM_SECRET_KEY` at rest and in deployment secrets.
- Keep `kemalg` consistent across participants (algorithm agility is explicit in payload).
- Validate payload structure before decapsulation/decryption attempts.
- Log failures with context, but never log plaintext sensitive payloads or secrets.
- ML-KEM here protects selected sensitive fields; it does not replace all other cryptographic controls in Safebox.
