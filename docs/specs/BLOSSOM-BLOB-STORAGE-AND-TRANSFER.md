# Blossom Blob Storage and Transfer in Safebox

## Overview

Safebox uses Blossom as external blob storage for large/binary record content (for example PDFs and images).  
Wallet records store metadata and encrypted blob references; raw blob bytes live on Blossom servers.

Core implementation is in:

- `/Users/trbouma/projects/safebox-2/safebox/acorn.py`
- `/Users/trbouma/projects/safebox-2/safebox/func_utils.py`
- `/Users/trbouma/projects/safebox-2/app/routers/records.py`

## Scope

This specification describes:

- how Safebox encrypts blobs before Blossom upload
- how blobs are retrieved and decrypted
- how original-record transfer blobs are issued and ingested

This specification does not define Blossom server-side internals.

## Data Model

Structured records are stored as `SafeboxRecord` with blob metadata fields:

- `blobref`
- `blobtype`
- `blobsha256`
- `origsha256`
- `encryptparms` (`alg`, `key`, `iv`, optional `aad`)

Transfer metadata for cross-party original-record handoff is `OriginalRecordTransfer`:

- original hash/mimetype
- encryption params
- transfer blossom server/ref/hash/type
- one-time transfer `blobnsec`

## Blob Encryption and Decryption

### Encryption

Safebox encrypts blob bytes before upload using AES-256-GCM:

- function: `encrypt_bytes(...)` in `safebox/func_utils.py`
- key: 32 bytes
- IV/nonce: 12 bytes random
- output: ciphertext (with auth tag), IV, optional AAD, algorithm label

When storing or re-storing blobs, Safebox:

1. computes original hash (`origsha256`) from plaintext
2. encrypts plaintext blob with AES-256-GCM
3. uploads ciphertext to Blossom
4. stores encryption parameters in record metadata

### Decryption

Safebox decrypts with `decrypt_bytes(...)`:

- requires matching `key` + `iv` (+ `aad` if used)
- AES-GCM authentication protects integrity; wrong parameters fail decryption

After decryption, Safebox typically:

- infers mime type from plaintext bytes
- verifies hash (in transfer flows) against expected `origsha256`

## Standard Blob Storage Flow (Local Record)

When user saves a record with `blob_data` (`put_record(...)`):

1. Safebox guesses mime type and hashes plaintext.
2. Generates random 32-byte key.
3. Encrypts bytes (`encrypt_bytes`).
4. Uploads ciphertext to Blossom (`BlossomClient.upload_blob`).
5. Stores `SafeboxRecord` with blob pointer + encryption parameters in wallet record storage.

Retrieval (`get_record_blobdata(...)`):

1. Load/decrypt `SafeboxRecord`.
2. Fetch ciphertext by `blobsha256` from Blossom.
3. Decrypt using stored `encryptparms`.
4. Return plaintext bytes + inferred mime type.

API exposure:

- `GET /records/blob`
- `POST /records/blob`

Both return raw bytes with content type and `Cache-Control: no-store`.

## Original Record Transfer for Issuance and Verification

Safebox uses a dedicated transfer blob flow when issuing grants/presentations that include original documents.

## A) Create transfer package (issuer side)

In `create_grant_from_offer(...)` and `create_request_from_grant(...)`:

1. Load source blob and decrypt it to plaintext.
2. Choose transfer encryption key:
   - PQC shared secret when available (`shared_secret_hex`), or
   - random 32-byte key fallback.
3. Encrypt plaintext blob for transfer.
4. Upload encrypted blob to transfer Blossom server (`BLOSSOM_XFER_SERVER`, default `https://nostr.download`).
5. Create `OriginalRecordTransfer` with:
   - origin hash/mimetype
   - transfer blob location/hash
   - transfer encryption params
   - ephemeral `blobnsec` used for transfer object access.

This transfer metadata is then protected in-record transmittal (for PQC paths, inside `pqc_encrypted_original`).

## B) Receive and ingest transfer package (holder/verifier side)

In record accept/presentation flows (`app/routers/records.py`), Safebox decrypts and passes transfer metadata into:

- `transfer_blob(...)`

`transfer_blob(...)` does:

1. Parse `OriginalRecordTransfer`.
2. Fetch encrypted blob from transfer server using transfer `blobnsec`.
3. Delete transfer blob from source server after fetch.
4. Decrypt blob using transfer `encryptparms`.
5. Verify decrypted hash equals `origsha256`.
6. Re-encrypt blob with a new local random key.
7. Upload to local/home Blossom server.
8. Update local `SafeboxRecord` blob metadata to point to new blob location.

This makes transfer blobs short-lived while anchoring the accepted document in the recipient’s own storage context.

## C) Direct retrieval path for transfer object

`POST /records/originalblob` accepts `OriginalRecordTransfer` and returns decrypted blob bytes via:

- `get_original_blob(...)`

`get_original_blob(...)` can also delete transfer blob after successful fetch/decrypt.

## Server Configuration Notes

Configured defaults:

- `BLOSSOM_SERVERS`: `https://blossom.getsafebox.app`
- `BLOSSOM_HOME_SERVER`: `https://blossom.getsafebox.app`
- `BLOSSOM_XFER_SERVER`: `https://nostr.download`

Note: parts of `safebox/acorn.py` still use explicit Blossom URLs in-code. Functional behavior follows those values unless refactored to fully use config constants.

## Security Considerations

- Blob confidentiality at rest/on transport server comes from AES-256-GCM encryption.
- Integrity/authenticity of blob ciphertext is enforced by AES-GCM tag verification.
- Transfer flow verifies plaintext hash (`origsha256`) before accepting.
- Transfer blobs are designed for temporary exchange and are deleted after pull in transfer paths.
