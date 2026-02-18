# Wallet Record Storage: Plaintext and Structured SafeboxRecord

## Overview

Safebox stores wallet records as encrypted Nostr events keyed by a deterministic label hash (`d` tag).  
At the content layer, records are stored in two patterns:

- plaintext/string payloads
- structured JSON payloads using `SafeboxRecord`

Both are written via `set_wallet_info(...)` and read/decrypted via `get_wallet_info(...)`.

## Scope

This specification describes record storage patterns in Safebox wallet records:

- plaintext/raw string records
- structured `SafeboxRecord` JSON records
- grant payload handling as embedded signed events

This specification does not define record UI rendering behavior.

## Common Storage Envelope

All wallet records follow the same envelope mechanics:

- label hash: `sha256(privkey_hex + label)` used as `["d", <hash>]`
- encryption: NIP-44 to wallet pubkey
- event kind:
  - `37375` for general wallet/user records
  - other kinds used for specialized streams (for example proof/ecash metadata elsewhere)

Relevant implementation:

- `/Users/trbouma/projects/safebox-2/safebox/acorn.py` (`set_wallet_info`, `get_wallet_info`)

## Mode 1: Plaintext/String Records

Plaintext mode means the decrypted content is treated as a raw string (or non-JSON text).

This is used for reserved/simple wallet labels and operational flags (examples include lock and simple settings patterns).  
For reserved labels in `put_record(...)`, Safebox writes `record_value` directly without wrapping it in a `SafeboxRecord`.

Read behavior:

- `get_wallet_info(...)` returns decrypted string content
- `get_record(...)` attempts `json.loads(...)`; on JSON decode failure it returns the raw string

This preserves compatibility with lightweight records and legacy/plain values.

## Mode 2: Structured SafeboxRecord

For user content records, Safebox wraps data in `SafeboxRecord` and stores its JSON serialization.

Model (`safebox/models.py`):

- `tag`
- `type`
- `payload`
- optional blob metadata: `blobref`, `blobtype`, `blobsha256`, `origsha256`, `encryptparms`

Write path:

- `put_record(...)` builds `SafeboxRecord(...)`
- serializes with `model_dump_json()`
- stores with `set_wallet_info(...)`

Read path:

- `get_record_safebox(...)` decrypts content and strictly parses as `SafeboxRecord`
- raises if the content cannot be parsed as structured JSON

## Grants as Signed Events in SafeboxRecord Payload

Grant workflows store signed Nostr events inside `SafeboxRecord.payload`.

Creation path:

1. `issue_private_record(...)` creates and signs an event (grant event kind, tags, signature)
2. this signed event data is serialized
3. serialized signed-event JSON is stored in the `payload` field of a `SafeboxRecord`

Retrieval path for presentation/request:

1. `create_request_from_grant(...)` loads the structured record via `get_record_safebox(...)`
2. reads `safebox_record.payload`
3. parses payload JSON as signed event data
4. reconstructs `Event(...)` from that payload for downstream transmittal/use

This means the grant record in wallet storage is a structured Safebox wrapper whose payload is itself a signed event representation.

## Why This Dual Model Exists

- Plaintext mode keeps simple wallet state and legacy records lightweight.
- Structured `SafeboxRecord` mode supports richer content, typed metadata, and blob linkage.
- Grant flows specifically need signed-event preservation, which is naturally carried inside structured payloads.

## Security Considerations

- wallet record payloads are encrypted before relay storage
- strict `SafeboxRecord` parsing is used where structured semantics are required
- signed-event payload preservation supports downstream signature validation workflows

## Implementation References

- `/Users/trbouma/projects/safebox-2/safebox/acorn.py`
  - `set_wallet_info`, `get_wallet_info`
  - `get_record`, `get_record_safebox`
  - `put_record`
  - `issue_private_record`
  - `create_grant_from_offer`
  - `create_request_from_grant`
- `/Users/trbouma/projects/safebox-2/safebox/models.py`
  - `SafeboxRecord`
