# WoT, Attestation, and Record Verification

## Overview

This specification describes how Safebox currently implements Web-of-Trust expansion, owner attestation lookup, and record verification for inbound and stored record views.

It is an implementation-facing companion to:

- `docs/specs/ACCEPTANCE-MODEL.md`

This document describes what the code does now. It is not a general Nostr trust theory document.

## Scope

This specification covers:

- root authority storage and expansion
- trusted assertion provider storage and lookup
- owner attestation lookup for record verification
- record verification fact resolution
- how trust results are rendered in:
  - request-record verification
  - my-records display
  - individual record display

This specification does not define:

- the normative meaning of trust scores
- governance rules for choosing root authorities
- attestation issuance policy
- NIP-level protocol standardization beyond the currently implemented behavior

## Core Model

Safebox record verification currently combines four distinct checks:

1. **Validated**
   - the record payload can be parsed as a Nostr event
   - the event signature validates

2. **Attested By Owner**
   - the record owner has published a qualifying ownership attestation for the current Safebox

3. **Recognized**
   - the record owner is reachable from a configured root authority set

4. **Issuer WoT Scores**
   - configured trusted assertion providers are queried for advisory score tags about the owner

These checks are assembled into a verification summary, but they are not all equivalent:

- attestation is a direct ownership/control signal
- recognition is a standing/realm-membership signal
- WoT scores are advisory

## Data Sources

### Root Authorities

Root authorities are stored as an internal wallet record:

- label: `trusted entities`
- kind: `37376`

The payload is a whitespace-delimited set of `npub` values.

The current storage/read path is implemented in:

- `safebox/acorn.py`
  - `set_trusted_entities(...)`
  - `get_root_entities(...)`
  - `get_trusted_entities(...)`
  - `get_trusted_entity_sources(...)`

### Trusted Assertion Providers

Trusted assertion providers are stored as an internal wallet record:

- label: `wot entities`
- kind: `37376`

The payload is a whitespace-delimited set of entries in this format:

- `npub:tag[:relay]`

Where:

- `npub`
  - the assertion provider identity
- `tag`
  - the score tag to read from the provider’s event
- `relay` optional
  - the relay host or URL used to query that provider

If the relay is present but does not begin with `wss://`, Safebox prefixes `wss://` during lookup.

The current storage/read path is implemented in:

- `safebox/acorn.py`
  - `set_wot_entities(...)`
  - `get_wot_entities(...)`
  - `get_wot_scores(...)`

### Owner Attestations

Owner attestation lookup is implemented in:

- `safebox/func_utils.py`
  - `get_attestation(...)`

The current attestation query uses:

- event kind: `31871`
- author: the record owner
- `#d` tag:
  - `<current safebox npub>:safebox-under-control`

The attestation is treated as valid only if:

- the event signature is valid
- the event contains a `p` tag matching the current Safebox public key in hex form

This is the current implementation of the `Attested By Owner` signal.

## Root Expansion Model

### Stored Roots

Configured roots are stored as `npub` values and normalized back to `npub` on write.

At read time, Safebox:

1. loads the internal `trusted entities` record
2. tokenizes payload on whitespace
3. converts valid entries to hex pubkeys
4. discards invalid or blank entries

### Expanded Trusted Set

Safebox then expands the root set using contact-list events:

- event kind: `3`
- authors: configured root authority pubkeys

For each returned contact-list event, Safebox reads `p` tags and appends the tagged pubkeys to the trusted set.

The final trusted set therefore contains:

- the root authorities themselves
- any pubkeys followed by those root authorities in kind-3 contact lists

This expansion is implemented in:

- `safebox/acorn.py`
  - `get_trusted_entities(...)`

### Root Recognition Provenance

Safebox also builds a source-aware recognition map:

- root authority pubhex -> list of recognized pubhex values

This is implemented in:

- `safebox/acorn.py`
  - `get_trusted_entity_sources(...)`

This map is used to render:

- `Recognized By`

in record verification output.

## Trusted Assertion Provider Model

### Stored Provider Entries

Each trusted assertion provider entry is stored in canonicalized form:

- `canonical_npub:tag[:relay]`

Blank or malformed entries are skipped during load.

### Score Query Behavior

For a record owner being scored, Safebox:

1. normalizes the owner key into pubhex
2. loads the configured trusted assertion provider entries
3. for each provider entry:
   - normalizes the provider npub
   - normalizes the relay
   - queries the provider relay for:
     - kind `30382`
     - author = provider pubhex
     - `#d` = owner pubhex
4. scans returned tags for the configured `tag`

If a matching tag is found:

- the returned score is recorded as:
  - `[tag, value]`

If no matching tag is found for that provider:

- Safebox records:
  - `[tag, "na"]`

This behavior is implemented in:

- `safebox/acorn.py`
  - `get_wot_scores(...)`

### Interpretation

Trusted assertion scores are currently advisory only.

They:

- are shown in record verification output
- do not by themselves make an issuer recognized
- do not replace signature validation
- do not replace attestation checks

## Record Verification Resolution

The shared verification logic is implemented in:

- `app/records_verification.py`
  - `parse_event_payload(...)`
  - `build_record_trust_context(...)`
  - `resolve_record_verification_facts(...)`

### Event Parsing

Safebox first attempts to parse the payload into a Nostr event.

If the payload:

- is not JSON
- is missing core event fields
- or cannot be loaded as an event

then it is treated as plain text and full Nostr verification is skipped.

### Owner Normalization

For event payloads that parse successfully, Safebox extracts:

- `safebox_owner`
- `safebox_issuer`
- `safebox_holder`

The owner key is normalized into:

- owner pubhex
- owner `npub`
- display form

This normalized owner identity is the basis for:

- profile lookup
- attestation lookup
- recognition lookup
- WoT score lookup

### Request-Scoped Trust Context

Safebox builds a request-scoped trust context so repeated records in the same request do not repeat the same expensive lookups.

The trust context currently caches:

- profile lookup results
- attestation results
- WoT score results
- root authority profiles
- expanded trusted entities
- root recognition sources

This is implemented in:

- `app/records_verification.py`
  - `build_record_trust_context(...)`

### Verification Facts

`resolve_record_verification_facts(...)` returns structured facts including:

- issuer display info
- profile picture
- signature validity
- content
- `is_attested`
- `is_trusted`
- `is_presenter`
- `is_held_by_current_safebox`
- `recognized_by`
- `wot_scores`

## Rendering Semantics

### Live Request / Presentation Verification

In request-record flows, verification shows:

- `Valid`
- `Self-Presented`
- `Attested By Owner`
- `Recognized`
- `Recognized By`
- `Issuer WoT Scores`

`Self-Presented` is true only when:

- the active presenter identity equals the event’s `safebox_holder` tag

This view is used in:

- `app/routers/records.py`
  - websocket request-record verification flow

### Stored Record Views

In stored-record views, verification shows:

- `Valid`
- `Held By Current Safebox`
- `Attested By Owner`
- `Recognized`
- `Recognized By`
- `Issuer WoT Scores`

Stored-record views do not show `Self-Presented`, because there is no live presenter context in those routes.

Instead, Safebox checks whether:

- the event’s `safebox_holder` tag
- matches the current Safebox identity

This rendering is used in:

- my-records display
- individual record display

## Recognition Semantics

An owner is currently marked `Recognized` when:

- the normalized owner pubhex is present in the expanded trusted entity set

This means recognition is currently derived from:

- configured root authorities
- plus first-hop kind-3 follow edges from those root authorities

Recognition does not currently require:

- a score threshold
- an attestation event
- recursive transitive graph expansion beyond the current root -> followee step

## Current Limitations

### Root Expansion is Shallow

Recognition currently expands only through:

- configured roots
- one layer of kind-3 follow tags

It is not a general recursive graph traversal.

### WoT Provider Lookup Uses Stored Config Directly

`get_wot_scores(...)` currently calls:

- `get_wot_entities()`

internally rather than consuming provider data from the request trust context.

This is acceptable for current behavior but is not the cleanest long-term contract.

### Attestation Semantics are Specific

The current attestation check is narrowly defined around:

- owner-issued kind `31871` events
- `#d = <safebox npub>:safebox-under-control`
- matching `p` tag

This is sufficient for current ownership-style verification but does not yet cover richer attestation semantics such as:

- invalidation
- revocation
- competing attestors
- weighted attestor sets

### Trust Scores are Advisory

NIP-85-style trusted assertion scores are displayed but not currently used as hard policy gates in record acceptance.

## Security Considerations

- invalid or blank root and WoT entries are skipped rather than crashing verification
- trust is layered:
  - score visibility does not bypass signature checks
  - recognition does not imply attestation
  - attestation does not imply acceptance
- provider-specific WoT queries are relay-dependent
- recognition provenance depends on current root authority contact lists and may change as those lists change
- stored-record and live-presentation verification intentionally use different holder/presenter semantics

## Implementation References

- `safebox/acorn.py`
  - `get_trusted_entities(...)`
  - `get_trusted_entity_sources(...)`
  - `set_trusted_entities(...)`
  - `set_wot_entities(...)`
  - `get_wot_entities(...)`
  - `get_wot_scores(...)`
- `safebox/func_utils.py`
  - `get_attestation(...)`
- `app/records_verification.py`
  - `parse_event_payload(...)`
  - `build_record_trust_context(...)`
  - `resolve_record_verification_facts(...)`
- `app/routers/records.py`
  - my-records rendering
  - individual record rendering
  - websocket request-record verification rendering
- `app/routers/safebox.py`
  - trust-page storage and management routes
