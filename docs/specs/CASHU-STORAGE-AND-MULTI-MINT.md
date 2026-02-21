# Safebox Cashu Storage and Multi-Mint Model

## Overview

Safebox uses Cashu as its core funds layer. Wallet value is represented as Cashu proofs, and Safebox handles mint interactions (mint, melt, swap, redeem) behind the scenes so users can think in terms of a single balance.

In practice, Safebox behaves like:

- a unified sat balance for the user
- an internal proof engine for Cashu operations
- automatic mint/keyset handling across one or more Cashu mints

## Scope

This specification describes:

- how Safebox stores, loads, and updates Cashu proofs
- how multi-mint proof origin is abstracted from end users

This specification does not define Cashu protocol internals or mint-side policy.

## How Funds Are Stored

### Proof-based wallet state

Safebox stores funds as Cashu proofs in memory (`self.proofs`) and derives balance by summing proof amounts.

- Balance computation: `get_balance()`
- Proof partitioning by keyset: `_proofs_by_keyset()`

### Persistent encrypted proof records

Proofs are persisted as encrypted Nostr events:

- event kind: `7375`
- format: NIP-60 style proof bundle (`NIP60Proofs`)
- encryption: NIP-44/Extended NIP-44 to the wallet’s own pubkey

Write/load paths in `safebox/acorn.py`:

- write: `add_proofs_obj(...)`, `write_proofs(...)`
- read: `_load_proofs(...)`, `_async_load_proofs(...)`

This design allows Safebox to reconstruct wallet state from relay events while keeping proof payloads encrypted.

## How Funds Enter and Leave the Wallet

### Inbound (deposit / mint)

1. Safebox requests a mint quote (`deposit(...)` / `async_deposit(...)`)
2. User pays the Lightning invoice
3. Safebox polls quote status (`poll_for_payment(...)`)
4. On settlement, Safebox mints blinded outputs (`_mint_proofs(...)`)
5. New proofs are encrypted and stored as proof events

### Outbound (withdraw token / pay)

For ecash issuance:

- `issue_token(...)` selects proofs, performs swap for exact spendability, and serializes Cashu token output.

For Lightning payment:

- `pay_multi(...)` performs melt flow (quote + melt) against the selected mint path and updates stored proofs.

For incoming ecash:

- `accept_token(...)` parses token, validates/swaps proofs into local wallet state, persists proofs, and updates history.

## Multi-Mint Support: User-Facing Simplicity

Safebox supports multiple Cashu mints without exposing proof origin complexity to end users.

### Internal mint routing model

Safebox tracks a mapping of:

- `keyset_id -> mint_url` in `self.known_mints`

When proofs are loaded or accepted, Safebox updates `known_mints` using proof/keyset metadata.  
When spending, melting, or swapping, Safebox uses this mapping to call the correct mint endpoints for each proof set.

### Why keyset-centric handling matters

Cashu proofs are bound to mint keysets. Safebox therefore:

- groups proofs by keyset (`_proofs_by_keyset()`)
- selects an adequate keyset for requested amount
- swaps proofs as needed to produce spendable denomination sets
- consolidates/rebalances proof sets (`swap_multi_consolidate(...)`)

All of this happens internally; users see only successful payments, receipts, and total balance.

## What the User Sees

Users are not required to manage:

- which mint issued each proof
- keyset IDs
- proof denomination fragmentation
- swap/rebalance cycles

Instead, users interact with:

- a single displayed sat balance
- normal send/receive flows
- transaction history entries

## Security Considerations

- Proof persistence is encrypted but relay availability still matters for recovery.
- Multi-mint wallets may need swap/consolidation to optimize spendability.
- Safebox attempts to choose suitable keysets automatically and raises errors when a payment cannot be assembled with current proof distribution.

## Operational Notes

Safebox may trigger proof consolidation when proof count or keyset fragmentation increases, to keep spending paths reliable.

## Implementation References

- `safebox/acorn.py`
  - storage/load: `add_proofs_obj`, `write_proofs`, `_load_proofs`
  - balance/keyset: `get_balance`, `_proofs_by_keyset`
  - mint/deposit: `deposit`, `poll_for_payment`, `_mint_proofs`
  - outbound spend: `issue_token`, `pay_multi`
  - inbound redeem: `accept_token`
  - consolidation/swap: `swap_for_payment_multi`, `swap_multi_consolidate`
