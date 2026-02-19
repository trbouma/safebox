# Payments Between Safebox Instances (Cashu + Lightning Fallback)

## Overview

Safebox presents a single Lightning-style payment UX to the user (`name@domain`), but internally it can optimize transport:

- If the recipient is a Safebox endpoint, payment is delivered as Cashu ecash over secure Nostr messaging.
- If the recipient is a regular Lightning address (non-Safebox), Safebox automatically falls back to standard Lightning invoice payment.

To an end user, both flows look like "send to Lightning address."

## Scope

This specification describes Safebox payment routing behavior for:

- Safebox-to-Safebox transfers over Cashu + secure transmittal
- fallback to standard Lightning for non-Safebox destinations

This specification does not define UI implementation details beyond high-level user flow.

## User Experience Model

From `/safebox/access`, the sender enters:

- recipient address (for example `alice@example.com`)
- amount and currency
- optional comment

The sender still clicks one payment action (`/safebox/payaddress`).  
Safebox decides the transport path automatically.

## How Safebox Detects the Path

Safebox resolves LNURL-pay metadata from:

- `https://<domain>/.well-known/lnurlp/<name>`

In `safebox/lightning.py` (`lightning_address_pay`), it reads:

- `safebox` flag
- `nonce`
- callback `pr` data

Decision in `safebox/acorn.py` (`Acorn.pay_multi`):

- `safebox == True` -> use Cashu + secure transmittal
- otherwise -> pay Lightning invoice via Cashu melt

## Flow A: Safebox-to-Safebox Payment (Cashu over Secure Messaging)

### 1. Sender prepares payment

Sender API path:

- `/safebox/payaddress` -> `task_pay_multi(...)` -> `Acorn.pay_multi(...)`

### 2. Recipient advertises Safebox capability

Recipient LNURL metadata includes `safebox: true` and `nonce`.

### 3. Sender mints ecash token

Sender creates a Cashu token:

- `cashu_token = await self.issue_token(amount=amount, comment=comment)`

### 4. Sender wraps token payload as `nembed`

Sender packages:

- `token`
- `amount`
- `comment`
- `tendered_amount`
- `tendered_currency`
- `nonce`

Then encodes with `create_nembed_compressed(...)`.

### 5. Sender transmits securely over Nostr relays

Sender calls:

- `secure_transmittal(..., kind=21401)`

This uses gift-wrapped encrypted messaging to the recipient npub via configured ecash relays.

### 6. Recipient listens and redeems token

On recipient side (`/lnpay/{name}` with `safebox=true`):

- no Lightning invoice is created (`pr = None`)
- background `handle_ecash(...)` polls `get_ecash_latest(...)`
- received `nembed` payload is decoded
- `accept_token(...)` redeems Cashu token into recipient wallet balance

Result: value transfer happened peer-to-peer using ecash transmittal while preserving a Lightning-address UX.

## Flow B: Automatic Fallback to Standard Lightning

If recipient is not Safebox-capable (`safebox` absent/false):

### 1. Sender receives standard LNURL callback invoice (`pr`)

`Acorn.pay_multi(...)` gets invoice via `lightning_address_pay(...)`.

### 2. Sender pays invoice using Cashu melt

Safebox selects proofs, requests melt quote, and executes melt against mint APIs.

### 3. Recipient gets a regular Lightning payment

No Safebox-specific secure ecash messaging is required.

## Why This Works Well

- One familiar address format for users (`name@domain`)
- Best path chosen automatically
- Fast in-network settlement between Safebox instances (ecash message transport)
- Broad interoperability with existing Lightning addresses via fallback

## Security Considerations

- Safebox path uses encrypted secure transmittal events (`kind=21401`) to recipient npub.
- `nonce` is included to correlate expected payment sessions and reduce replay/confusion.
- Payloads are encoded in `nembed` for robust transport across QR/NFC/text channels.
- Fallback keeps compatibility with the broader Lightning ecosystem when Safebox features are unavailable.

## Relevant Implementation Files

- `/Users/trbouma/projects/safebox-2/app/routers/safebox.py` (`/payaddress`)
- `/Users/trbouma/projects/safebox-2/safebox/acorn.py` (`pay_multi`, `secure_transmittal`, `get_ecash_latest`)
- `/Users/trbouma/projects/safebox-2/safebox/lightning.py` (`lightning_address_pay`)
- `/Users/trbouma/projects/safebox-2/app/routers/lnaddress.py` (`/.well-known/lnurlp/{name}`, `/lnpay/{name}`)
- `/Users/trbouma/projects/safebox-2/app/tasks.py` (`task_pay_multi`, `handle_ecash`)
