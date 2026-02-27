# Safebox Configuration and Key Material Inventory

## Purpose

This document enumerates runtime configuration parameters and defaults, and identifies where cryptographic key material is generated and stored.

Primary sources:

- `app/config.py`
- `app/appmodels.py`
- `app/routers/safebox.py`
- `app/routers/lnaddress.py`
- `safebox/acorn.py`

## Configuration Resolution Order

### Application settings (`Settings` in `app/config.py`)

- Loaded from environment (via `BaseSettings`, `.env` enabled).
- If env value is absent, code default in `Settings` is used.

### Key fallback settings (`ConfigWithFallback` in `app/config.py`)

- Checks environment first for required key variables.
- If missing, reads `data/default.conf`.
- If still missing (or value is `notset`), generates keys and writes `data/default.conf`.
- Effective precedence:
  - environment variable
  - `data/default.conf`
  - generated-at-startup and persisted to `data/default.conf`

## Runtime Configuration Parameters and Defaults

The following defaults are defined in `Settings` (`app/config.py`).

### Core Service

- `APP_ENV`: `"development"`
- `SERVICE_NAME`: `"Safebox"`
- `SERVICE_TAG_LINE`: `"Your Funds. Your Records"`
- `SERVICE_SECRET_KEY`: `None`
- `SERVICE_RELAY_DB`: `"data/relay.db"`
- `TZ`: `"America/New_York"`
- `ALGORITHM`: `"HS256"`
- `LOGGING_LEVEL`: `10`
- `DATABASE`: `"sqlite:///data/database.db"`
- `DB_POOL_SIZE`: `10`
- `DB_MAX_OVERFLOW`: `20`
- `DB_POOL_RECYCLE_SECONDS`: `1800`
- `DB_POOL_TIMEOUT_SECONDS`: `30`

### Relay, Mint, and Network

- `HOME_RELAY`: `"wss://relay.getsafebox.app"`
- `HOME_MINT`: `"https://mint.getsafebox.app"`
- `RELAYS`: `["wss://relay.getsafebox.app"]`
- `ECASH_RELAYS`: `["wss://relay.getsafebox.app"]`
- `MINTS`: `["https://mint.getsafebox.app"]`
- `AUTH_RELAYS`: `["wss://relay.getsafebox.app"]`
- `NWC_RELAYS`: `["wss://relay.getsafebox.app"]`
- `TRANSMITTAL_RELAYS`: `["wss://relay.getsafebox.app"]`
- `DM_RELAYS`: `["wss://relay.getsafebox.app"]`
- `WOT_RELAYS`: `["wss://wotr.relatr.xyz","wss://nip85.brainstorm.world"]`
- `LOCAL_RELAY_PORT`: `8735`

### Protocol and Kinds

- `PQC_SIGALG`: `"ML-DSA-44"`
- `PQC_KEMALG`: `"ML-KEM-512"`
- `TRANSMITTAL_KIND`: `21060`
- `AUTH_KIND`: `21061`
- `CREDENTIAL_TRANSMITTAL_KIND`: `21062`
- `CREDENTIAL_TRANSMITTAL_RELAYS`: `["wss://relay.getsafebox.app"]`
- `RECORD_TRANSMITTAL_KIND`: `21062`
- `RECORD_TRANSMITTAL_RELAYS`: `["wss://relay.getsafebox.app"]`
- `OFFER_KINDS`: predefined list in `app/config.py` (default matrix)
- `GRANT_KINDS`: predefined list in `app/config.py` (default matrix)

### Timing and Session

- `TOKEN_EXPIRES_WEEKS`: `4`
- `TOKEN_EXPIRES_HOURS`: `8`
- `SESSION_AGE_DAYS`: `30`
- `LISTEN_TIMEOUT`: `120`
- `ECASH_LISTEN_TIMEOUT`: `120`
- `REFRESH_CURRENCY_INTERVAL`: `3600`

### Currency and Branding

- `SUPPORTED_CURRENCIES`: `["SAT","CAD","USD","EUR","GBP","JPY","INR"]`
- `CURRENCY_CSV`: `"setup/currency.csv"`
- `BRANDING`: `"Get SafeBox"`
- `BRANDING_MESSAGE`: `"Control your personal funds and data."`
- `BRANDING_RETRY`: `"Whoops! Let's try that again!"`
- `BRANDING_DIR`: `"branding"`

### NFC and Card Behavior

- `NFC_ECASH_CLEARING`: `True`
- `NFC_DEFAULT`: `["Badge","Member"]`
- `NWC_SERVICE`: `False`
- `WALLET_SWAP_MODE`: `False`

### Blob/Storage Services

- `BLOSSOM_SERVERS`: `["https://blossom.getsafebox.app"]`
- `BLOSSOM_HOME_SERVER`: `"https://blossom.getsafebox.app"`
- `BLOSSOM_XFER_SERVER`: `"https://blossomx.getsafebox.app"`

Note: `safebox/acorn.py` also has internal defaults for blossom endpoints and
resolves in this order inside `Acorn.__init__`:

- explicit constructor args
- environment (`BLOSSOM_HOME_SERVER`, `BLOSSOM_XFER_SERVER`, `BLOSSOM_SERVERS`)
- internal defaults:
  - `DEFAULT_BLOSSOM_HOME_SERVER = "https://blossom.getsafebox.app"`
  - `DEFAULT_BLOSSOM_XFER_SERVER = "https://blossomx.getsafebox.app"`

### CORS and Cookie Security

- `CORS_ALLOW_ORIGINS`:
  - `"https://getsafebox.app"`
  - `"https://www.getsafebox.app"`
  - `"https://openbrowserclaw.com"`
  - `"https://www.openbrowserclaw.com"`
  - `"http://localhost:7375"`
  - `"http://127.0.0.1:7375"`
- `COOKIE_SECURE`: `True`
- `COOKIE_SAMESITE`: `"Lax"`
- `CSRF_COOKIE_NAME`: `"csrf_token"`

### Agent Rate Limits and Access

- `AGENT_RATE_LIMIT_ENABLED`: `True`
- `AGENT_RPM`: `60`
- `AGENT_BURST`: `20`
- `AGENT_ONBOARD_RPM`: `10`
- `AGENT_ONBOARD_BURST`: `5`

### Miscellaneous

- `IP_INFO_TOKEN`: `"notset"`
- `INVITE_CODES`: `["alpha", "rektuser", "earlyaccess"]`

## Automatically Generated Keys

`ConfigWithFallback` auto-generates missing keys at startup when absent from
both environment and `data/default.conf`:

- `SERVICE_NSEC`
- `SERVICE_NPUB`
- `NWC_NSEC`
- `PQC_SIG_SECRET_KEY`
- `PQC_SIG_PUBLIC_KEY`
- `PQC_KEM_SECRET_KEY`
- `PQC_KEM_PUBLIC_KEY`

Generation behavior:

- Nostr keys via `monstr.encrypt.Keys()`
- PQ signature keys via `oqs.Signature(settings.PQC_SIGALG)`
- PQ KEM keys via `oqs.KeyEncapsulation(settings.PQC_KEMALG)`

Persistence behavior:

- Written to `data/default.conf` in stable key order.
- Existing env values are never overwritten by file values.

## Key Material Storage Locations

### File-based

- `data/default.conf`
  - service identity keys
  - NWC service key
  - PQ signature and KEM keypairs

### Database-backed

- `NWCSecret` table (`app/appmodels.py`)
  - `nwc_secret` (card/session secret mapping)
  - `npub` owner mapping
  - used by card issuance/rotation and token validation

- `RegisteredSafebox` table (`app/appmodels.py`)
  - `nsec` (nullable; may be stored for custodial/default wallet mode)
  - `npub`, `access_key`, and related wallet identity fields

### Runtime-only / Request-bound

- Browser cookies/tokens (access and CSRF) managed by routers.
- Ephemeral per-flow nonces generated at runtime (`generate_nonce`).
- Session-scoped `nauth`/`nembed` payloads passed through relay/websocket/API flows.

## Key Rotation and Lifecycle Notes

- NFC/card secret rotation:
  - `get_or_create_nwc_secret(..., rotate=True)` creates a new `NWCSecret`.
  - old card payloads become invalid once active mapping changes.
- Service key and PQ key rotation:
  - can be forced by deleting specific keys from env and `data/default.conf`
    before restart (new values are generated).
- Environment override remains highest priority and should be treated as
  production authority when set.

## Operational Recommendations

- In production, prefer explicit environment injection for all key material.
- Protect `data/default.conf` with strict filesystem permissions.
- Backup key-bearing data (`data/default.conf`, DB secrets) under encrypted
  operational procedures.
- Avoid mixing long-lived production keys with ad-hoc local fallback generation.
- After key or relay config changes, restart all web/worker processes.
