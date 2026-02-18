# Safebox

Control your funds and records with a sovereign, protocol-native wallet.

Safebox is an experimental Python/FastAPI application that combines:

- Cashu ecash wallet functionality
- Nostr-native secure messaging/transmittal
- Record offer/present/accept flows (including NFC-assisted flows)
- Optional post-quantum payload protection (ML-KEM)
- Blob storage and transfer workflows via Blossom

## Why Safebox

Most systems force a tradeoff between convenience and control.

Safebox aims for a hybrid model:

- user-friendly inputs where they help adoption (for example Lightning addresses)
- key-addressed protocol flows where security matters (`npub`, encrypted Nostr events)
- transport security (HTTPS/WSS) plus payload security layered above transport

## Current Status

Safebox is actively developed and still experimental.

Use with caution, test before production, and treat all deployments as security-sensitive.

## Core Capabilities

- Wallet
  - deposit via Lightning invoice
  - pay invoice or Lightning address
  - issue and accept Cashu ecash tokens
  - multi-mint proof handling and consolidation
- Records
  - store private records and blob-backed records
  - offer and present records through `nauth`/`nembed` flows
  - transfer original encrypted blobs for grant/presentation workflows
- NFC + Vault flows
  - NFC card issuance and login
  - NFC-assisted payment and record workflows
  - vault endpoints that validate/sign requests before forwarding NWC instructions
  - PIN-gated record presentation support
- Quantum-safe payload protection
  - ML-KEM key agreement for selected sensitive transmittal payloads

## Architecture (High Level)

- API/UI: FastAPI + Jinja templates (`app/`)
- Wallet engine: `Acorn` (`safebox/acorn.py`)
- NWC extension service: `app/nwc.py`
- Storage:
  - SQLModel database (default SQLite at `data/database.db`)
  - Nostr event storage for encrypted wallet/record data
- Optional blob layer: Blossom server APIs

## Quick Start (Local)

### 1) Prerequisites

- Python `3.11+`
- Poetry
- Access to at least one relay and mint (defaults are preconfigured)

### 2) Install

```bash
poetry install
```

### 3) Configure

Create/update `.env` (optional at first; defaults exist). Important values include:

- `APP_ENV`
- `DATABASE`
- `HOME_RELAY`
- `HOME_MINT`
- `RELAYS`
- `MINTS`
- `NWC_RELAYS`
- `CORS_ALLOW_ORIGINS`
- `COOKIE_SECURE`

Safebox also uses generated/managed keys via `ConfigWithFallback`.

### 4) Run

Development server:

```bash
poetry run uvicorn app.main:app --host 0.0.0.0 --port 7375 --reload
```

Production-style command (same pattern as compose):

```bash
poetry run gunicorn app.main:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:7375 \
  --timeout 120
```

Open:

- `http://localhost:7375`

### 5) Onboarding

Default invite codes are configured in `app/config.py` (`INVITE_CODES`) and include `alpha` by default.

## Docker

Use the included `Dockerfile` and `docker-compose.yaml`.

```bash
docker compose up --build -d
docker compose logs -f
```

Default exposed app port:

- `7375`

Persisted data volume in compose:

- `./data:/app/data`

## CLI

Poetry exposes these scripts:

- `safebox`
- `acorn`
- `safedaemon`

Example:

```bash
poetry run safebox --help
```

## Security Notes

- In production mode, Safebox enforces stricter startup checks (for example explicit CORS and secure cookie settings).
- Treat secrets (`SERVICE_NSEC`, `NWC_NSEC`, PQC keys) as critical credentials.
- TLS/WSS protect transport hops; sensitive workflows also rely on payload-level encryption.
- Review and harden vault-facing endpoints before internet exposure.

## Specs and Protocol Docs

See:

- `docs/specs/INDEX.md`

The specs folder documents key protocols/flows, including:

- Cashu storage + multi-mint behavior
- NWC + NFC vault extension
- nembed format
- transport vs payload security model
- ML-KEM usage
- Blossom blob encryption and transfer

## Repository Layout

- `app/` FastAPI app, routers, templates, NWC integration
- `safebox/` wallet engine and protocol primitives
- `docs/specs/` protocol and architecture specifications
- `Dockerfile`, `docker-compose.yaml` container deployment

## Disclaimer

Safebox is experimental software. No warranty is provided. Audit, test, and stage carefully before production use.
