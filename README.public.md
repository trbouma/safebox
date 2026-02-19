# Safebox

Safebox is a sovereign wallet and records platform that helps people control funds and sensitive data using open protocols.

Safebox is built to feel familiar while keeping cryptographic control with the user.

## What Safebox Does

- Send and receive value with Cashu + Lightning-compatible flows
- Store and share private records securely
- Use NFC cards for practical in-person payment and record workflows
- Layer payload security on top of transport security
- Support advanced cryptography (including quantum-safe payload options)

## Why Safebox

Many tools are either:

- easy to use but highly centralized, or
- sovereign but hard to use in the real world

Safebox is designed as a hybrid approach:

- human-friendly interfaces for adoption
- key-native protocols for security and portability

## Typical Use Cases

- Personal sovereign wallet and secure data vault
- NFC-based payment and record exchange flows
- Organization and community workflows that require signed, verifiable records

## Quick Start

## Run with Docker

```bash
docker compose up --build -d
```

App default URL:

- `http://localhost:7375`

## Run Locally (Developer)

```bash
poetry install
poetry run uvicorn app.main:app --host 0.0.0.0 --port 7375 --reload
```

## Learn More

- Technical/protocol specs: `docs/specs/INDEX.md`
- Developer README: `README.md`

## Project Status

Safebox is actively developed and experimental. Use staged testing before production deployment.

![Safebox Logo](./assets/safebox-orginal.png)
