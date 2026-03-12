# Zero-Config Docker Bootstrap and Production Path

## Purpose

Safebox aims to be instantly usable in a Docker-enabled environment with near-zero operator setup. The objective is simple: a developer or evaluator should be able to start the stack and run core flows quickly without pre-provisioning external infrastructure.

This document defines that bootstrap goal, why it is valuable, and the expected transition path to production-grade operation.

## Zero-Config Bootstrap Goal

In bootstrap mode, Safebox should:

- start with minimal environment variables,
- auto-generate required service keys when missing,
- use sane default endpoints for relays, mint, and blob services,
- run core QR/NFC, record, and payment flows for local validation.

This mode is optimized for:

- rapid testing,
- onboarding contributors,
- regression checks,
- functional demos.

## Example Docker Compose Bootstrap

The following `docker-compose.yaml` is the reference example for zero-config bootstrap testing. It is intentionally minimal and suitable for local evaluation or small test deployments.

```yaml
services:
  safebox-app:
    image: safebox/safebox:release-candidate
    build:
      context: "https://github.com/trbouma/safebox.git#release-candidate"
      dockerfile: Dockerfile
    restart: always
    container_name: safebox-bootstrap
    ports:
      - "7375:7375"
    environment:
      - TZ=America/New_York
      # - DATABASE=postgresql+psycopg2://postgres:yourpassword@yourdbserver:5432/safebox
    volumes:
      - ./data:/app/data
      - ./branding:/app/branding
    command: ["gunicorn", "app.main:app", "--workers", "4", "--worker-class", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:7375", "--timeout", "120"]
```

Bootstrap characteristics of this example:

- uses the `release-candidate` image/tag by default,
- persists local runtime data under `./data`,
- mounts `./branding` for local host-specific branding overrides,
- requires no database configuration unless the operator chooses to provide PostgreSQL.

To start:

```bash
docker compose up -d --build
```

To follow logs:

```bash
docker compose logs -f safebox-app
```

To stop:

```bash
docker compose down
```

## Why Zero-Config Matters

- Lowers setup friction and accelerates feedback loops.
- Makes development/test environments reproducible.
- Reduces configuration mistakes during initial evaluation.
- Encourages broader testing across real devices and browsers.

## Bootstrap Mode Boundaries

Zero-config is intentionally a convenience mode, not a production target.

Risks if left as-is in production:

- default infrastructure may be outside operator control,
- key material may be generated/stored in local fallback files without hardened secret management,
- single-node defaults reduce resilience and observability control,
- third-party service dependency introduces policy and availability risk.

## Recommended Production Transition

For production deployments, move from convenience defaults to operator-owned infrastructure.

### 1) Database

- Replace SQLite with PostgreSQL (`DATABASE` DSN).
- Use managed backups, migration discipline, and operational monitoring.

Why:

- Better concurrency behavior,
- improved durability/operability for multi-user or multi-instance deployments,
- clearer lifecycle controls for schema and recovery.

### 2) Relays

- Set `HOME_RELAY`, `RELAYS`, `AUTH_RELAYS`, `NWC_RELAYS`, and transmittal relay settings to infrastructure you control.

Why:

- Flow reliability depends on relay behavior.
- Cross-instance hardening requires predictable relay topology and policy.

### 3) Mints

- Set `HOME_MINT` and `MINTS` to trusted/operator-approved mint infrastructure.

Why:

- Settlement reliability and operational guarantees depend on mint control and policy.

### 4) Blossom Services

- Set `BLOSSOM_HOME_SERVER`, `BLOSSOM_XFER_SERVER`, and `BLOSSOM_SERVERS` to operator-managed endpoints.

Why:

- Record/blob transfer durability and retention/deletion policy should be operator-controlled.
- Dedicated transfer endpoints simplify cleanup and operational isolation.

### 5) Keys and Secrets

- Move from auto-generated fallback persistence to explicit secret management.
- Inject service and PQ key material via controlled environment/secret manager workflows.

Why:

- Reduces accidental key drift across deploys.
- Improves auditability and incident response posture.

## Operational Posture by Environment

### Development / Test

- Zero-config Docker bootstrap is acceptable and preferred for speed.
- Auto-generated keys and default external services are acceptable for non-critical environments.

### Staging / Production

- Explicit configuration is required.
- Operator-owned Postgres, relays, mints, and blossom services are strongly recommended.
- Key material should be managed as controlled secrets, not ad-hoc local fallbacks.

## Practical Checklist

Before promoting to production:

1. Set `DATABASE` to PostgreSQL.
2. Set relay variables to operator-controlled endpoints.
3. Set mint variables to operator-trusted endpoints.
4. Set blossom variables to operator-controlled endpoints.
5. Validate key source of truth (environment/secret manager).
6. Restart all services after configuration changes.
7. Run full cross-instance QR/NFC regression checks.

## Summary

Safebox’s zero-config Docker experience is a deliberate design choice for fast start and rapid validation. It is ideal for testing and early adoption.

Production readiness, however, requires explicit operator control of core dependencies: database, relays, mints, blob infrastructure, and secrets. The recommended path is not to remove zero-config, but to treat it as a bootstrap phase and transition to controlled infrastructure before handling real value or high-trust records.
