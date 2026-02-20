# Database Backends and Migrations

## Overview

Safebox supports both:

1. SQLite (`sqlite:///...`)
2. PostgreSQL (`postgresql+psycopg2://...`)

SQLite is useful for local/single-node setups. PostgreSQL is recommended for production durability, concurrency, and operational scaling.

## Scope

This specification defines:

1. Supported database backends
2. Connection/engine behavior
3. Schema management via Alembic
4. Startup safety considerations
5. Operational practices for migration and deployment

## Supported Backends

### SQLite

Use cases:

1. Local development
2. Lightweight single-instance deployments

Characteristics:

1. File-based DB
2. Lower operational complexity
3. Limited write concurrency compared to PostgreSQL

### PostgreSQL

Use cases:

1. Production deployments
2. Multi-worker/multi-instance application runtimes
3. Higher reliability and operational control

Characteristics:

1. Networked RDBMS
2. Better concurrent write handling
3. Recommended for resilient deployments and operational growth

## Configuration

Primary database URL:

1. `DATABASE`

Examples:

1. `sqlite:///data/database.db`
2. `postgresql+psycopg2://postgres:password@db-host:5432/safebox`

Pool tuning parameters (primarily relevant for PostgreSQL):

1. `DB_POOL_SIZE`
2. `DB_MAX_OVERFLOW`
3. `DB_POOL_RECYCLE_SECONDS`
4. `DB_POOL_TIMEOUT_SECONDS`

Branding and other app-level settings are independent of DB backend selection.

## Engine and Session Model

Safebox uses a centralized DB engine/session model (`app/db.py`) rather than creating independent engines per module.

Behavior:

1. Shared engine across app modules
2. `pool_pre_ping` enabled for connection health checks
3. SQLite path uses backend-safe connection arguments
4. PostgreSQL path uses configurable pool sizing/timeouts

## Schema and Migration Model

Alembic is used as schema authority for managed environments.

Baseline revision:

1. `20260220_0001`

Expected migration workflow:

1. `poetry run alembic upgrade head` before app startup in deployment pipelines
2. `poetry run alembic current -v` for verification

For pre-existing databases:

1. Use `alembic stamp <revision>` when schema already exists and must be aligned to migration history.

## Startup and Integrity Guards

Application startup performs integrity checks that enforce uniqueness for core wallet identity fields.

Current enforced uniqueness:

1. `registeredsafebox.npub`
2. `registeredsafebox.handle`
3. `registeredsafebox.access_key` (non-null)

If duplicates exist, startup should fail fast with clear diagnostics rather than serving inconsistent wallet resolution behavior.

## Concurrency-Safe Initialization

Initialization paths that may run under multi-worker startup should be idempotent and conflict-safe.

Example:

1. Currency CSV initialization uses conflict-safe insert semantics to avoid duplicate key failures when multiple workers start concurrently.

## Deployment Guidance

### SQLite deployment

1. Ensure writable DB file path
2. Use persistent volume for DB file
3. Prefer single-writer operational patterns

### PostgreSQL deployment

1. Run Alembic migrations before application workers start
2. Set DB pool tuning values for expected load
3. Monitor connection usage and statement errors
4. Keep regular backups and restore testing in place

## Limitations and Future Work

1. Per-host/per-brand database routing is not currently implemented.
2. Current model is single app instance DB target selected by `DATABASE`.
3. Multi-tenant per-request DB routing requires a separate tenant/session architecture specification.

## Implementation References

1. `app/db.py`
2. `app/config.py`
3. `app/main.py`
4. `alembic.ini`
5. `alembic/env.py`
6. `alembic/versions/20260220_0001_baseline.py`
