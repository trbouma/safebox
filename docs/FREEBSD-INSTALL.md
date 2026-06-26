# Running Safebox on FreeBSD

This document describes the steps required to build and run Safebox natively on FreeBSD.

These instructions were developed and tested on FreeBSD 15 using Python 3.11.

## Overview

Safebox runs successfully on FreeBSD, but several Python packages require native compilation. Before running `poetry install`, the appropriate development tools and system libraries must be installed.

Once these dependencies are present, Poetry is able to compile all required native extensions, including Rust-based packages such as:

- `pydantic-core`
- `cryptography`
- `uvloop`
- `asyncpg`
- `pyzmq`

## Prerequisites

Update the package repository:

```sh
pkg update
```

Install the required development tools:

```sh
pkg install \
    git \
    cmake \
    gmake \
    pkgconf
```

## Python

Install Python 3.11 and the required packaging tools:

```sh
pkg install \
    python311 \
    py311-pip \
    py311-setuptools \
    py311-wheel
```

On FreeBSD, the executable is typically available as `python3.11`.

Python 3.11 is currently recommended because package support on FreeBSD is more reliable than Python 3.12 for this stack.

## SQLite

Python's SQLite bindings are packaged separately on FreeBSD.

Install:

```sh
pkg install \
    sqlite3 \
    py311-sqlite3
```

Without this package the application will fail with:

```text
ModuleNotFoundError: No module named '_sqlite3'
```

## PostgreSQL Client

Safebox depends on `psycopg2`, which requires `pg_config`.

Install:

```sh
pkg install postgresql16-client
```

## Rust Toolchain

Several Python packages require Rust during installation.

Install:

```sh
pkg install rust
```

This provides:

- `rustc`
- `cargo`

## ZeroMQ

Install:

```sh
pkg install libzmq4
```

This is required for the `pyzmq` package.

## Open Quantum Safe

Safebox uses the Open Quantum Safe (`liboqs`) libraries.

Install:

```sh
pkg install \
    liboqs \
    py311-liboqs-python
```

This avoids runtime attempts to download and compile `liboqs`.

A warning similar to the following is currently harmless:

```text
liboqs version (major, minor) 0.15.0 differs from liboqs-python version 0.14.1
```

## Poetry

Install Poetry for the current user:

```sh
python3.11 -m pip install --user poetry
```

Ensure your shell includes:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

If needed, refresh your shell command cache:

```sh
rehash
```

## Installing Safebox

Clone the repository:

```sh
git clone <repository-url>
cd safebox-2
```

Create the virtual environment:

```sh
poetry env use python3.11
```

Install the project:

```sh
poetry install
```

## Build Time

The first installation may take a significant amount of time because several packages are compiled from source.

Packages commonly built locally include:

- `cryptography`
- `pydantic-core`
- `uvloop`
- `asyncpg`
- `pyzmq`

On older hardware this may take 20 to 60 minutes.

This is expected.

## Runtime Configuration

For an initial installation, Safebox requires bootstrap mode in order to generate its cryptographic secrets.

Start the application with:

```sh
SECRET_BOOTSTRAP_MODE=true poetry run uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Run this only for first-time initialization so Safebox can generate the required secrets.

After the generated secrets have been written to your `.env` file, disable bootstrap mode and start normally.

If you are accessing the service from another machine on your network, open:

```text
http://<host-ip>:8000
```

For a named public deployment, set `PUBLIC_BASE_URL` in `.env` so generated links and externally resolved wallet flows use the correct host:

```env
PUBLIC_BASE_URL=https://freebsd.safebox.dev
```

Branding values can also be set in `.env`, but visible UI branding is overridden by files in `branding/` when they exist. In practice, updating `branding/default.yml` is the most reliable way to change the displayed brand on a single-host FreeBSD deployment:

```yaml
brand_name: SafeBox FreeBSD
brand_message: FreeBSD instance running
branding_retry_message: FreeBSD instance: please try again.
```

If you later host multiple domains from one instance, add host-specific branding files such as `branding/freebsd.safebox.dev.yml`.

## Dependency Sanity Checks

After installation, it is useful to verify the core native modules explicitly:

```sh
python3.11 -c "import sqlite3, zmq, psycopg2"
python3.11 -c "import oqs"
```

If these imports succeed, the most common native dependency issues have been resolved.

## Common Issues

### Missing SQLite Support

Error:

```text
ModuleNotFoundError: No module named '_sqlite3'
```

Solution:

```sh
pkg install py311-sqlite3
```

### Missing PostgreSQL Client

Error:

```text
Error: pg_config executable not found
```

Solution:

```sh
pkg install postgresql16-client
```

### Missing liboqs

Error:

```text
liboqs not found
```

Solution:

```sh
pkg install \
    liboqs \
    py311-liboqs-python
```

### Long Compilation Times

The following packages compile native code and may take several minutes each:

- `uvloop`
- `cryptography`
- `asyncpg`
- `pyzmq`
- `pydantic-core`

This is normal, particularly on older hardware.

## Successful Startup

A successful startup should produce output similar to:

```text
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

At this point Safebox should be accessible from a browser.

## Next Steps

After confirming the application is running, consider:

- Running Safebox as a native FreeBSD `rc.d` service
- Deploying Nginx as a reverse proxy with HTTPS
- Using Tailscale for secure remote access
- Running Safebox inside a FreeBSD jail, for example with Bastille
- Leveraging ZFS snapshots before upgrades and database migrations

These provide a clean, lightweight, and reliable deployment path suitable for a dedicated Safebox appliance.
