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

This differs from the Docker build path. In Docker, the `Dockerfile` explicitly clones and compiles `liboqs` from source and then installs the Python dependencies on top of that compiled shared library. On FreeBSD, the recommended path is to install both `liboqs` and `py311-liboqs-python` from the package repository, so the PQC library is supplied by the operating system rather than built locally during the Safebox install.

As a result, a long `poetry install` on FreeBSD does not necessarily mean `liboqs` is being rebuilt. More commonly, other native Python dependencies such as `cryptography`, `pydantic-core`, `uvloop`, `asyncpg`, or `pyzmq` are what take time to compile.

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

Safebox can derive a public origin from the incoming request when this value is unset, but explicit configuration is more reliable for public deployments. In particular, LNURL wallets such as Blink are sensitive to callback host and scheme mismatches, so `PUBLIC_BASE_URL` should be treated as recommended for production even though it remains optional in simpler environments.

Branding values can be set in `.env`, and explicit `.env` values now act as the final override for displayed branding. On a single-host FreeBSD deployment, you can either update `branding/default.yml` or set the values directly in `.env`:

```yaml
brand_name: SafeBox FreeBSD
brand_message: FreeBSD instance running
branding_retry_message: FreeBSD instance: please try again.
```

If you later host multiple domains from one instance, add host-specific branding files such as `branding/freebsd.safebox.dev.yml`.

## Running as a Daemon

For the current web application deployment, the simplest FreeBSD daemon approach is to run Safebox under a native `rc.d` service wrapper that starts the same Poetry-managed command you use interactively.

If you want to test daemonized execution directly from the command line first, you can use FreeBSD's `daemon` utility:

```sh
cd /usr/local/safebox-2
daemon -f -p /var/run/safebox.pid \
  /usr/bin/env APP_ENV=production \
  /home/trbouma/.local/bin/poetry run uvicorn app.main:app --host 0.0.0.0 --port 7375
```

To stop that manually started daemon:

```sh
kill "$(cat /var/run/safebox.pid)"
```

To inspect whether it is still running:

```sh
ps aux | grep uvicorn
```

For example, create `/usr/local/etc/rc.d/safebox`:

```sh
#!/bin/sh
#
# PROVIDE: safebox
# REQUIRE: LOGIN NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="safebox"
rcvar="safebox_enable"

load_rc_config $name

: ${safebox_enable:="NO"}
: ${safebox_user:="trbouma"}
: ${safebox_group:="trbouma"}
: ${safebox_dir:="/usr/local/safebox-2"}
: ${safebox_host:="0.0.0.0"}
: ${safebox_port:="7375"}
: ${safebox_command:="/home/trbouma/.local/bin/poetry"}
: ${safebox_env:="APP_ENV=production"}

pidfile="/var/run/${name}.pid"
command="/usr/sbin/daemon"
command_args="-f -p ${pidfile} /usr/bin/env ${safebox_env} ${safebox_command} run uvicorn app.main:app --host ${safebox_host} --port ${safebox_port}"

start_precmd="${name}_precmd"

safebox_precmd()
{
    cd "${safebox_dir}" || exit 1
    install -d -o "${safebox_user}" -g "${safebox_group}" /var/run
}

run_rc_command "$1"
```

Then:

```sh
chmod +x /usr/local/etc/rc.d/safebox
sysrc safebox_enable=YES
service safebox start
service safebox status
```

This keeps the service model close to your tested command:

```sh
poetry run uvicorn app.main:app --host 0.0.0.0 --port 7375
```

For a more production-style process model, you can replace the `uvicorn` command in `command_args` with Gunicorn:

```sh
/home/trbouma/.local/bin/poetry run gunicorn app.main:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:7375 \
  --timeout 120
```

Notes:

- Adjust `safebox_user`, `safebox_group`, `safebox_dir`, and the Poetry path for your system.
- Keep your `.env`, `branding/`, and `data/` paths readable by the service user.
- If you use a reverse proxy such as Nginx or Caddy, bind Safebox to localhost or a private interface instead of exposing it directly.
- The existing `safedaemon` script in the repository is for the older wallet-side daemon path and is not the recommended service wrapper for the FastAPI web application.

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
