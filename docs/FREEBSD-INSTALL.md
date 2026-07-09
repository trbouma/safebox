# Running Safebox on FreeBSD

This document describes the steps required to build and run Safebox natively on FreeBSD.

These instructions were developed and tested on FreeBSD 15 using Python 3.11.

## Overview

Safebox runs successfully on FreeBSD, but several Python packages require native compilation. Before running `poetry install`, the appropriate development tools and system libraries must be installed.

Once these dependencies are present, Poetry is able to compile all required native extensions, including Rust-based packages such as:

- `pydantic-core`
- `cryptography`
- `asyncpg`
- `pyzmq`

`uvloop` should be treated as optional on FreeBSD. The standard asyncio event
loop is acceptable for the FreeBSD deployment path.

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

As a result, a long `poetry install` on FreeBSD does not necessarily mean `liboqs` is being rebuilt. More commonly, other native Python dependencies such as `cryptography`, `pydantic-core`, `asyncpg`, or `pyzmq` are what take time to compile.

If `liboqs` is built from source, make sure it is built as a shared library
with `-DBUILD_SHARED_LIBS=ON`; the Python wrapper needs to load
`/usr/local/lib/liboqs.so`.

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
poetry config virtualenvs.in-project true
poetry env use python3.11
```

When relying on FreeBSD package-provided native modules such as `coincurve`,
`yarl`, `multidict`, `frozenlist`, or `psycopg2`, enable system site packages
before creating the environment:

```sh
poetry config virtualenvs.options.system-site-packages true
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
- `asyncpg`
- `pyzmq`

On older hardware this may take 20 to 60 minutes.

On Raspberry Pi and other lower-power ARM systems, the `Preparing metadata (pyproject.toml)` phase can also take a long time before you see obvious progress. That does not necessarily mean the install is stuck. It often means Poetry and `pip` are still evaluating or building native dependencies in the background.

This is expected.

If you want to confirm the install is still making progress, open another shell and run:

```sh
top
```

If you see processes such as `python3.11`, `rustc`, `cargo`, or `cc` using CPU, the install is usually still progressing normally.

## Runtime Configuration

For an initial installation, Safebox can generate its cryptographic secrets automatically when the secret store is empty. This guarded first-run auto-bootstrap behavior is enabled by default.

You can also force explicit bootstrap mode if you want deterministic operator control:

```sh
SECRET_BOOTSTRAP_MODE=true poetry run uvicorn app.main:app --host 0.0.0.0 --port 8000
```

If you want to be explicit about the default automatic behavior, you can still run:

```sh
AUTO_BOOTSTRAP_ON_EMPTY_SECRET_STORE=true poetry run uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The automatic mode only bootstraps when the secret store is truly empty. If Safebox detects partial or previously initialized secret state, startup still fails closed instead of silently generating a new identity.

Use either mode only for first-time initialization so Safebox can generate the required secrets.

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
cd /usr/local/safebox
daemon -f -p /usr/local/safebox/data/safebox.pid \
  /usr/bin/env APP_ENV=production \
  /home/safebox/.local/bin/poetry run gunicorn app.main:app \
    --workers 1 \
    --worker-class uvicorn.workers.UvicornWorker \
    --bind 0.0.0.0:7375 \
    --timeout 120
```

To stop that manually started daemon:

```sh
kill "$(cat /usr/local/safebox/data/safebox.pid)"
```

To inspect whether it is still running:

```sh
ps aux | grep gunicorn
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
: ${safebox_user:="safebox"}
: ${safebox_group:="safebox"}
: ${safebox_dir:="/usr/local/safebox"}
: ${safebox_host:="127.0.0.1"}
: ${safebox_port:="7375"}
: ${safebox_command:="/home/safebox/.local/bin/poetry"}
: ${safebox_stdout:="/usr/local/safebox/logs/safebox.log"}
: ${safebox_stderr:="/usr/local/safebox/logs/safebox.err"}

command="/usr/sbin/daemon"
command_args="-f -r -u ${safebox_user} -o ${safebox_stdout} -e ${safebox_stderr} /bin/sh -c 'cd ${safebox_dir} && exec ${safebox_command} run gunicorn app.main:app --workers 1 --worker-class uvicorn.workers.UvicornWorker --bind ${safebox_host}:${safebox_port} --timeout 120'"

run_rc_command "$1"
```

Then:

```sh
chmod +x /usr/local/etc/rc.d/safebox
sysrc safebox_enable=YES
service safebox start
service safebox status
```

This keeps the service model close to the tested production-style command:

```sh
poetry run gunicorn app.main:app \
  --workers 1 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:7375 \
  --timeout 120
```

Notes:

- `daemon -r` provides restart-on-exit behavior.
- Use `--workers 1` for first startup and for SQLite-backed deployments. A
  fresh SQLite database can hit a schema creation race when multiple Gunicorn
  workers start at the same time. Use PostgreSQL before increasing workers for
  production.
- The service runs as the non-root `safebox` user.
- SafeBox reads `.env` itself through `pydantic-settings`; the service wrapper should not source `.env` as a shell script.
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

If building from source, configure CMake with:

```sh
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON ..
ninja
ninja install
ldconfig
```

### uvloop on FreeBSD

`uvloop` is not required for the FreeBSD service path. If it fails to build or
import, use the standard asyncio loop and make `uvloop` conditional on
non-FreeBSD platforms.

### Slow native modules

Prefer FreeBSD packages where available:

```sh
pkg install py311-coincurve py311-yarl py311-multidict py311-frozenlist py311-psycopg2
poetry config virtualenvs.options.system-site-packages true
```

If the repository pins `coincurve = "20.0.0"` and FreeBSD provides
`py311-coincurve` 21.x, relax the local constraint before installing:

```toml
coincurve = ">=20.0.0,<22.0.0"
```

Then run:

```sh
poetry update coincurve
poetry install --only main
```

### Long Compilation Times

The following packages compile native code and may take several minutes each:

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
- Running Safebox inside a FreeBSD jail; see
  [SafeBox in a FreeBSD Jail](devops/freebsd-jail-from-scratch.md)
- Leveraging ZFS snapshots before upgrades and database migrations

These provide a clean, lightweight, and reliable deployment path suitable for a dedicated Safebox appliance.
