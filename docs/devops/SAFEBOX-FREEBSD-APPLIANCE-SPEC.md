# SafeBox FreeBSD Appliance Specification

## Purpose

This document defines the current target architecture for running SafeBox as a dedicated FreeBSD appliance and provides a step-by-step deployment sequence that can be followed on a fresh host.

The intended end state is:

- FreeBSD-based dedicated SafeBox appliance
- SafeBox web application running as a non-root service account
- HTTPS exposed through a reverse proxy
- remote administration only over Tailscale and SSH
- minimal ongoing administration
- compatibility with later migration into a Bastille jail

This is both:

- an appliance architecture specification
- an operator runbook for building the current appliance manually

## Appliance Goals

The appliance should:

- boot directly into the SafeBox service
- automatically start SafeBox on boot
- restart the service after crashes, using a simple supervising strategy
- expose the application over HTTPS
- join an existing Tailscale network
- run as a non-root service account
- keep application data out of `/root`
- require little or no interactive administration after setup

## Target Platform

### Base OS

- FreeBSD 15.x
- ZFS root filesystem preferred

### Current Development VM

- UTM on Apple Silicon
- ARM64
- 60 GB virtual disk
- 8 GB RAM
- 4 CPU cores

### Production Target

- dedicated FreeBSD hardware appliance

## Runtime Architecture

The intended service order is:

1. system boot
2. networking
3. `tailscaled`
4. reverse proxy
5. SafeBox application service

Current application runtime:

- Gunicorn
- `uvicorn.workers.UvicornWorker`
- SafeBox bound on port `7375`

Recommended production network layout:

- nginx listens publicly on `443`
- SafeBox listens privately on `127.0.0.1:7375`

Development/testing may temporarily use:

- `0.0.0.0:7375`

## Application Layout

Preferred install root:

```text
/usr/local/safebox/
```

Recommended tree after installation:

```text
/usr/local/safebox/
    branding/
    data/
    logs/
    .env
    .venv/
    app/
    pyproject.toml
    poetry.lock
```

The application should not be installed under `/root`.

## Service Account

Dedicated service account:

- user: `safebox`
- group: `safebox`

Recommended shell:

- `/usr/sbin/nologin` for steady state
- `/bin/sh` may be used temporarily during development

Ownership:

- `/usr/local/safebox` and all application state should be owned by `safebox:safebox`

## Key Runtime Requirements

SafeBox requires the following secret material:

- `NWC_NSEC`
- `PQC_KEM_PUBLIC_KEY`
- `PQC_KEM_SECRET_KEY`
- `PQC_SIG_PUBLIC_KEY`
- `PQC_SIG_SECRET_KEY`
- `SERVICE_NPUB`
- `SERVICE_NSEC`

Current bootstrap behavior:

- guarded first-run auto-bootstrap is enabled by default
- on a truly empty secret store, SafeBox will generate and persist secrets automatically
- if partial or previously initialized secret state is detected, startup fails closed

Explicit bootstrap remains available with:

```env
SECRET_BOOTSTRAP_MODE=true
```

Steady-state production should run with:

```env
SECRET_BOOTSTRAP_MODE=false
```

## Networking and External Access

### Public Base URL

Set:

```env
PUBLIC_BASE_URL=https://your-hostname.example
```

This is strongly recommended for public deployments because LNURL wallet clients such as Blink are sensitive to callback host and scheme mismatches.

### HTTPS

Production should be HTTPS-only.

Reasons:

- browser security expectations
- CSRF/session correctness
- third-party wallet interoperability
- appliance-quality deployment posture

### Tailscale

The appliance joins an existing Tailnet.

Expected services reachable over Tailscale:

- SSH
- HTTPS

## Reverse Proxy

Target reverse proxy:

- nginx

Required features:

- HTTPS termination
- Let's Encrypt support
- HTTP to HTTPS redirect
- reverse proxy to local SafeBox port

Recommended final proxy shape:

- nginx listens on `80` and `443`
- redirects `80` to `443`
- proxies `443` to `http://127.0.0.1:7375`
- forwards `Host`, `X-Forwarded-Host`, and `X-Forwarded-Proto`

## Jail Architecture

Validated native-jail target:

- host OS manages ZFS, jail lifecycle, Tailscale, and nginx
- SafeBox runs inside a dedicated FreeBSD jail
- the simplest validated jail networking mode is `ip4 = inherit`

Longer-term variants may use Bastille or VNET if the deployment needs more
automation or stronger network isolation.

Target separation:

Host:

- ZFS
- Bastille
- Tailscale
- nginx

Jail:

- Python
- Poetry
- SafeBox
- SafeBox data

The application should require minimal or no code changes when moved into the jail.

## Current Status

Completed:

- FreeBSD installed
- Python working
- Poetry working
- Rust toolchain working
- SafeBox builds successfully
- `liboqs` working
- SQLite working
- bootstrap secrets working
- SafeBox runs manually
- SafeBox runs via `daemon`
- SafeBox runs inside a native FreeBSD jail
- `bsdinstall jail` path validated for a clean single-jail install

In progress:

- `rc.d` service
- nginx reverse proxy
- Tailscale integration
- automated bootstrap script

Planned:

- Bastille or VNET variant, if needed
- automated deployment
- production appliance image

## Step-by-Step Build Sequence

This sequence assumes a fresh FreeBSD host.

### 1. Update the system and install required packages

As `root`:

```sh
pkg update
pkg install -y \
  git \
  python311 \
  py311-pip \
  py311-setuptools \
  py311-wheel \
  py311-sqlite3 \
  rust \
  cmake \
  ninja \
  pkgconf \
  sqlite3 \
  postgresql16-client \
  liboqs \
  py311-liboqs-python \
  openssl \
  ca_root_nss \
  tailscale \
  nginx
```

Optional:

```sh
pkg install -y llvm
```

Note:

- `clang` is often provided by the FreeBSD base system and may not exist as a separate `pkg` package
- verify with:

```sh
clang --version
which clang
```

### 2. Create the service account

As `root`:

```sh
pw groupadd safebox
pw useradd safebox -g safebox -d /home/safebox -m -s /bin/sh
```

Later, after setup stabilizes, you can lock this down:

```sh
chsh -s /usr/sbin/nologin safebox
```

### 3. Create the application layout

As `root`:

```sh
install -d -o safebox -g safebox /usr/local/safebox
```

### 4. Install Poetry for the service user

As `root`:

```sh
su - safebox
python3.11 -m pip install --user poetry
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.profile
. ~/.profile
hash -r
```

If `hash -r` is not available in your shell, simply log out and start a fresh `su - safebox` session before running `poetry`.

Verify the installed Poetry path:

```sh
su - safebox -c 'which poetry'
```

Use that returned path in later daemon and `rc.d` service configuration examples.

### 5. Clone SafeBox

As `root`:

```sh
git clone <repository-url> /usr/local/safebox
chown -R safebox:safebox /usr/local/safebox
```

After cloning, create the writable runtime directories:

```sh
install -d -o safebox -g safebox /usr/local/safebox/logs
install -d -o safebox -g safebox /usr/local/safebox/data
install -d -o safebox -g safebox /usr/local/safebox/branding
```

### 6. Create and install the Poetry environment

As user `safebox`:

```sh
cd /usr/local/safebox
/home/safebox/.local/bin/poetry config virtualenvs.in-project true
/home/safebox/.local/bin/poetry env use python3.11
/home/safebox/.local/bin/poetry install
```

Expect long compile times for some dependencies on FreeBSD. This is normal.

Verify the in-project virtual environment exists:

```sh
ls -l /usr/local/safebox/.venv/bin/python
ls -l /usr/local/safebox/.venv/bin/uvicorn
ls -l /usr/local/safebox/.venv/bin/gunicorn
```

### 7. Verify core dependencies

As user `safebox`:

```sh
python3.11 -c "import sqlite3"
python3.11 -c "import oqs"
/usr/local/safebox/.venv/bin/python -c "import coincurve, oqs, psycopg2, zmq; print('ok')"
```

### 8. Create the base `.env`

As user `safebox`, create `/usr/local/safebox/.env`:

```env
APP_ENV=production
DATABASE=sqlite:///data/database.db
PUBLIC_BASE_URL=https://freebsd.safebox.dev
BRANDING=SafeBox FreeBSD
BRANDING_MESSAGE=FreeBSD instance running
BRANDING_RETRY=FreeBSD instance: please try again.
COOKIE_SECURE=true
SECRET_BOOTSTRAP_MODE=false
```

Notes:

- `AUTO_BOOTSTRAP_ON_EMPTY_SECRET_STORE` now defaults to `true`
- `SECRET_BOOTSTRAP_MODE=false` is the correct steady-state setting
- if this is the first startup and the secret store is truly empty, bootstrap should still occur automatically

### 9. Set branding override file if desired

If you want file-based default branding in addition to `.env`, create:

```text
/usr/local/safebox/branding/default.yml
```

Example:

```yaml
brand_name: SafeBox FreeBSD
brand_message: FreeBSD instance running
branding_retry_message: FreeBSD instance: please try again.
```

`.env` branding values are the final override if set.

### 10. Test manual startup

As user `safebox`:

```sh
cd /usr/local/safebox
poetry run uvicorn app.main:app --host 0.0.0.0 --port 7375
```

Confirm:

- the app starts
- bootstrap secrets are generated on the first clean run
- the UI is reachable
- branding appears correctly

This is the initial server test. Keep it simple here. Later production guidance can tighten the bind address once `nginx` is in front.

### 11. Test production-style startup

As user `safebox`:

```sh
cd /usr/local/safebox
/usr/local/safebox/.venv/bin/gunicorn \
  --chdir /usr/local/safebox \
  app.main:app \
  --workers 1 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:7375 \
  --timeout 120
```

Do not proceed to daemon or `rc.d` setup until both the manual `uvicorn` and manual `gunicorn` commands work correctly as the `safebox` user.

Use one worker for the first startup and for SQLite-backed deployments. A fresh
SQLite database can race during schema creation if multiple Gunicorn workers
start simultaneously. After the database is initialized, two workers may work,
but PostgreSQL is the safer path before increasing worker count for production.

### 12. Test daemonized execution from the command line

Only do this after the manual commands above work.

As `root` or an appropriate operator:

```sh
cd /usr/local/safebox
daemon -f -p /usr/local/safebox/data/safebox.pid \
  /usr/local/safebox/.venv/bin/gunicorn \
    --chdir /usr/local/safebox \
    app.main:app \
    --workers 1 \
    --worker-class uvicorn.workers.UvicornWorker \
    --bind 0.0.0.0:7375 \
    --timeout 120
```

Stop it:

```sh
kill "$(cat /usr/local/safebox/data/safebox.pid)"
```

### 13. Enable SSH and Tailscale

As `root`:

```sh
sysrc sshd_enable=YES
service sshd start

sysrc tailscaled_enable=YES
service tailscaled start
```

### 14. Join the appliance to Tailscale

Once `tailscaled` is running, join the appliance to your Tailnet.

Interactive join:

```sh
tailscale up
```

If you want to advertise a stable appliance name:

```sh
tailscale up --hostname safebox-freebsd
```

If you are using an auth key for unattended provisioning:

```sh
tailscale up --authkey tskey-xxxxxxxxxxxxxxxx --hostname safebox-freebsd
```

Useful verification commands:

```sh
tailscale status
tailscale ip
```

At this point, verify you can administer the box over Tailscale SSH/network paths.

### 15. Create the FreeBSD `rc.d` service

Create `/usr/local/etc/rc.d/safebox`:

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
: ${safebox_dir:="/usr/local/safebox"}
: ${safebox_host:="0.0.0.0"}
: ${safebox_port:="7375"}
: ${safebox_gunicorn:="/usr/local/safebox/.venv/bin/gunicorn"}
: ${safebox_log:="/usr/local/safebox/logs/safebox.log"}
: ${safebox_pidfile:="/usr/local/safebox/data/safebox.pid"}

command="/usr/sbin/daemon"
command_args="-f -r -p ${safebox_pidfile} -o ${safebox_log} -m 3 /usr/bin/su -m safebox /bin/sh -c '${safebox_gunicorn} --chdir ${safebox_dir} app.main:app --workers 1 --worker-class uvicorn.workers.UvicornWorker --bind ${safebox_host}:${safebox_port} --timeout 120'"

run_rc_command "$1"
```

Then:

```sh
chmod +x /usr/local/etc/rc.d/safebox
sysrc safebox_enable=YES
service safebox start
service safebox status
```

Notes:

- the service uses the stable in-project virtualenv at `/usr/local/safebox/.venv`
- SafeBox reads `.env` itself through `pydantic-settings`; the service wrapper should not source `.env` as a shell script
- do not move to this step until manual `uvicorn` and `gunicorn` both work as `safebox`
- you can tighten the bind to `127.0.0.1` later once nginx is in front

### 16. Configure nginx reverse proxy

Create a basic nginx site config such as:

```nginx
server {
    listen 80;
    server_name freebsd.safebox.dev;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name freebsd.safebox.dev;

    ssl_certificate /usr/local/etc/letsencrypt/live/freebsd.safebox.dev/fullchain.pem;
    ssl_certificate_key /usr/local/etc/letsencrypt/live/freebsd.safebox.dev/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:7375;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
    }
}
```

Then enable nginx:

```sh
sysrc nginx_enable=YES
service nginx start
```

Certificate issuance can be added once DNS is in place.

### 17. Lock the application down for steady state

After everything works:

- ensure `SECRET_BOOTSTRAP_MODE=false`
- keep `PUBLIC_BASE_URL` set
- switch service shell to `/usr/sbin/nologin` if desired
- expose HTTPS only
- keep SafeBox bound locally behind nginx

Recommended shell lock-down:

```sh
chsh -s /usr/sbin/nologin safebox
```

### 18. Regression checklist before treating the appliance as stable

Verify:

1. SafeBox starts automatically after reboot
2. SafeBox restarts after process crash
3. Tailscale comes up on boot
4. nginx proxies successfully to SafeBox
5. HTTPS works without mixed-content issues
6. Blink and other LNURL wallets work with the configured `PUBLIC_BASE_URL`
7. branding appears correctly
8. secrets are reused across restarts
9. partial secret deletion causes a fail-closed startup rather than silent regeneration

## Operational Notes

### OQS behavior

On Docker:

- `liboqs` is compiled during image build

On FreeBSD:

- `liboqs` and `py311-liboqs-python` come from `pkg`

This means a long `poetry install` on FreeBSD is usually due to other native dependencies, not necessarily OQS itself.

### coincurve

Older project revisions pinned:

```text
coincurve==20.0.0
```

On FreeBSD 15/arm64, the package repository may provide `py311-coincurve` 21.x.
If Poetry attempts to downgrade to 20.0.0, it can force a source build and fail
in `scikit-build-core`. For FreeBSD, relax the local constraint to:

```text
coincurve>=20.0.0,<22.0.0
```

Then run `poetry update coincurve` before `poetry install --only main`.

### Logging

Current acceptable paths:

- `/usr/local/safebox/logs/safebox.log`
- stdout/stderr captured by `daemon`

Longer term, log rotation should be handled by `newsyslog` or a similarly explicit rotation policy.

## Next Implementation Targets

The next artifacts that should be generated from this spec are:

1. `ops/freebsd/rc.d/safebox`
2. `ops/freebsd/nginx/safebox.conf`
3. `ops/freebsd/bootstrap/setup-safebox-appliance.sh`
4. `ops/freebsd/bastille/`

## Summary

SafeBox is now in a good position to become a FreeBSD appliance:

- it builds on FreeBSD
- it can bootstrap secrets on first run
- it runs under Poetry and Gunicorn
- it can be daemonized
- it can be exposed through HTTPS and Tailscale

The remaining work is mostly packaging, service integration, and deployment automation rather than core application changes.
