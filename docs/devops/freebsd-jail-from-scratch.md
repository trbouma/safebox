# SafeBox in a FreeBSD Jail: From-Scratch Runbook

This runbook creates a dedicated FreeBSD jail for SafeBox, builds its native
dependencies, starts SafeBox with an `rc.d` service, and leaves the jail ready
for repeatable upgrades.

The commands target FreeBSD 15 and Python 3.11. Replace example values before
running them. A jail userland must not be newer than its host kernel.

## Resulting layout

The host owns networking, ZFS, backups, and the jail lifecycle:

```text
FreeBSD host
├── zroot/jails/templates/15.1-RELEASE
├── zroot/jails/containers/safebox
└── /etc/jail.conf.d/safebox.conf
```

The jail owns the application and its runtime:

```text
/usr/local/safebox
├── .env
├── .venv
├── app
├── branding
├── data
└── logs
```

This guide uses a ZFS clone (a thin jail) and a simple shared-network-stack IP.
That is easier to reproduce than VNET and is sufficient when the host provides
the reverse proxy. A VNET variant is described later.

## Before you begin

Choose values appropriate for the host:

| Setting | Example |
| --- | --- |
| Host ZFS pool | `zroot` |
| FreeBSD release | `15.1-RELEASE` |
| Architecture | `arm64` or `amd64` |
| Jail name | `safebox` |
| Jail IP | `192.168.1.51` |
| Host interface | `em0` (often `ue0` on a Raspberry Pi) |
| Default gateway | `192.168.1.1` |
| Repository | `https://github.com/trbouma/safebox.git` |
| Public URL | `https://safebox.example.com` |

Discover the host values rather than copying the examples:

```sh
freebsd-version
uname -m
zpool list
ifconfig
netstat -rn -f inet
```

All commands in the host sections run as `root` on the host. Commands prefixed
with `jexec safebox` run inside the jail.

## 1. Prepare the host

Enable jails at boot and create the standard ZFS hierarchy:

```sh
sysrc jail_enable=YES
sysrc jail_parallel_start=YES

zfs create -o mountpoint=/usr/local/jails zroot/jails
zfs create zroot/jails/media
zfs create zroot/jails/templates
zfs create zroot/jails/containers
```

If one or more datasets already exist, ZFS will report that fact; do not
destroy them. Confirm the resulting mount points:

```sh
zfs list -r zroot/jails
```

Make `/etc/jail.conf` include per-jail configuration files:

```text
.include "/etc/jail.conf.d/*.conf";
```

Create the directory if necessary:

```sh
mkdir -p /etc/jail.conf.d
```

## 2. Build a FreeBSD jail template

Set the release and architecture for the current shell. Use `arm64` for an
ARM64 Raspberry Pi and `amd64` for an x86-64 host.

```sh
setenv RELEASE 15.1-RELEASE
setenv ARCH arm64
```

Fetch and extract the base userland:

```sh
fetch "https://download.freebsd.org/ftp/releases/${ARCH}/${ARCH}/${RELEASE}/base.txz" \
  -o "/usr/local/jails/media/${RELEASE}-base.txz"

zfs create -p "zroot/jails/templates/${RELEASE}"
tar -xf "/usr/local/jails/media/${RELEASE}-base.txz" \
  -C "/usr/local/jails/templates/${RELEASE}" --unlink
```

Supply DNS and timezone data, then patch the template from the host:

```sh
cp /etc/resolv.conf "/usr/local/jails/templates/${RELEASE}/etc/resolv.conf"
cp /etc/localtime "/usr/local/jails/templates/${RELEASE}/etc/localtime"
freebsd-update -b "/usr/local/jails/templates/${RELEASE}" fetch install
```

Freeze the template and clone the SafeBox jail:

```sh
zfs snapshot "zroot/jails/templates/${RELEASE}@base"
zfs clone "zroot/jails/templates/${RELEASE}@base" \
  zroot/jails/containers/safebox
```

## 3. Configure and start the jail

Create `/etc/jail.conf.d/safebox.conf`, changing the interface and address:

```text
safebox {
    path = "/usr/local/jails/containers/${name}";
    host.hostname = "safebox";

    exec.clean;
    mount.devfs;
    persist;

    exec.start = "/bin/sh /etc/rc";
    exec.stop = "/bin/sh /etc/rc.shutdown";
    exec.consolelog = "/var/log/jail_console_${name}.log";

    interface = "em0";
    ip4.addr = "192.168.1.51";
}
```

Assign the jail address to the host interface at boot. Preserve any existing
aliases and substitute the real interface:

```sh
sysrc ifconfig_em0_alias0="inet 192.168.1.51/32"
```

Start and inspect the jail:

```sh
ifconfig em0 alias 192.168.1.51/32
service jail start safebox
jls
jexec safebox /bin/sh
```

Do not restart the host's primary network interface remotely just to add the
alias; that can terminate the administrative connection. The `ifconfig` command
adds it immediately, while the earlier `sysrc` setting restores it at boot.

Inside the jail, verify DNS and outbound connectivity before attempting a
build:

```sh
cat /etc/resolv.conf
ping -c 1 pkg.freebsd.org
pkg bootstrap -f
pkg update
```

If `pkg` cannot resolve names, recopy the host's `/etc/resolv.conf` to the jail
root. If it can resolve names but cannot connect, check the address, interface,
gateway, and host firewall before debugging Python.

## 4. Install the build toolchain inside the jail

Install the full native build set. `clang` is supplied by the FreeBSD base
system, while Rust is needed by packages such as `pydantic-core` and modern
`cryptography` releases.

```sh
jexec safebox pkg install -y \
  ca_root_nss git curl \
  python311 py311-pip py311-setuptools py311-wheel py311-sqlite3 \
  cmake ninja gmake pkgconf rust \
  openssl sqlite3 postgresql16-client libzmq4
```

Verify the tools before installing Python packages:

```sh
jexec safebox clang --version
jexec safebox cmake --version
jexec safebox ninja --version
jexec safebox rustc --version
jexec safebox python3.11 -c 'import sqlite3; print(sqlite3.sqlite_version)'
jexec safebox pg_config --version
```

On small ARM systems, give compilation several gigabytes of swap. A killed
`rustc`, `cc`, or `c++` process with no compiler diagnostic usually indicates
memory pressure, not bad source code. Check from the host with:

```sh
swapinfo -h
dmesg | tail -50
```

## 5. Install Open Quantum Safe (`liboqs`)

SafeBox's `liboqs-python` dependency is a Python wrapper around the native
`liboqs` shared library. These are two separate layers:

```text
SafeBox -> Python package `oqs` -> /usr/local/lib/liboqs.so
```

Install the C library first and verify that the runtime linker sees it. Only
then install the Python environment.

### Path A: FreeBSD packages (preferred)

First see what the configured repository provides:

```sh
jexec safebox pkg search -x 'liboqs|py311-liboqs-python'
```

When available, install both packages:

```sh
jexec safebox pkg install -y liboqs py311-liboqs-python
```

The Poetry virtual environment will still install its locked
`liboqs-python` dependency. The system Python binding is useful as an early
diagnostic; the important shared component is `/usr/local/lib/liboqs.so`.

Verify both layers:

```sh
jexec safebox sh -c 'pkg info liboqs && ls -l /usr/local/lib/liboqs.so*'
jexec safebox python3.11 -c 'import oqs; print(oqs.oqs_version())'
```

If the package is unavailable for the release/architecture, or if the C and
Python package versions are incompatible, use the source path below.

### Path B: Build `liboqs` from source

Do not build an unrecorded moving `main` branch for production. Select a
release tag compatible with the `liboqs-python` version in `poetry.lock`, and
record it in the deployment log. The following uses `0.14.0` as an example;
check the wrapper's compatibility before substituting a version.

```sh
jexec safebox sh -c 'cd /usr/local/src && \
  git clone --branch 0.14.0 --depth 1 \
  https://github.com/open-quantum-safe/liboqs.git'

jexec safebox sh -c 'cmake -S /usr/local/src/liboqs \
  -B /usr/local/src/liboqs/build \
  -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr/local \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_DIST_BUILD=ON \
  -DOQS_USE_OPENSSL=ON'

jexec safebox cmake --build /usr/local/src/liboqs/build --parallel 2
jexec safebox cmake --install /usr/local/src/liboqs/build
jexec safebox ldconfig -m /usr/local/lib
```

Why these flags matter:

- `BUILD_SHARED_LIBS=ON` creates the `.so` required by the Python wrapper.
- `OQS_DIST_BUILD=ON` produces a portable architecture build instead of
  assuming every optional CPU instruction is available.
- `OQS_BUILD_ONLY_LIB=ON` avoids building documentation and test utilities on
  constrained hardware.
- `--parallel 2` limits peak RAM use; reduce it to `1` on a Raspberry Pi 3.

Validate the installed library before continuing:

```sh
jexec safebox sh -c 'ls -l /usr/local/lib/liboqs.so*'
jexec safebox sh -c 'ldconfig -r | grep liboqs'
jexec safebox sh -c 'pkgconf --modversion liboqs || true'
```

After `liboqs-python` is installed in the application virtual environment,
validate a real KEM operation rather than only importing the module:

```sh
jexec -U safebox safebox /usr/local/safebox/.venv/bin/python -c \
  'import oqs; k=oqs.KeyEncapsulation("ML-KEM-512"); pub=k.generate_keypair(); print(oqs.oqs_version(), len(pub))'
```

If `import oqs` tries to download or compile `liboqs`, stop it and repair the
native library discovery. Confirm `liboqs.so` exists, run `ldconfig -m
/usr/local/lib`, and test `ldconfig -r | grep liboqs` from inside the jail.

## 6. Create the service account and install SafeBox

Create an unprivileged account and application directories:

```sh
jexec safebox pw groupadd safebox
jexec safebox pw useradd safebox -g safebox -d /home/safebox -m -s /bin/sh
jexec safebox install -d -o safebox -g safebox /usr/local/safebox
```

Clone the application. If the destination is already populated, clone into a
temporary directory and deploy deliberately instead of overwriting it.

```sh
jexec safebox git clone https://github.com/trbouma/safebox.git /usr/local/safebox
jexec safebox chown -R safebox:safebox /usr/local/safebox
jexec safebox install -d -o safebox -g safebox \
  /usr/local/safebox/data /usr/local/safebox/logs
```

Install Poetry for the service user and create an in-project environment:

```sh
jexec -U safebox safebox python3.11 -m pip install --user poetry
jexec -U safebox safebox sh -c \
  'cd /usr/local/safebox && \
   /home/safebox/.local/bin/poetry config virtualenvs.in-project true && \
   /home/safebox/.local/bin/poetry env use python3.11 && \
   /home/safebox/.local/bin/poetry install --only main'
```

On ARM hardware this can take an hour. In another host terminal, confirm that
the build is alive:

```sh
jexec safebox top -aSH
```

Processes named `rustc`, `cargo`, `clang`, `cc`, or `c++` consuming CPU are
normal. Do not repeatedly restart the install during native compilation.

Run a consolidated dependency check:

```sh
jexec -U safebox safebox sh -c \
  'cd /usr/local/safebox && .venv/bin/python -c \
  "import sqlite3, oqs, coincurve, psycopg2, zmq, uvloop; print(\"native dependencies: OK\")"'
```

## 7. Configure first startup

Create `/usr/local/safebox/.env` inside the jail. Do not copy production keys
into shell history.

```env
APP_ENV=production
DATABASE=sqlite:///data/database.db
PUBLIC_BASE_URL=https://safebox.example.com
COOKIE_SECURE=true
SECRET_BOOTSTRAP_MODE=false
```

Set restrictive ownership and permissions:

```sh
jexec safebox chown safebox:safebox /usr/local/safebox/.env
jexec safebox chmod 600 /usr/local/safebox/.env
```

SafeBox's guarded automatic bootstrap may create secrets only when its secret
store is truly empty. Partial secret state fails closed. Back up the resulting
`.env` and data immediately after a successful first start.

Test interactively before creating a service:

```sh
jexec -U safebox safebox sh -c \
  'cd /usr/local/safebox && \
   .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 7375'
```

From the host, test the jail address:

```sh
fetch -qo - http://192.168.1.51:7375/
```

Stop the foreground server with `Ctrl-C` after validation.

## 8. Install the jail's `rc.d` service

Create `/usr/local/jails/containers/safebox/usr/local/etc/rc.d/safebox` from
the host (or `/usr/local/etc/rc.d/safebox` from inside the jail):

```sh
#!/bin/sh
# PROVIDE: safebox
# REQUIRE: LOGIN NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="safebox"
rcvar="safebox_enable"

load_rc_config "$name"

: ${safebox_enable:="NO"}
: ${safebox_user:="safebox"}
: ${safebox_dir:="/usr/local/safebox"}
: ${safebox_bind:="0.0.0.0:7375"}

pidfile="/var/run/${name}.pid"
command="/usr/sbin/daemon"
command_args="-f -r -P ${pidfile} -u ${safebox_user} \
  -o /usr/local/safebox/logs/safebox.log \
  -e /usr/local/safebox/logs/safebox.err \
  /bin/sh -c 'cd ${safebox_dir} && exec .venv/bin/gunicorn app.main:app \
  --workers 2 --worker-class uvicorn.workers.UvicornWorker \
  --bind ${safebox_bind} --timeout 120'"

run_rc_command "$1"
```

Enable and start it inside the jail:

```sh
jexec safebox chmod 555 /usr/local/etc/rc.d/safebox
jexec safebox sysrc safebox_enable=YES
jexec safebox service safebox start
jexec safebox service safebox status
jexec safebox sockstat -4 -6 -l | grep 7375
```

Inspect failures in:

```sh
jexec safebox tail -100 /usr/local/safebox/logs/safebox.err
tail -100 /var/log/jail_console_safebox.log
```

The host reverse proxy should connect to `192.168.1.51:7375`. Keep TLS,
certificate renewal, Tailscale, and public firewall policy on the host unless
there is a specific reason to put them in this application jail.

## 9. Validate the finished deployment

Run these checks after every fresh build:

```sh
jls
jexec safebox freebsd-version
jexec safebox pkg check -d
jexec safebox service safebox status
jexec safebox sockstat -4 -6 -l
jexec -U safebox safebox /usr/local/safebox/.venv/bin/python -c \
  'import oqs; print(oqs.oqs_version(), "ML-KEM-512" in oqs.get_enabled_kem_mechanisms())'
fetch -qo - http://192.168.1.51:7375/
```

Also test an application workflow that exercises PQC. A successful homepage
does not prove that KEM key generation or encapsulation works.

## 10. Snapshots, upgrades, and rollback

Snapshot both code and mutable application state before an upgrade:

```sh
service jail stop safebox
zfs snapshot zroot/jails/containers/safebox@before-2026-07-upgrade
service jail start safebox
```

Then update as the service user:

```sh
jexec -U safebox safebox sh -c \
  'cd /usr/local/safebox && git pull --ff-only && \
   /home/safebox/.local/bin/poetry install --only main'
jexec safebox service safebox restart
```

If the upgrade fails, stop the jail before rollback:

```sh
service jail stop safebox
zfs rollback zroot/jails/containers/safebox@before-2026-07-upgrade
service jail start safebox
```

A snapshot is not an off-host backup. Replicate the dataset with `zfs send`,
and separately protect the service identity, `.env`, and database.

Patch a same-release jail from the host, not from inside the jail:

```sh
freebsd-update -j safebox fetch install
service jail restart safebox
```

The host must be upgraded before a jail is moved to a newer FreeBSD release.
For major upgrades, creating a new jail and migrating SafeBox is usually easier
to audit than upgrading the existing jail in place.

## VNET alternative

Use VNET when SafeBox needs its own network stack, routing table, or firewall.
It requires a host bridge and an `epair` pair. The FreeBSD Handbook's VNET jail
example should be adapted to the host interface and network; do not combine
its VNET stanza with the shared-stack `interface` and `ip4.addr` stanza above.

VNET is not required merely to give a jail a dedicated address. Start with the
shared-stack configuration unless the stronger network isolation is useful.

## Troubleshooting native builds

### `No module named '_sqlite3'`

```sh
pkg install -y py311-sqlite3
```

### `pg_config executable not found`

```sh
pkg install -y postgresql16-client
which pg_config
```

### ZeroMQ headers or library missing

```sh
pkg install -y libzmq4 pkgconf
pkgconf --libs libzmq
```

### Rust package fails during metadata or wheel build

```sh
rustc --version
cargo --version
swapinfo -h
```

Upgrade the FreeBSD Rust package, add swap, and retry with less parallelism.
Avoid mixing a root-owned Cargo cache with builds run by `safebox`.

### `liboqs.so` cannot be opened

```sh
ls -l /usr/local/lib/liboqs.so*
ldconfig -r | grep liboqs
ldconfig -m /usr/local/lib
```

Then test with the exact interpreter used by the service:

```sh
/usr/local/safebox/.venv/bin/python -c 'import oqs; print(oqs.oqs_version())'
```

### Illegal instruction on ARM

Rebuild `liboqs` with `-DOQS_DIST_BUILD=ON`. Make sure the jail architecture
matches the host and avoid copying an optimized `.so` from a different ARM CPU.

### Compiler process disappears on Raspberry Pi

Check `dmesg` and swap. Rebuild with one job:

```sh
cmake --build /usr/local/src/liboqs/build --parallel 1
```

### C library and Python wrapper versions differ

A warning may be harmless, but missing symbols or algorithms are not. Record:

```sh
pkg info liboqs
/usr/local/safebox/.venv/bin/python -c \
  'import importlib.metadata, oqs; print(importlib.metadata.version("liboqs-python"), oqs.oqs_version())'
```

Pin compatible releases and rebuild; do not hide the mismatch with a global
`LD_LIBRARY_PATH` in production.

## References

- [FreeBSD Handbook: Jails and Containers](https://docs.freebsd.org/en/books/handbook/jails/)
- [Open Quantum Safe: liboqs](https://github.com/open-quantum-safe/liboqs)
- [SafeBox native FreeBSD installation](../FREEBSD-INSTALL.md)
- [SafeBox FreeBSD appliance specification](SAFEBOX-FREEBSD-APPLIANCE-SPEC.md)
