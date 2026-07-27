# Safebox Acorn

Acorn is the reusable Nostr/Cashu wallet and records component extracted from
Safebox. It provides:

- the `Acorn` Python runtime class
- the `acorn` command-line interface
- supporting Nostr, Cashu, Lightning, record, and crypto helpers used by Acorn

This package is intended to make Acorn installable into other Python projects
without requiring the Safebox web application.

## Install from this repository

From another project:

```sh
pip install "safebox-acorn @ git+https://github.com/trbouma/safebox.git@acorn-component#subdirectory=packages/acorn"
```

For local development:

```sh
cd packages/acorn
poetry install
poetry run acorn --help
```

## Python usage

```python
from acorn import Acorn

wallet = Acorn(nsec="nsec...", home_relay="wss://relay.getsafebox.app")
```

## Notes

This is the first standalone packaging boundary. Safebox still contains its
current in-tree Acorn implementation while this component package is stabilized.
