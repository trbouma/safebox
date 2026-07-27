# Acorn Standalone Component

Acorn now has a first standalone package boundary under `packages/acorn`.
This allows other Python projects to install and experiment with the Acorn
runtime and CLI without installing the Safebox web application.

## Package

- Distribution name: `safebox-acorn`
- Python import: `acorn`
- CLI command: `acorn`
- Package root: `packages/acorn`

Install from this repository:

```sh
pip install "safebox-acorn @ git+https://github.com/trbouma/safebox.git@acorn-component#subdirectory=packages/acorn"
```

For local development:

```sh
cd packages/acorn
poetry install
poetry run acorn --help
```

## Current boundary

This first extraction intentionally leaves the Safebox web application unchanged.
The new component includes Acorn and the supporting helpers it currently needs:

- Nostr helpers
- Cashu and proof models
- Lightning helpers
- secp256k1 helpers
- OQS/NIP-44 extension helpers
- CLI prompts and configuration

This avoids destabilizing the Safebox web app while making Acorn installable
for other projects.

## Next migration step

Once the component is validated in another project, Safebox can be migrated to
consume `safebox-acorn` as a dependency instead of importing its in-tree Acorn
implementation directly.

The desired end state is:

- Acorn owns reusable wallet, record, Nostr, Cashu, and transmittal logic.
- Safebox owns web application concerns, database registration, sessions,
  templates, routes, and deployment-specific behavior.
- The public `Acorn` method surface remains stable while internal services are
  gradually split according to the modularization transition plan.
