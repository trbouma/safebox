# Acorn and Safebox Separation Plan

## Summary

Acorn is being separated from Safebox so it can become an independently
installable component while Safebox remains the working web product. The
separation must be staged carefully: the existing Safebox application should
not lose working wallet, payment, record, or deployment behavior while Acorn is
being hardened as its own package.

The standalone component lives at:

- <https://github.com/trbouma/safebox-acorn>

## Current state

Safebox currently contains the known-good Acorn implementation in-tree under
`safebox/`. That implementation powers the CLI, wallet operations, Cashu proof
flows, Lightning payments, Nostr record handling, secure transmittals, and web
application routes.

A new standalone package, `safebox-acorn`, has been created from that code and
validated as an independently installable Python package. The initial standalone
validation has confirmed:

- `from acorn import Acorn` works from a fresh virtual environment.
- The `acorn` CLI entry point installs and loads.
- A real payment has been completed through the standalone package.

This is enough to treat `safebox-acorn` as a real component boundary, but not
yet enough to remove the in-tree Safebox implementation.

## Separation principle

Do not remove working Acorn code from Safebox until the external package has
been proven against Safebox itself.

Temporary duplication is acceptable. It protects the existing Safebox product
while the new component package stabilizes. The goal is controlled extraction,
not a disruptive rewrite.

## Ownership boundary

### `safebox-acorn` owns

- the `Acorn` runtime class
- the `acorn` CLI
- Nostr wallet and event logic
- Cashu mint/proof lifecycle
- Lightning payment helpers
- encrypted record storage/retrieval
- secure transmittal primitives
- crypto helpers, including secp256k1 and OQS/NIP-44 extensions
- reusable models needed by the Acorn runtime

### Safebox owns

- FastAPI application startup and routing
- web templates and user interaction flows
- browser sessions, cookies, CSRF, and authentication behavior
- Safebox registration database and migrations
- branding, host resolution, and deployment-specific configuration
- operator/deployment documentation
- FreeBSD jail/appliance/service packaging
- product-level integrations that compose Acorn with web UX

## Migration phases

### Phase 0: Preserve the known-good product

Keep `safebox/acorn.py` and related in-tree modules in place. Do not change
Safebox production behavior while validating the standalone package.

Recommended guardrails:

- keep the current Safebox branch deployable;
- maintain the FreeBSD jail deployment path;
- keep payment and record flows smoke-tested;
- avoid broad import rewrites until the standalone Acorn package is tagged.

### Phase 1: Stabilize `safebox-acorn`

Harden the standalone package in its own repository.

Minimum targets:

- fresh virtual environment install works;
- `acorn --help` works;
- `from acorn import Acorn` works;
- wallet initialization works;
- at least one payment flow works;
- key record operations work;
- known OQS version warnings are documented;
- README includes install and smoke-test instructions;
- initial version tag exists, for example `v0.1.0`.

### Phase 2: Add an external dependency branch in Safebox

Create a Safebox branch such as:

```text
use-external-acorn
```

On that branch, add `safebox-acorn` as a dependency, preferably pinned to a tag
or commit:

```toml
safebox-acorn = { git = "https://github.com/trbouma/safebox-acorn.git", tag = "v0.1.0" }
```

Then begin replacing imports gradually:

```python
from safebox.acorn import Acorn
```

becomes:

```python
from acorn import Acorn
```

Do not remove the in-tree implementation during the first import-replacement
pass. Keeping it available makes rollback simple.

### Phase 3: Compatibility layer

If Safebox still needs old import paths during transition, add a thin
compatibility module:

```python
# safebox/acorn_compat.py
from acorn import Acorn
```

or, if necessary during migration:

```python
try:
    from acorn import Acorn
except ImportError:
    from safebox.acorn import Acorn
```

The fallback pattern is useful during transition but should not become the final
architecture. The final dependency direction should be:

```text
Safebox -> safebox-acorn
```

not:

```text
safebox-acorn -> Safebox
```

### Phase 4: Replace supporting imports

Safebox also imports supporting types and helpers that currently live under
`safebox.*`, such as models, record helpers, and crypto helpers. These should be
migrated only after the `Acorn` class import is working.

For each supporting import, decide whether it belongs to:

- `safebox-acorn`, if it is part of reusable wallet/record/payment behavior; or
- Safebox, if it is web-app, database, session, or deployment specific.

This phase should be done file-by-file with targeted smoke tests.

### Phase 5: Deprecate in-tree Acorn

Only after Safebox works reliably against the external package:

- mark the in-tree Acorn implementation as deprecated;
- remove direct app imports from `safebox.acorn`;
- keep a temporary compatibility shim if needed;
- document the minimum `safebox-acorn` version Safebox requires.

### Phase 6: Remove duplicated code

After a stable release cycle using the external package, remove duplicated
Acorn runtime code from Safebox.

Do not remove protocol compatibility names, event tags, record shapes, or
well-known endpoint behavior merely because they contain the word `safebox`.
Those may be externally visible compatibility surfaces.

## Rollback strategy

Rollback must remain simple at every phase:

- Safebox mainline remains deployable with the in-tree implementation.
- The external dependency migration happens on a branch first.
- Version pins or commit pins are used instead of floating dependency heads.
- The in-tree implementation remains available until external Acorn has passed
  app-level smoke tests.

If a regression appears, revert the import-replacement branch or switch imports
back to the in-tree implementation.

## Testing checklist

Before Safebox depends on external Acorn:

- `safebox-acorn` installs in a fresh virtual environment.
- `acorn --help` works.
- `from acorn import Acorn` works.
- payment smoke test works.
- record put/get smoke test works.
- OQS warning behavior is understood and documented.

Before removing in-tree Acorn from Safebox:

- Safebox app boots.
- login/registration flow works.
- balance loads.
- payment flow works.
- token issue/accept flow works.
- record put/get/delete flow works.
- secure transmittal flow works.
- NFC/QR-adjacent flows still pass current smoke tests.
- FreeBSD jail install path still works.

## Open questions

- Should `safebox-acorn` publish to PyPI, or remain installed from Git tags?
- Which models should be renamed from `Safebox*` to `Acorn*`, and which must
  remain stable for protocol compatibility?
- Should `safebox-acorn` provide separate optional dependency groups for OQS,
  CLI, and payment features?
- Should the Acorn CLI remain broad, or should some commands move back to
  Safebox when they are product-specific?

## Related documents

- [Acorn Standalone Component](./ACORN-STANDALONE-COMPONENT.md)
- [Acorn Modularization Transition Plan](./ACORN-MODULARIZATION-TRANSITION-PLAN.md)
- [Acorn Resiliency and Guards](./ACORN-RESILIENCY-AND-GUARDS.md)
