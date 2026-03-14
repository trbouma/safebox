# Secret Management Without Persistent `data/default.conf`

## Purpose

This note explains why persisting secrets into `data/default.conf` is not a good long-term deployment pattern, especially for Kubernetes, and proposes a safer target design with a phased migration plan.

This is a design and implementation review note. It is intentionally not a code-change document.

---

## Current Behavior

Today, Safebox uses `ConfigWithFallback` in `app/config.py` to resolve certain key material and runtime configuration values.

Current behavior includes:

- reading from environment variables first,
- reading from `data/default.conf` if values are not present in the environment,
- generating missing values in some cases,
- writing generated values back into `data/default.conf`.

Operationally, this means a persistent data volume can become the long-term storage location for sensitive runtime material.

Examples of sensitive values in this model include:

- `SERVICE_NSEC`
- related derived service identity values
- potentially other private key material or secret-bearing config fields

---

## Problem Statement

Persisting secrets into `data/default.conf` creates a deployment model where sensitive values are stored alongside application runtime data on a writable filesystem path.

That pattern may be acceptable for local bootstrap or throwaway evaluation environments, but it is not a good fit for hardened Docker or Kubernetes deployments.

The core problem is not only that secrets are written to disk. The deeper problem is that the system no longer has a clear and controlled secret source of truth.

---

## Why This Is Risky

### 1. Secrets Become Persistent Application State

When a secret is written into `data/default.conf`, it stops being a controlled runtime input and becomes durable application state.

Implications:

- secrets survive pod/container restart,
- secrets may be copied through backups and volume snapshots,
- secrets may remain present after operational context changes,
- operators may forget that the file has become authoritative.

### 2. Kubernetes Volumes Expand Exposure

In Kubernetes, persistent volumes are frequently:

- reused across pod replacement,
- backed by shared or network storage,
- included in backup and restore workflows,
- mounted in contexts broader than intended.

If secrets are stored in `data/default.conf`, then the persistent volume becomes an implicit secret store.

That increases exposure to:

- replacement pods,
- cluster operators,
- debugging sessions,
- backup processes,
- accidental copying or migration of application data.

### 3. Source Of Truth Becomes Ambiguous

If secrets can come from:

- environment variables,
- mounted secret files,
- generated runtime state written into `data/default.conf`,

then operators can no longer answer a basic question cleanly:

- what is the actual source of truth for this deployment?

This creates operational ambiguity during:

- incident response,
- key rotation,
- disaster recovery,
- environment promotion,
- debugging.

### 4. Runtime Generation Can Create Hidden Drift

If a missing secret is silently generated and then persisted:

- environments can drift without intent,
- replacements can behave differently than original deployments,
- secret provenance becomes unclear,
- recovery depends on filesystem state rather than declared deployment state.

### 5. Persistent Secret Storage Violates Least Persistence

Secret values should exist in the narrowest possible scope and for the shortest possible time consistent with system requirements.

Persisting them into `data/default.conf` violates that principle.

---

## Design Goal

The target design should be:

- secrets come from a dedicated secret source,
- secrets are not written back into application data volumes,
- non-secret config is kept separate from secret-bearing config,
- startup fails if required secrets are missing,
- deployments have one clear secret source of truth.

---

## Recommended Target Design

### A. Split Secret Material From Non-Secret Config

Non-secret config may still live in:

- normal config files,
- ConfigMaps,
- deployment manifests,
- app settings files.

Examples:

- relay lists,
- branding config,
- feature flags,
- currency CSV path,
- timeout values.

Secrets should not live there.

Examples of secrets:

- `SERVICE_NSEC`
- database passwords
- JWT signing keys
- mint/API credentials
- NWC private keys

### B. Use Kubernetes Secret As The Source Of Truth

For Kubernetes, the preferred pattern is:

- store secret values in Kubernetes `Secret` objects,
- inject them into the container as:
  - environment variables, or
  - mounted files under a secrets path such as `/run/secrets/...`.

This gives:

- explicit deployment ownership,
- clearer auditability,
- cleaner rotation paths,
- better separation from app data.

### C. Fail Closed On Missing Required Secrets

If a required secret is missing:

- the application should fail startup,
- the application should not generate a new secret and continue,
- the application should not write a replacement secret into `data/default.conf`.

This is especially important for:

- service signing keys,
- encryption keys,
- identity keys,
- private relay/messaging keys.

### D. Treat Persistent Volumes As Data Storage, Not Secret Storage

Persistent volumes should hold:

- user data,
- non-secret runtime state,
- databases where explicitly intended,
- caches when acceptable.

They should not become the fallback registry for deployment secrets.

---

## Deployment Options

### Option 1: Kubernetes Secret -> Environment Variables

The app reads secrets directly from env vars populated by a Kubernetes `Secret`.

Advantages:

- simplest operational model,
- very common deployment pattern,
- easy manifest wiring,
- clear secret ownership.

Tradeoffs:

- env vars are easier to expose accidentally in process-level debugging,
- rotation usually requires pod restart.

### Option 2: Kubernetes Secret -> Mounted Secret Files

The app reads secret files from a mounted path such as:

- `/run/secrets/service_nsec`
- `/run/secrets/db_password`

Advantages:

- avoids mixing secrets into generic config files,
- cleaner for multiline or file-oriented secrets,
- better file permission separation.

Tradeoffs:

- slightly more path-handling complexity in application config,
- still requires careful deployment discipline.

### Option 3: External Secret Manager

Examples:

- HashiCorp Vault
- AWS Secrets Manager
- GCP Secret Manager
- External Secrets Operator

Advantages:

- strongest long-term operational model,
- rotation support,
- centralized governance,
- clean audit surface.

Tradeoffs:

- more infrastructure complexity,
- more moving parts,
- usually unnecessary for local bootstrap.

---

## Recommended Safebox Policy

### Bootstrap / Local Evaluation

For local development or throwaway testing, the current bootstrap model may remain acceptable if convenience is the primary goal.

However, this should be treated as:

- local-only,
- non-production,
- explicitly convenience-oriented.

### Staging / Production

For staging or production:

- secrets should not be persisted into `data/default.conf`,
- Kubernetes `Secret` or an external secret manager should be authoritative,
- required secrets should be present before the app starts,
- startup should fail if required secret material is absent.

---

## Proposed Target Rules

1. `SERVICE_NSEC` must come from a dedicated secret source.
2. `SERVICE_NSEC` must not be written back into `data/default.conf`.
3. If `SERVICE_NSEC` is missing, startup must fail.
4. `data/default.conf` must be treated as:
   - non-secret config only, or
   - deprecated entirely.
5. Secret-bearing values must not be persisted onto volume-backed config paths in production.

---

## Migration Plan

### Phase 0: Inventory And Classification

Before changing behavior:

1. list all fields currently resolved through `ConfigWithFallback`
2. classify each field as:
   - required secret
   - optional secret
   - non-secret config
3. identify which of those are currently written to `data/default.conf`

Expected key targets:

- `SERVICE_NSEC`
- any service keypairs or secret-bearing fields that are generated on fallback

### Phase 1: Document Current Precedence Clearly

Before changing runtime behavior:

1. document current precedence:
   - env
   - file
   - generated fallback
2. document which environments are allowed to use generated fallback
3. define production policy explicitly:
   - generated fallback not allowed

This prevents migration confusion.

### Phase 2: Introduce Secret-Only Input Paths

Add support for a dedicated secret source:

- environment variable only, or
- secret-file path support such as:
  - `SERVICE_NSEC_FILE=/run/secrets/service_nsec`

Recommended precedence in the target model:

1. explicit env var
2. explicit secret file path
3. no fallback generation in production

This phase should not yet remove existing fallback behavior; it should introduce the new source cleanly first.

### Phase 3: Stop Writing Secrets To `data/default.conf`

Change runtime behavior so that:

- generated secret values are not written to `data/default.conf`
- or secret generation is disabled entirely outside bootstrap mode

At this point:

- local bootstrap may still allow temporary in-memory generation
- production must not persist secret-bearing values to the data volume

### Phase 4: Enforce Fail-Closed Startup In Hardened Environments

For staging/production:

1. require `SERVICE_NSEC` to be present from the chosen secret source
2. fail startup if not present
3. log a clear actionable startup error

This turns hidden drift into an explicit deployment failure, which is the correct behavior.

### Phase 5: Migrate Existing Deployments

For environments already using `data/default.conf` as a secret store:

1. extract the existing secret value(s)
2. create Kubernetes `Secret` objects from them
3. update deployment manifests to inject the secrets
4. deploy with both mechanisms temporarily if needed for transition
5. verify the app is reading from the new secret source
6. remove or scrub secret-bearing values from `data/default.conf`

Migration must preserve existing identity keys where continuity matters.

### Phase 6: Deprecate Secret-Bearing `default.conf`

After migration:

- treat `data/default.conf` as non-secret only
- or eliminate it entirely for production deployments

At that point, any secret still present there should be considered migration debt.

---

## Operational Review Questions

Before implementation, the following should be agreed:

1. Which secret source is preferred for production?
   - env vars
   - mounted secret files
   - external secret manager

2. Should bootstrap auto-generation remain for local-only mode?

3. Should `data/default.conf` remain as:
   - non-secret config only
   - or be removed entirely

4. Which existing deployments depend on persisted `SERVICE_NSEC` continuity?

5. What is the rotation and recovery process once secrets are no longer stored in the app data volume?

---

## Conclusion

Persisting secrets into `data/default.conf` is convenient, but it is not a strong deployment design for Kubernetes or other hardened environments.

The recommended direction is:

- dedicated secret source,
- no secret persistence into application data volumes,
- fail-closed startup when required secret material is absent,
- clear migration away from secret-bearing fallback files.

That gives Safebox a cleaner and more defensible secret-management posture without changing the underlying application responsibilities.
