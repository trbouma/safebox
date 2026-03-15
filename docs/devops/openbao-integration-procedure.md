# OpenBao Integration Procedure

## Purpose

This note describes how to integrate Safebox with OpenBao while preserving the existing application secret-file contract.

The recommended design goal is:

- Safebox remains unaware of OpenBao-specific APIs,
- Safebox continues to read secrets from `/run/secrets/...`,
- OpenBao becomes the upstream source of truth for secret material in steady state.

This keeps the application contract stable across:

- Docker Compose,
- Kubernetes,
- Kubernetes with OpenBao-backed secret management.

---

## Recommended Integration Model

The preferred OpenBao model for Safebox is:

1. OpenBao stores the authoritative secret values
2. an OpenBao integration layer renders those secrets into files
3. those files appear inside the Safebox container at `/run/secrets/...`
4. Safebox reads them through the existing `*_FILE` settings
5. `SECRET_BOOTSTRAP_MODE` remains `false` in steady state

This is the cleanest model because Safebox does not need:

- direct OpenBao API access,
- OpenBao authentication logic,
- custom startup code for secret retrieval.

---

## Safebox Secret File Contract

Safebox expects the following files:

- `/run/secrets/service_nsec`
- `/run/secrets/service_npub`
- `/run/secrets/nwc_nsec`
- `/run/secrets/pqc_sig_secret_key`
- `/run/secrets/pqc_sig_public_key`
- `/run/secrets/pqc_kem_secret_key`
- `/run/secrets/pqc_kem_public_key`

These correspond to:

- `SERVICE_NSEC_FILE`
- `SERVICE_NPUB_FILE`
- `NWC_NSEC_FILE`
- `PQC_SIG_SECRET_KEY_FILE`
- `PQC_SIG_PUBLIC_KEY_FILE`
- `PQC_KEM_SECRET_KEY_FILE`
- `PQC_KEM_PUBLIC_KEY_FILE`

As long as OpenBao integration produces those files in the expected location, Safebox does not care how they were sourced.

---

## Recommended OpenBao Patterns

### Pattern A: OpenBao Agent Sidecar Rendering Files

This is the preferred approach.

Use:

- an OpenBao agent sidecar,
- a shared volume mounted at `/run/secrets`,
- templates or file rendering to write the expected secret files.

Why this is preferred:

- it matches Safebox’s current file-based contract exactly,
- it keeps OpenBao authentication and lease handling outside the app,
- it allows rotation workflows without modifying application logic,
- it keeps the runtime contract the same as Docker Compose and Kubernetes native secret mounts.

### Pattern B: External Secret Sync To Kubernetes `Secret`

Alternative approach:

- OpenBao is still the upstream source of truth,
- an operator/controller syncs values into a Kubernetes `Secret`,
- Safebox mounts that Kubernetes `Secret` at `/run/secrets`.

This is acceptable, but it materializes the secret set into native Kubernetes `Secret` objects.

That may be fine operationally, but it is one step further from OpenBao being the only storage authority.

### Pattern C: Safebox Calls OpenBao Directly

This is not recommended.

Reasons:

- adds OpenBao-specific client logic into the app,
- complicates startup and failure handling,
- makes local parity harder,
- couples app initialization to networked secret retrieval.

The app should keep reading local files and let the platform handle how those files are produced.

---

## Bootstrap And Promotion Strategy

The recommended OpenBao rollout uses two phases:

1. bootstrap or migration phase
2. steady-state OpenBao-backed runtime

### Phase 1: Bootstrap Or Migrate Secrets

You need an initial source of truth for the secret set.

Options:

- bootstrap using Docker Compose and the mounted `./secrets` directory,
- bootstrap in Kubernetes using a writable `/run/secrets` volume,
- migrate an existing `data/default.conf` into the new secret-file set,
- import already-known values manually.

At the end of this phase, you should have the full secret file set:

- `service_nsec`
- `service_npub`
- `nwc_nsec`
- `pqc_sig_secret_key`
- `pqc_sig_public_key`
- `pqc_kem_secret_key`
- `pqc_kem_public_key`

### Phase 2: Load Secrets Into OpenBao

Once the initial secret file set exists, load those values into OpenBao as the authoritative store.

Conceptually, this means:

- one OpenBao path per deployment/environment,
- access scoped to the Safebox workload identity,
- separation between staging and production secret material.

### Phase 3: Render Secrets Back Into `/run/secrets`

Deploy the OpenBao integration layer so that the OpenBao-held values are rendered to:

- `/run/secrets/service_nsec`
- `/run/secrets/service_npub`
- etc.

Now Safebox reads exactly the same file contract, but OpenBao is upstream.

### Phase 4: Disable Bootstrap

In the final deployment:

- set `SECRET_BOOTSTRAP_MODE=false`
- ensure the `/run/secrets` files are present before the app starts
- fail startup if the secret set is incomplete

That is the hardened steady-state model.

---

## Kubernetes Sidecar Procedure

This is the recommended concrete pattern.

### 1. Create A Shared Secret Volume

Use a shared in-pod volume such as:

- `emptyDir`, or
- another writable ephemeral volume

This volume is mounted:

- writable by the OpenBao agent sidecar,
- readable by the Safebox container.

### 2. Configure The OpenBao Agent

The OpenBao agent should:

- authenticate using the workload’s chosen auth method,
- read the Safebox secret values from the configured OpenBao path,
- render each required value into a file in the shared `/run/secrets` volume.

### 3. Configure Safebox

Safebox should be configured with:

- `SECRET_BOOTSTRAP_MODE=false`
- the `*_FILE` paths pointing at `/run/secrets/...`

### 4. Start Order

The safest operational assumption is:

- the OpenBao-rendered files must exist before Safebox is treated as ready

That may require:

- startup ordering,
- readiness probes,
- or agent template completion before app readiness.

---

## Example Pod Pattern

The following is an abstract example of the pod shape.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: safebox
spec:
  replicas: 2
  selector:
    matchLabels:
      app: safebox
  template:
    metadata:
      labels:
        app: safebox
    spec:
      containers:
        - name: openbao-agent
          image: openbao/agent:latest
          volumeMounts:
            - name: rendered-secrets
              mountPath: /run/secrets
        - name: safebox
          image: safebox/safebox:release-candidate
          env:
            - name: SECRET_BOOTSTRAP_MODE
              value: "false"
            - name: SERVICE_NSEC_FILE
              value: /run/secrets/service_nsec
            - name: SERVICE_NPUB_FILE
              value: /run/secrets/service_npub
            - name: NWC_NSEC_FILE
              value: /run/secrets/nwc_nsec
            - name: PQC_SIG_SECRET_KEY_FILE
              value: /run/secrets/pqc_sig_secret_key
            - name: PQC_SIG_PUBLIC_KEY_FILE
              value: /run/secrets/pqc_sig_public_key
            - name: PQC_KEM_SECRET_KEY_FILE
              value: /run/secrets/pqc_kem_secret_key
            - name: PQC_KEM_PUBLIC_KEY_FILE
              value: /run/secrets/pqc_kem_public_key
          volumeMounts:
            - name: rendered-secrets
              mountPath: /run/secrets
              readOnly: true
      volumes:
        - name: rendered-secrets
          emptyDir: {}
```

This example does not define OpenBao auth or templating details. Those should be supplied according to the cluster’s OpenBao setup.

---

## Recommended Operational Procedure

### Initial Adoption

1. bootstrap the Safebox secret files outside OpenBao
2. verify the secret set is complete
3. load those values into OpenBao
4. deploy OpenBao rendering into `/run/secrets`
5. deploy Safebox with `SECRET_BOOTSTRAP_MODE=false`

### Verification

Verify:

1. all expected files exist under `/run/secrets`
2. Safebox starts without generating or migrating secrets
3. `data/default.conf` is not recreated
4. the app fails closed if the OpenBao-rendered files are missing

### Rotation

For long-lived root identity secrets:

- do not rotate casually,
- define a formal service identity rotation procedure,
- validate downstream compatibility before rotation.

OpenBao helps with:

- auditability,
- controlled access,
- formal rotation workflows,
- revocation and operational traceability.

---

## What Not To Do

- do not leave `SECRET_BOOTSTRAP_MODE=true` in an OpenBao-backed steady-state deployment
- do not make Safebox call OpenBao directly at startup unless there is a very strong reason
- do not mix OpenBao-backed secrets with `data/default.conf` as concurrent sources of truth
- do not allow multiple bootstrap writers to initialize the same root secret set concurrently

---

## Summary

The correct OpenBao integration for Safebox is to keep the application contract unchanged and change only the secret source behind it.

Recommended final model:

- OpenBao stores the authoritative secret values
- an agent or integration layer renders them into `/run/secrets`
- Safebox reads them via `*_FILE`
- `SECRET_BOOTSTRAP_MODE=false`

That gives:

- a stable application interface,
- compatibility with existing Compose and Kubernetes secret-file handling,
- a clean path from bootstrap convenience to hardened secret management.
