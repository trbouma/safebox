# Kubernetes Secret Bootstrap And Promotion

## Purpose

This note describes a concrete Kubernetes bootstrap pattern for Safebox secret initialization and a promotion path from bootstrap runtime state to a hardened steady-state deployment.

The target is to keep the application-facing secret contract the same as Docker Compose:

- the app reads files from `/run/secrets/...`
- bootstrap mode may create or migrate those files once
- steady-state runtime reads them without generation

---

## Secret File Contract

The container expects these files:

- `/run/secrets/service_nsec`
- `/run/secrets/service_npub`
- `/run/secrets/nwc_nsec`
- `/run/secrets/pqc_sig_secret_key`
- `/run/secrets/pqc_sig_public_key`
- `/run/secrets/pqc_kem_secret_key`
- `/run/secrets/pqc_kem_public_key`

These are configured through the corresponding `*_FILE` environment variables.

---

## Bootstrap Strategy

Use Kubernetes in two phases:

1. bootstrap phase
2. steady-state phase

### Bootstrap Phase

Use a single-replica deployment with:

- `SECRET_BOOTSTRAP_MODE=true`
- a writable volume mounted at `/run/secrets`
- one app replica
- preferably one gunicorn worker

The purpose of this phase is:

- initialize missing secret files into the mounted secret path, or
- migrate legacy `data/default.conf` values into the mounted secret path

This phase is intentionally temporary.

### Steady-State Phase

After bootstrap succeeds:

- set `SECRET_BOOTSTRAP_MODE=false`
- use the secret files as the source of truth
- scale replicas and worker count to normal operating levels
- fail startup if secret files are missing

---

## Recommended Promotion Model

The recommended long-term Kubernetes model is:

1. bootstrap to a writable volume
2. copy the generated files into a Kubernetes `Secret`
3. mount the Kubernetes `Secret` read-only at `/run/secrets`
4. run the steady-state deployment with `SECRET_BOOTSTRAP_MODE=false`

This gives a good balance between:

- operational simplicity during bootstrap
- hardened secret handling in steady state

---

## Bootstrap Deployment Pattern

### Option A: PVC-backed bootstrap

This is the simplest initial pattern.

Use:

- a `PersistentVolumeClaim`
- mounted at `/run/secrets`
- writable by the container

Example manifest pattern:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: safebox-bootstrap-secrets
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: safebox-bootstrap
spec:
  replicas: 1
  selector:
    matchLabels:
      app: safebox-bootstrap
  template:
    metadata:
      labels:
        app: safebox-bootstrap
    spec:
      containers:
        - name: safebox
          image: safebox/safebox:release-candidate
          env:
            - name: TZ
              value: America/New_York
            - name: CURRENCY_CSV
              value: /app/setup/currency.csv
            - name: SECRET_BOOTSTRAP_MODE
              value: "true"
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
          command:
            - gunicorn
            - app.main:app
            - --workers
            - "1"
            - --worker-class
            - uvicorn.workers.UvicornWorker
            - --bind
            - 0.0.0.0:7375
            - --timeout
            - "120"
          volumeMounts:
            - name: bootstrap-secrets
              mountPath: /run/secrets
      volumes:
        - name: bootstrap-secrets
          persistentVolumeClaim:
            claimName: safebox-bootstrap-secrets
```

Expected result:

- the pod starts once
- the secret files appear in the mounted volume
- no further secret generation should be needed in steady state

### Why only one replica

Bootstrap writes secret material. That should not happen concurrently.

Do not bootstrap with:

- multiple replicas
- multiple pods sharing the same writable secret volume

---

## Promotion To Kubernetes Secret

After bootstrap succeeds, create a Kubernetes `Secret` from the generated files.

Example pattern:

```bash
kubectl create secret generic safebox-runtime-secrets \
  --from-file=service_nsec=/path/to/service_nsec \
  --from-file=service_npub=/path/to/service_npub \
  --from-file=nwc_nsec=/path/to/nwc_nsec \
  --from-file=pqc_sig_secret_key=/path/to/pqc_sig_secret_key \
  --from-file=pqc_sig_public_key=/path/to/pqc_sig_public_key \
  --from-file=pqc_kem_secret_key=/path/to/pqc_kem_secret_key \
  --from-file=pqc_kem_public_key=/path/to/pqc_kem_public_key
```

The exact source path depends on how you extract the files from the bootstrap volume.

---

## Steady-State Deployment Pattern

Once the Kubernetes `Secret` exists, switch to a steady-state deployment that mounts it read-only.

Example manifest pattern:

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
        - name: safebox
          image: safebox/safebox:release-candidate
          env:
            - name: TZ
              value: America/New_York
            - name: CURRENCY_CSV
              value: /app/setup/currency.csv
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
          command:
            - gunicorn
            - app.main:app
            - --workers
            - "4"
            - --worker-class
            - uvicorn.workers.UvicornWorker
            - --bind
            - 0.0.0.0:7375
            - --timeout
            - "120"
          volumeMounts:
            - name: runtime-secrets
              mountPath: /run/secrets
              readOnly: true
      volumes:
        - name: runtime-secrets
          secret:
            secretName: safebox-runtime-secrets
```

Expected result:

- no secret generation
- no migration
- startup fails if the secret set is incomplete

---

## Compose-To-Kubernetes Promotion Workflow

This is the practical workflow if Compose bootstrap has already been used successfully.

### Step 1: Bootstrap Locally With Compose

Use the bootstrap-oriented `docker-compose.yaml`:

- `SECRET_BOOTSTRAP_MODE=true`
- `./secrets:/run/secrets`
- single worker

Expected result:

- local `./secrets` directory is populated

### Step 2: Treat `./secrets` As The Bootstrap Output

The files in `./secrets` become the initial authoritative secret set for the first Kubernetes deployment.

These should include:

- `service_nsec`
- `service_npub`
- `nwc_nsec`
- `pqc_sig_secret_key`
- `pqc_sig_public_key`
- `pqc_kem_secret_key`
- `pqc_kem_public_key`

### Step 3: Create A Kubernetes `Secret`

Create a Kubernetes `Secret` from those files.

### Step 4: Deploy Bootstrap Or Go Directly To Steady State

If the secret set is already trusted:

- skip Kubernetes bootstrap generation
- deploy directly with:
  - `SECRET_BOOTSTRAP_MODE=false`
  - secret mounted read-only at `/run/secrets`

If you still need in-cluster bootstrap:

- use the bootstrap deployment pattern first
- then promote to the mounted Kubernetes `Secret`

### Step 5: Run Hardened Steady State

Final deployment posture:

- `SECRET_BOOTSTRAP_MODE=false`
- mounted secret files at `/run/secrets`
- normal replica count
- normal worker count

---

## Operational Checks

Before promoting from bootstrap to steady state, verify:

1. all required secret files exist
2. the app starts successfully with bootstrap mode disabled
3. `data/default.conf` is not recreated
4. secret source of truth is clear and documented
5. secret rotation procedure is defined

---

## What Not To Do

- do not leave bootstrap mode enabled in steady-state Kubernetes
- do not bootstrap with multiple replicas
- do not rely on `data/default.conf` as the long-term secret store
- do not make the application mutate Kubernetes `Secret` objects directly

---

## Summary

The Kubernetes bootstrap model should mirror the Compose secret-file contract, but with a deliberate promotion step.

Bootstrap:

- writable `/run/secrets`
- single replica
- `SECRET_BOOTSTRAP_MODE=true`

Steady state:

- mounted Kubernetes `Secret` at `/run/secrets`
- `SECRET_BOOTSTRAP_MODE=false`
- normal scaling and worker settings

That preserves one application secret interface across both Compose and Kubernetes while still giving Kubernetes a hardened final state.
