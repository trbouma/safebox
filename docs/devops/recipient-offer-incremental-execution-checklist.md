# Recipient-Offer Incremental Execution Checklist

## Purpose
Use this checklist to advance recipient-first offer flows without regressing stable QR/NFC payment and record paths.

## 0) Baseline Freeze

- Confirm clean tree: `git status --short`
- Create a safety tag or branch for known-good state.
- Record current commit hash in test notes.

## 1) Full Regression First (Mandatory)

Run and log pass/fail for:

- Offer by QR code
- Offer by NFC
- Request record by QR code
- Request record by NFC
- POS invoice flow (create, pay, completion status)
- POS NFC payment flow
- Access-page NFC pay-to-tag flow

Logging guidance:

- Capture first failing step only.
- Save 20-50 relevant backend log lines per failure.
- Include browser status text shown to user.

## 2) Execution Rules (Incremental Discipline)

- One slice per commit.
- No unrelated cleanup in the same commit.
- Preserve existing working path as default behavior.
- If a slice fails, revert that slice before proceeding.

## 3) Slice Plan (Apply In Order)

### Slice A: Recipient Offer Request Bootstrap

- Agent/API creates `offer_request` `nauth` with nonce.
- No delivery/transmit changes yet.
- Success criteria: QR renders, scanner can read payload.

### Slice B: Scanner Return Routing

- Scanner returns to exact originating offer page/context.
- Success criteria: return URL preserves selected offer state.

### Slice C: Transmit Using Existing Path

- Offer page transmit button uses existing `/records/transmit` behavior.
- No alternate send pipeline.
- Success criteria: grant appears in recipient flow exactly as legacy path.

### Slice D: Recipient Listener Status

- Add background listener/status for recipient side.
- Expose clear state transitions (created, scanned, waiting, received, timeout).
- Success criteria: no silent hangs; deterministic timeout.

### Slice E: Agent Grant Retrieval

- Agent can list/read grants needed to complete recipient-first loop.
- Success criteria: end-to-end recipient-first flow completes with existing grant consumption logic.

## 4) Guardrails

- Always validate nonce correlation before accepting handshake continuation.
- Require explicit fallback when relay/kind values are missing.
- Keep record-flow defaults aligned:
  - `RECORD_TRANSMITTAL_KIND`
  - `RECORD_TRANSMITTAL_RELAYS`
- Do not change `nauth` schema during these slices.

## 5) Observability Requirements

Per flow, log:

- `flow_id` (short id) and nonce prefix
- state transition marker
- relay/kind used for auth and transmittal
- terminal outcome (`success`, `timeout`, `cancelled`, `error`)

Do not log sensitive payload contents.

## 6) Rollback Criteria

Rollback immediately if any of these regress:

- QR offer/request flow
- NFC request-record flow
- POS completion signaling
- payment proof/balance integrity

Rollback method:

- Revert only latest slice commit.
- Re-run impacted regression subset.
- Continue only after clean pass.

## 7) Daily Closeout

- Summarize slices attempted, completed, reverted.
- Capture open defects with exact failing step and log excerpt.
- Leave branch in a runnable state with clear next action.
