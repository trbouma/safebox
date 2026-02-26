# Blossom Xfer Rollout Checklist

## Purpose

Deploy and validate a dedicated transfer Blossom server (`BLOSSOM_XFER_SERVER`) while preserving stable record and payment behavior.

## Target Configuration

- `BLOSSOM_HOME_SERVER`: durable wallet blob server (for example `https://blossom.getsafebox.app`)
- `BLOSSOM_XFER_SERVER`: dedicated transfer server (for example `https://blossomx.getsafebox.app`)
- `BLOSSOM_XFER_SERVER` should not equal `BLOSSOM_HOME_SERVER` in production.

## 1) Pre-Deploy Checks

- Confirm DNS and TLS are valid for xfer host.
- Confirm xfer server supports upload and read.
- If xfer `DELETE` is not implemented/authorized, accept this temporarily; Safebox handles delete non-fatally.
- Confirm app env vars are set on deployment target.

## 2) Deploy Steps

- Deploy app with updated env:
  - `BLOSSOM_HOME_SERVER=...`
  - `BLOSSOM_XFER_SERVER=...`
- Restart app workers/containers.
- Confirm startup logs do not show accidental same-server warning unless intentionally testing.

## 3) Functional Verification (Same Instance)

- Offer by QR with original image/pdf:
  - receive and render payload
  - verify original blob is available when source exists.
- Offer by NFC with original image/pdf:
  - verify no post-tap stall
  - verify original blob retrieval succeeds.
- Request by QR and NFC:
  - verify completion and record rendering.

## 4) Cross-Instance Verification (Required)

- A -> B and B -> A for:
  - Offer by QR
  - Offer by NFC
  - Request by QR
  - Request by NFC
- Validate:
  - payload is actual record content (not placeholder text)
  - original blob behavior is consistent across instances
  - no KEM downgrade behavior.

## 5) Failure-Mode Verification

- Temporarily make transfer blob unavailable on xfer server:
  - flow should continue non-fatally
  - expect warning/status that original record is unavailable
  - no worker crash.
- If xfer delete is unauthorized:
  - retrieval should still succeed
  - expect warning log only (non-fatal).

## 6) Log Signals To Watch

- `op=transfer_blob status=uploaded`
- `op=transfer_blob status=not_available ... reason=original_record_not_available`
- `op=get_original_blob status=delete_failed ...` (acceptable in current xfer policy)
- No repeated websocket timeout/loop errors in request/offer flows.

## 7) Operational Policy

- Treat xfer storage as ephemeral.
- Use manual or TTL-based purge on the dedicated xfer server.
- Do not apply blind age-based purge on durable home server.

## Exit Criteria

- All QR/NFC offer and request flows pass both directions across instances.
- Original blob retrieval works or degrades gracefully with explicit warning.
- No critical ASGI exceptions from blob transfer/retrieval paths.
