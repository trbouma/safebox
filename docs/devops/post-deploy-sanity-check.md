# Post-Deploy Sanity Check

## Purpose

Quick user-facing verification after deployment to confirm critical NFC/QR/payment/record flows are operational.

## 1) Basic Health

- Load `/` and log in.
- Open access page and confirm balance loads.
- Confirm no immediate startup/websocket errors in service logs.

## 2) Offer Flows

- Offer by QR:
  - Generate QR.
  - Accept from second wallet/device.
  - Verify offer is received.
- Offer by NFC:
  - Tap card.
  - Complete flow and verify offer is received.

## 3) Request Flows (Critical)

- Request by QR:
  - Generate QR.
  - Present from second wallet/device.
  - Verify completion.
  - Refresh QR and repeat to confirm no nonce mismatch failure.
- Request by NFC:
  - Start request.
  - Tap card and complete flow.
  - Verify it does not hang.
  - If multiple records match, verify multiple records are returned.

## 4) NFC Payments

- Pay to NFC tag from access page:
  - Verify completion indicator appears.
  - Verify balance updates.
- Request payment from NFC card:
  - Verify terminal success/failure status appears.
- Insufficient-balance test:
  - Verify user-friendly failure without leaking available balance.

## 5) POS Checks

- Create invoice (QR) and pay from another wallet.
- Verify status progression: pending -> processing -> complete.
- Pay by NFC at POS and verify completion status updates.
- Verify UI layout remains stable (no right-side bleed).

## 6) Card Lifecycle / Security

- Rotate NFC secret.
- Test old card:
  - Must fail quickly as invalid/rotated.
- Issue new card and verify NFC login/payment/request all work.

## 7) Public Balance Page

- Open `/public/mybalance`.
- Scan valid local card and verify balance is shown.
- Scan invalid/foreign card and verify fast, user-friendly failure.

## 8) Logs and Runtime Checks

- Monitor logs for:
  - `ws_request_record`
  - `listen_for_record_sub`
  - `listen_for_request`
- Confirm no repeated nonce mismatch, parse-error loops, or timeout loops.
- Confirm no worker boot/restart crashes.
- Confirm DB migration/startup is clean.

## 9) Cross-Instance Verification (Required)

Use two independent Safebox instances (for example instance A and instance B).

- Offer by QR (A -> B and B -> A):
  - Verify received payload is actual record content (not placeholder text).
- Offer by NFC (A -> B and B -> A):
  - Verify received payload is actual record content (not placeholder text).
  - Verify no silent KEM fallback behavior.
- Request by QR (A -> B and B -> A):
  - Verify presenter response completes and records render.
- Request by NFC (A -> B and B -> A):
  - Verify no hang at post-tap stage.
  - Verify records render correctly (plain text + signed event payloads).

Expected KEM behavior:

- If peer KEM is present/valid, flow completes quantum-safe.
- If peer KEM is missing/invalid, flow must fail/re-authenticate (not silently continue with local-default KEM).

## Exit Criteria

- QR and NFC offer flows pass.
- QR and NFC request flows pass reliably.
- NFC payment flows complete with correct status updates.
- No recurring critical runtime errors in logs.
