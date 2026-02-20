# New Wallet Checklist

Use this checklist when creating a new Safebox wallet in a fresh database or after infrastructure changes.

## 1. Create Wallet

1. Create a new wallet using the normal onboarding flow (web invite flow or approved provisioning path).
2. Confirm login succeeds and the access page loads without warnings/errors.

## 2. Capture Critical Recovery Data

Record all of the following immediately:

1. Access key
2. Seed phrase
3. Home relay URL used by this wallet
4. Service/domain used for login (for operational traceability)

Recommended: store in an offline backup location and verify readability.

## 3. Confirm Wallet Initialization

1. Verify a non-error balance response in UI.
2. Verify CLI can load wallet state:
   - `acorn balance`
3. If CLI fails with missing wallet data, verify the configured home relay is correct.

## 4. Payments Smoke Test

Run low-value tests:

1. Request a payment (invoice generation)
2. Receive a payment
3. Send a payment
4. Confirm transaction history updates correctly

If NFC is enabled:

1. Issue NFC card
2. Test NFC send payment
3. Test NFC request payment
4. Confirm completion status appears in UI

## 5. Records Smoke Test

1. Create/store a simple note record
2. Offer a record by QR
3. Request/accept a record by QR
4. If using NFC record flows, test offer/request with card

## 6. Branding/Domain Check (If Enabled)

1. Verify top branding indicator shows expected:
   - branding message
   - request hostname/domain
2. If using host-specific branding files, verify fallback to `default.yml` behavior.

## 7. Restart and Persistence Check

1. Restart app/service.
2. Re-login with access key.
3. Confirm balance and records are still present.
4. Re-run one small payment test.

## 8. Migration State Check (Postgres/Alembic)

1. Confirm migration head:
   - `poetry run alembic current -v`
2. Ensure reported revision matches expected head before promoting environment.

## 9. Sign-off

Wallet is ready for normal use when all checks above pass with no critical errors.
