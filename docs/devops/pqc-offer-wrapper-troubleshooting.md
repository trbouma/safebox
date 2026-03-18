# PQC Offer Wrapper Troubleshooting

## Symptom

During QR/NFC or cross-instance record offer flows, the receiving side shows:

- `This record is quantum-safe`

instead of the actual offered record content.

This can appear in:

- the receiving inbox,
- the incoming-record acceptance path,
- stored accepted records after inbox acceptance.

## Meaning

This string is not the actual record payload. It is a transport wrapper marker used by the PQC delivery path.

When this marker appears on the receiving side, the usual interpretation is:

1. the sender successfully wrapped the real payload,
2. the receiver got the wrapped record,
3. the receiver did not successfully decrypt `pqc_encrypted_payload`.

So this symptom usually indicates a recipient-side secret/config problem, not a sender-side share failure.

## Most Likely Cause

The most common cause observed in local/dev environments is:

- stale or inconsistent PQC/KEM secret material

Examples:

- `pqc_kem_secret_key`
- `pqc_kem_public_key`
- mismatched generated companion files
- partially migrated or stale secret mounts

This is especially likely when:

- same-environment sharing works,
- cross-environment sharing fails,
- or a known-good branch works on one host but not another.

## Proven Diagnostic Pattern

Observed good control test:

- `release-candidate` on `safebox.dev` -> `safebox.dev` works
- `release-candidate` on `safebox.dev` -> `dev.safebox.dev` shows `This record is quantum-safe`

Observed fix:

- refresh the recipient environment’s local secret-file set
- restart in bootstrap mode
- allow the secret set to regenerate

After refreshing local secrets, the receiving side correctly decrypted and displayed the real record content again.

## Recommended Debug Sequence

### 1. Establish a branch control

Test the same flow on a known-good branch first.

If the known-good branch behaves the same way, do not assume a code regression.

### 2. Compare environment behavior

Check:

- same-host share
- cross-host share

If same-host works but cross-host fails, suspect host-specific secret/config drift.

### 3. Verify PQC/KEM secret consistency

Confirm the recipient environment has a consistent secret set:

- `pqc_kem_secret_key`
- `pqc_kem_public_key`
- `pqc_sig_secret_key`
- `pqc_sig_public_key`
- service bootstrap identity files

### 4. Refresh local secret files if needed

For direct local dev fallback:

```bash
cd /Users/trbouma/projects/safebox-2
mv /Users/trbouma/projects/safebox-2/data/secrets /Users/trbouma/projects/safebox-2/data/secrets.bak.$(date +%Y%m%d%H%M%S)
mkdir -p /Users/trbouma/projects/safebox-2/data/secrets
SECRET_BOOTSTRAP_MODE=true /Users/trbouma/projects/safebox-2/.venv/bin/python -m uvicorn app.main:app --reload
```

Expected regenerated files:

- `service_nsec`
- `service_npub`
- `nwc_nsec`
- `pqc_sig_secret_key`
- `pqc_sig_public_key`
- `pqc_kem_secret_key`
- `pqc_kem_public_key`

Then restart in normal mode.

### 5. Retest the same record-offer flow

If the symptom disappears after secret refresh, the issue was secret/config drift.

## Notes

- Refreshing secrets changes the local cryptographic identity.
- Previously encrypted local payloads tied to the old key set may no longer decrypt.
- Back up the old secret directory before regeneration.

## Conclusion

If a recipient shows `This record is quantum-safe` instead of the real offered record, first verify recipient secret consistency before assuming a code-path regression.

In practice, this symptom has been a reliable indicator of PQC/KEM secret drift in the recipient environment.
