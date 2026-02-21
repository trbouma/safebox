# Incident Response and Key Compromise Runbook

## Purpose

Define operational steps for security incidents involving key compromise, unauthorized access, suspected fund-loss conditions, and data exposure.

## Severity Levels

- `SEV-1`: Active compromise or likely unauthorized control of funds/critical keys.
- `SEV-2`: High-risk suspicious activity with possible containment available.
- `SEV-3`: Localized or low-impact event with no active compromise confirmed.

## Immediate Actions (First 15 Minutes)

1. Declare incident and assign incident commander.
2. Freeze risky operations:
   - pause card issuance/rotation endpoints if needed
   - pause outbound payment automation if needed
3. Preserve evidence:
   - logs, metrics snapshots, recent deploy hashes
4. Start incident timeline with UTC timestamps.

## Key Compromise Playbooks

### A. `SERVICE_NSEC` Suspected Compromise

1. Rotate `SERVICE_NSEC` immediately.
2. Invalidate active card/token workflows dependent on prior service key.
3. Re-issue card payloads and communicate mandatory re-enrollment.
4. Review all requests since suspected compromise window.

### B. Wallet Private Key Compromise (User Scope)

1. Notify affected user immediately.
2. Block sensitive actions pending user verification.
3. Assist migration to new wallet key and rotate card secret mappings.
4. Provide evidence package for user and legal follow-up.

### C. NWC Secret Mapping Compromise

1. Rotate mapped secret for affected `npub`.
2. Invalidate older card payloads.
3. Verify downstream payment and record flows stabilize.

## Funds Integrity Containment

1. Check settlement queues and pending payment tasks.
2. Query for `ecash-recovery-*` records and unresolved rollbacks.
3. Reconcile:
   - sender wallet balance/proofs
   - receiver wallet balance/proofs
   - tx history entries

## Communications

- Internal update cadence: every 30 minutes for `SEV-1`.
- External message:
  - facts only
  - impact scope
  - immediate user action
  - next update time

## Recovery and Exit Criteria

Incident can close when:

1. Root cause identified or bounded.
2. Compromised keys rotated and old paths invalidated.
3. Fund/record reconciliation completed.
4. Monitoring confirms stable state for agreed observation window.

## Post-Incident Review

Within 5 business days:

1. Publish internal PIR with timeline and corrective actions.
2. Add tests/alerts to prevent recurrence.
3. Update this runbook and related specs.
