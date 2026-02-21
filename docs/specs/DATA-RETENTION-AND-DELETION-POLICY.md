# Data Retention and Deletion Policy

## Overview
This policy defines how Safebox operators retain, minimize, and delete data across wallet, payment, record, and operational systems.

## Scope
- Application database records (wallet metadata, onboarding state, transaction history)
- Encrypted blob references and transfer metadata
- Logs, telemetry, and security events
- Backup artifacts and recovery snapshots

## Policy
- Data minimization: Store only fields required for wallet operation, integrity, and legal obligations.
- Separation: Treat encrypted payloads and operational metadata as distinct retention classes.
- Least persistence: Avoid retaining transient secrets, decrypted payloads, and temporary tokens beyond processing windows.
- User-driven lifecycle: Provide workflows to rotate/revoke credentials and retire stale artifacts.

## Retention Classes
- Wallet/account metadata: Retain while account is active; archive or delete after closure per jurisdiction.
- Payment history: Retain per financial reporting and dispute windows in the operator jurisdiction.
- Record metadata: Retain minimal routing and integrity metadata; avoid plaintext content persistence unless explicitly configured.
- Logs and traces: Keep short default retention with extended retention only for security/compliance cases.
- Backups: Retain according to tiered schedule (daily/weekly/monthly) with defined expiration.

## Deletion Model
- Soft-delete where legal hold or reconciliation may be required.
- Hard-delete for expired data classes after hold windows close.
- Cryptographic erasure for encrypted material where direct deletion is delayed.
- Secure wipe of temporary files and export artifacts on completion.

## Governance and Controls
- Define owner for each data class and retention rule.
- Document lawful-basis/legal-hold exceptions.
- Maintain deletion runbooks and audit logs for deletion actions.
- Review policy at least quarterly or after major architecture changes.

## Security Considerations
- Deletion requests must be authenticated and authorized.
- Protect deletion pathways from mass-delete abuse.
- Verify backups and replicas respect deletion and expiry controls.

## Implementation References
- `docs/specs/BACKUP-AND-RECOVERY-PLAN.md`
- `docs/specs/FIDUCIARY-CONSIDERATIONS-FOR-SERVICE-OPERATORS.md`
- `docs/specs/SECURITY-TEST-PLAN.md`
