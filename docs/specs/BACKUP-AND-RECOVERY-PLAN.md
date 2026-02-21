# Backup and Recovery Plan

## Purpose

Define backup scope, retention, restore testing, and recovery objectives for Safebox production operations.

## Recovery Objectives

- `RPO`: 1 minute for metadata where feasible.
- `RTO`: 30 minutes for service restoration target.

## Backup Scope

1. Database:
   - schema and data backups
   - migration metadata
2. Config and secrets metadata (not raw secret values in plaintext backups).
3. Branding files and operational policy files.
4. Evidence logs needed for reconciliation.

## Retention Policy

- Daily backups: 30 days.
- Weekly backups: 12 weeks.
- Monthly backups: 12 months.

## Backup Controls

1. Encrypt backups at rest.
2. Store in separate failure domain.
3. Verify backup integrity checksums.
4. Restrict restore permissions to authorized operators.

## Restore Procedure

1. Provision clean environment.
2. Restore database snapshot.
3. Apply migrations to expected revision.
4. Validate critical flows:
   - login
   - payment request/send
   - record offer/request
5. Run proof/record reconciliation checks.

## Restore Testing Cadence

- Monthly restore drill in staging.
- Quarterly full disaster recovery simulation.

## Exit Criteria

- Service functional on restored environment.
- Reconciliation checks pass.
- Monitoring and alerting restored.
