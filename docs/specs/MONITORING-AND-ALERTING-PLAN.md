# Monitoring and Alerting Plan

## Overview
This plan defines operational telemetry, alert thresholds, and response ownership for Safebox service health and transaction integrity.

## Scope
- API/websocket reliability
- Payment and record transfer completion
- Relay, blossom, and database dependencies
- Worker lifecycle and queue/task health

## Core Signals
- Availability: HTTP success rate, websocket connect/close rates.
- Performance: endpoint latency percentiles and queue delay.
- Integrity: payment completion vs failure/rollback counts, record transfer success rates.
- Dependency health: relay reachability, blob retrieval/upload status, DB connection saturation.
- Security: auth failures, decryption errors, abnormal request patterns.

## Alert Classes
- Critical: payment integrity risk, data-loss risk, sustained outage.
- High: degraded core flows with user impact.
- Medium: dependency degradation with fallback available.
- Low: noisy/edge anomalies for investigation.

## Alert Routing
- Assign on-call owner per deployment.
- Route critical alerts to immediate paging channel.
- Route non-critical alerts to ticket queue with SLA.

## Dashboard Requirements
- Real-time board for core user flows.
- Incident board with error budget burn.
- Security board with auth/decrypt anomaly trends.

## Runbook Linkage
Each critical alert must map to a runbook entry with triage, mitigation, and recovery steps.

## Security Considerations
- Avoid logging secrets or plaintext sensitive payloads.
- Protect telemetry endpoints and dashboards with strict access controls.

## Implementation References
- `/Users/trbouma/projects/safebox-2/docs/specs/OPERATIONAL-SLO-SLA.md`
- `/Users/trbouma/projects/safebox-2/docs/specs/INCIDENT-RESPONSE-AND-KEY-COMPROMISE-RUNBOOK.md`
- `/Users/trbouma/projects/safebox-2/docs/specs/RESILIENCY-TEST-PLAN.md`
