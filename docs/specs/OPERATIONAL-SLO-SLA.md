# Operational SLO and SLA

## Overview
This specification defines service objectives and externally communicated service expectations for Safebox operators.

## Scope
- API and web application availability
- Payment and record transaction processing
- Relay/blob dependency health
- Incident response and recovery windows

## Service Level Objectives (SLO)
- Availability: target monthly uptime for critical user paths (login, payment send/receive, record request/present).
- Latency: target response times for key API endpoints and websocket notifications.
- Integrity: target successful completion rate for payment and record transfers.
- Recovery: target mean time to recover (MTTR) for service incidents.

## Service Level Agreement (SLA)
- Define public commitment tier (for example, community best-effort vs managed tier).
- Describe exclusions (upstream relay downtime, force majeure, customer misconfiguration).
- Define communication cadence and status-page behavior during incidents.

## Error Budgets
- Track monthly error budget per objective.
- Use error budget burn to gate feature rollouts and high-risk changes.

## Measurement Model
- Instrument SLI metrics for:
  - request success/failure rates
  - transaction completion states
  - websocket delivery timeliness
  - dependency health (relay/blob/db)
- Publish internal dashboards and periodic operator review.

## Escalation and Response
- Severity model (SEV1-SEV3) with owner and response timelines.
- Incident handoff and postmortem requirements.

## Security Considerations
- Do not disclose sensitive infrastructure details in public SLA reports.
- Maintain tamper-evident incident timelines.

## Implementation References
- `docs/specs/MONITORING-AND-ALERTING-PLAN.md`
- `docs/specs/INCIDENT-RESPONSE-AND-KEY-COMPROMISE-RUNBOOK.md`
- `docs/specs/RESILIENCY-TEST-PLAN.md`
