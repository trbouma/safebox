# Safebox Scalability Test Plan

## 1. Purpose
This plan defines how to validate Safebox behavior under increasing load, sustained load, and failure conditions. It focuses on API flows, websocket update paths, NFC payment paths, and backend dependencies (Cashu mint, relays, Blossom).

## 2. Goals and SLO Targets
Use these as initial targets and adjust after baseline runs.

- API latency: p95 < 300 ms for core authenticated endpoints under expected peak load.
- Error rate: < 1% non-2xx for normal load tests.
- Websocket update latency: payment status update visible in < 2 seconds after state change.
- NFC request success: > 99% for valid cards/tokens under expected peak.
- Stability: no worker crashes, no unbounded memory growth during soak tests.

## 3. In-Scope Paths

### 3.1 Core HTTP
- `GET /safebox/access`
- `POST /safebox/invoice`
- `POST /safebox/payinvoice`
- `POST /safebox/payaddress`
- `POST /safebox/requestnfcpayment`
- `POST /safebox/paytonfctag`
- `GET /safebox/poll` (legacy path still in use by some flows)

### 3.2 POS
- `GET /pos/`
- `POST /pos/invoice`
- `WS /pos/ws`

### 3.3 Websocket channels
- `WS /safebox/ws/status`
- `WS /safebox/ws/notify`

### 3.4 External dependencies to observe
- Mint endpoints (deposit/melt/swap/check)
- Nostr relays (NWC/event delivery)
- Blossom blob service

## 4. Test Environments
Run each tier before moving to the next.

- Tier A: local single-node dev (quick feedback)
- Tier B: staging with realistic network and reverse proxy
- Tier C: pre-prod-like environment with production-equivalent worker counts and limits

Environment controls:
- fixed app version/commit
- fixed worker count
- fixed DB backend (SQLite vs Postgres, test separately)
- dependency endpoints pinned and recorded

## 5. Workload Profiles

### 5.1 Baseline profile (expected peak)
- 60% read/navigation (`/safebox/access`, profile/status requests)
- 25% payment creation/execution (`invoice`, `payinvoice`, `payaddress`)
- 10% NFC payment flows (`requestnfcpayment`, `paytonfctag`)
- 5% POS (`/pos/invoice`, `/pos/ws` actions)

### 5.2 Stress profile (beyond peak)
- Ramp users/requests until one SLO is violated.
- Continue +20% load to identify hard breakpoints.

### 5.3 Soak profile (endurance)
- Run expected peak for 4-24 hours.
- Capture memory, worker restarts, websocket churn, timeout accumulation.

### 5.4 Spike profile
- Sudden 3-5x burst for 1-3 minutes.
- Measure recovery time to normal p95 and error rates.

## 6. Scenario Matrix

### Scenario A: Invoice lifecycle
1. Create invoice.
2. Simulate payment confirmation.
3. Validate websocket status propagation (`RECD`/`SENT`) and UI completion updates.

Success criteria:
- no stuck "processing" states
- websocket message delivery within SLO

### Scenario B: NFC request payment flow
1. Start `requestnfcpayment` with valid token.
2. Validate card-status preflight behavior.
3. Confirm ecash accept path and final status notification.

Success criteria:
- request accepted/rejected deterministically
- relay listening resolves completion reliably

### Scenario C: POS flow
1. Open `/pos/` with logged-in wallet.
2. Create invoice repeatedly under load.
3. Execute NFC payment path under load.
4. Validate top QR transitions to paid state.

Success criteria:
- no desync between backend payment success and POS UI status
- no websocket stalls or stale pending states

### Scenario D: Failure injection
Inject one failure at a time:
- relay delays/drops
- mint timeout/429/500
- Blossom 404/timeout
- websocket disconnects

Success criteria:
- graceful error response
- no worker crash
- retries/fallbacks behave as designed

## 7. Metrics to Collect

### 7.1 Application
- request rate, latency p50/p95/p99 by endpoint
- error rate by endpoint and exception type
- websocket connection count
- websocket message latency and drops
- background task duration (`handle_payment`, `handle_ecash`)

### 7.2 System
- CPU %, memory RSS, file descriptors
- worker restarts/timeouts
- event-loop lag

### 7.3 Data and dependency
- DB write latency and lock/conflict frequency
- mint/relay/blossom response latency and error codes

## 8. Tooling
Recommended minimal stack:
- HTTP load: `k6` or `Locust`
- Websocket load: small async Python harness (or k6 ws)
- Metrics: Prometheus/Grafana or structured logs + parser
- Log sampling: capture warning/error spikes with endpoint labels

## 9. Execution Procedure

1. Baseline run
- Run low load to validate script correctness and instrumentation.

2. Peak run
- Execute baseline profile for 20-30 min.
- Record SLO pass/fail.

3. Stress run
- Increment concurrency every 5 min until SLO failure.
- Record first failing endpoint and failure mode.

4. Soak run
- 4h minimum at expected peak.
- Track memory drift, websocket reconnect patterns, and task backlog.

5. Spike run
- Burst, then observe recovery timeline.

6. Failure injection run
- Apply one fault at a time.
- Verify graceful behavior and bounded impact.

## 10. Pass/Fail Criteria
A run is pass only if all apply:
- SLO targets met for baseline profile
- no repeated worker crashes or OOM kills
- websocket updates remain timely and consistent
- NFC and POS flows complete without stuck pending states
- no unbounded memory growth in soak run

## 11. Reporting Template
For each run, capture:
- commit SHA
- environment and worker config
- load profile and duration
- peak RPS and concurrency
- p50/p95/p99 latencies by endpoint
- error breakdown
- websocket delivery latency stats
- regressions vs prior run
- remediation actions and owner

## 12. Known Risks to Watch
- SQLite write contention under high concurrent writes
- websocket cleanup/reconnect edge cases under churn
- external relay/mint variability causing apparent app latency
- long-running background tasks increasing memory pressure

## 13. Next Step (Practical)
Start with a Tier A baseline run covering:
- `GET /safebox/access`
- `POST /safebox/invoice`
- `POST /safebox/requestnfcpayment`
- websocket listeners on `/safebox/ws/status` and `/safebox/ws/notify`

Then tune worker count and timeout settings before Tier B.
