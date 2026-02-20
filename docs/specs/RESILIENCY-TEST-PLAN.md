# Safebox Resiliency Test Plan

## 1. Purpose
This plan verifies that Safebox can preserve user funds, records, and recoverability during service disruption, including denial-of-service (DoS) and partial infrastructure failures.

Primary resiliency objective:
- User data remains retrievable and integrity-verifiable even if one or more service components are unavailable.

## 2. Resiliency Goals
Define explicit targets before testing.

- RTO (Recovery Time Objective):
  - API/front-end recovery: <= 30 minutes after primary outage.
  - Critical relay/blossom failover path active: <= 5 minutes.
- RPO (Recovery Point Objective):
  - Wallet/record metadata: <= 1 minute.
  - Blob availability: zero data loss for committed blobs.
- Data integrity:
  - 100% signature/verifiability checks must pass after failover.

## 3. System Components Under Test

- Safebox app/API service
- Home relay layer (Nostr event persistence and retrieval)
- Blossom blob layer (encrypted blob storage/retrieval)
- Background processors (payment polling, ecash handling, notification fanout)

## 4. Core Architecture Assumptions

Resiliency design should include:
- Separate home relay servers (at least primary + secondary)
- Separate Blossom servers (at least primary + secondary)
- No single dependency where both metadata and blob payload are lost together
- Client/application awareness of alternate relay and blob endpoints

## 5. Resiliency Architecture Strategies

Apply these strategies before running drills:
- Home relay separation:
  - Use independent relay operators/hosts for primary and secondary.
  - Avoid shared failure domains (same VM host, same provider region, same reverse proxy).
- Blossom separation:
  - Store and retrieve blobs from at least two independent Blossom endpoints.
  - Keep hash-addressed verification (`sha256`) mandatory on read and transfer.
- Endpoint diversity:
  - Maintain at least one direct endpoint path and one proxied endpoint path.
  - Validate that clients can reconnect when one DNS/proxy path is unavailable.
- Degraded-mode behavior:
  - If writes are unstable, fail closed with explicit user messaging (no silent success).
  - Keep read/recovery paths available for existing records whenever possible.
- Recovery-by-design:
  - Preserve enough event + blob state to reconstruct wallet/record views after outage.
  - Require signature/hash validation after restoration before marking system healthy.

## 6. Threat and Failure Model

Test at minimum these classes:
- Full app node outage
- App saturation (CPU/memory exhaustion)
- Home relay outage or partition
- Blossom outage or high-latency/degraded responses
- DNS/proxy path disruption
- Coordinated DoS against one tier (relay or blossom)
- Multi-component partial outage (one relay + one blossom unavailable)

## 7. Test Data Preparation

Before each run, seed known datasets:
- Wallet with non-trivial proof distribution (multiple keysets/mints)
- Records set containing:
  - plaintext records
  - signed structured records
  - blob-backed records (image/PDF)
- Active NFC flows and POS flow test users

Record baseline checksums and counts:
- event counts by kind
- blob counts and SHA-256 references
- wallet balance/proof counts

## 8. Test Scenarios

### Scenario A: App service hard down
1. Stop all app workers.
2. Keep relay and blossom online.
3. Validate that previously issued tokens/records remain retrievable from relays/blossom once app is restored.

Pass:
- no proof/record loss after app restart
- websocket and API flows recover without manual DB surgery

### Scenario B: Primary home relay unavailable
1. Disable primary relay endpoint.
2. Force reads/writes to secondary relay set.
3. Run payment and record offer/request workflows.
4. Restore primary and verify eventual consistency/replay behavior.

Pass:
- writes continue on alternate relay
- records/events remain signature-valid

### Scenario C: Primary Blossom unavailable
1. Disable primary Blossom endpoint.
2. Fetch existing blob-backed records via secondary.
3. Issue and transfer new blob-backed records.
4. Restore primary and validate parity.

Pass:
- blob reads/writes continue without corruption
- blob sha256 references remain consistent

### Scenario D: Relay DoS simulation
1. Introduce high latency, packet loss, or request throttling on primary relay.
2. Verify fallback relay selection and timeout behavior.
3. Confirm user-facing status degrades gracefully.

Pass:
- no stuck pending states beyond timeout policy
- fallback relay engagement observed in logs/metrics

### Scenario E: Blossom DoS simulation
1. Saturate blossom API with synthetic load.
2. Verify retries/backoff and alternate blossom use.
3. Confirm blob transfer functions fail safely with actionable errors.

Pass:
- no silent data loss
- no malformed record issuance on blob failures

### Scenario F: Combined attack simulation
1. Degrade primary relay and primary blossom simultaneously.
2. Execute:
  - invoice payment flows
  - NFC request/payment
  - offer/grant + blob presentation
3. Validate end-to-end recoverability after restoration.

Pass:
- funds and records remain consistent
- reconciliation requires no manual proof reconstruction

## 9. Service-Down Data Protection Matrix

Validate these explicitly:

| Failure case | Expected user impact | Data-protection expectation | Recovery check |
|---|---|---|---|
| App/API down, relay+Blossom up | New actions paused | Existing signed records/blobs remain intact | App restart + reconciliation clean |
| Primary relay down | Possible delay | Events continue via secondary relay | Event counts/signatures match baseline |
| Primary Blossom down | Blob fetch/write delay | Blob data available via secondary, hash-valid | Blob hash parity + transfer success |
| Relay+Blossom primary under DoS | Slower UX, fallback notices | No silent record/proof loss | Failover counters and integrity checks pass |
| DNS/proxy outage | Partial client failures | Direct alternate endpoints still usable | Clients reconnect to alternate path |

## 10. DoS and Chaos Strategy

Use controlled chaos injections:
- latency and error injection (timeouts, 429, 5xx)
- connection resets and websocket disconnect storms
- CPU/memory pressure at app and dependency layers

Recommended cadence:
- weekly short chaos drills in staging
- monthly full failover drill
- quarterly combined-failure game day

## 11. Observability and Evidence

Collect during every run:
- endpoint latency/error percentiles
- websocket disconnect/reconnect rates
- relay/blossom failover activation counters
- queue/backlog depth for payment and record tasks
- balance/proof/record reconciliation report before vs after test

Persist artifacts:
- logs
- metrics snapshots
- incident timeline and decision log

## 12. Data Protection Checks

After each disruption test, run these validations:
- Wallet proof reconciliation:
  - pre-test total balance == post-test total balance (adjusted for known txs)
- Record reconciliation:
  - all expected record IDs resolvable
  - signatures verify
- Blob reconciliation:
  - each `blobsha256` resolves and matches hash

## 13. Operational Recovery Runbooks to Validate

Test runbooks should include:
- relay failover activation/deactivation
- blossom failover activation/deactivation
- DNS/proxy cutover procedure
- read-only protective mode (if write paths unstable)
- post-incident integrity audit

## 14. Pass/Fail Criteria

Overall pass requires:
- RTO/RPO targets met
- no unrecoverable loss of proofs, records, or blobs
- integrity checks pass after failover and restoration
- user-facing flows either complete or fail with explicit, actionable status

## 15. Immediate Implementation Priorities

1. Ensure at least two independent home relay endpoints are configured and tested for failover.
2. Ensure at least two independent Blossom endpoints are configured and tested for failover.
3. Add periodic automated reconciliation checks (balance/proof/blob integrity).
4. Add scheduled resiliency drills with documented outcomes.

## 16. First Drill (Recommended)

Run this first in staging:
1. Seed 3 wallets with funds and blob-backed records.
2. Disable primary relay for 15 minutes.
3. Execute NFC request payment + record offer/request.
4. Disable primary Blossom for 15 minutes.
5. Repeat blob-backed record flows.
6. Restore both services and run full integrity reconciliation.

Expected outcome:
- No data loss, no proof drop, and all blobs/records remain retrievable and verifiable.
