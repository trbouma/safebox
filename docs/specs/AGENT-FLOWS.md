# Agent Flows

## Overview

Agent flows are machine-to-machine operational paths for Safebox wallets that run without browser sessions or cookie auth.  
They are designed to sit alongside NFC and QR flows as a third interaction model:

- `NFC`: card-present interaction
- `QR`: user-mediated optical handshake
- `Agent`: API-driven automation using `X-Access-Key`

## Scope

Current agent flows:

- Invite onboarding (`/agent/onboard`)
- Wallet info/balance (`/agent/info`, `/agent/balance`)
- Lightning invoice create/pay (`/agent/create_invoice`, `/agent/pay_invoice`)
- Cashu token issue/accept (`/agent/issue_ecash`, `/agent/accept_ecash`)

## Flow Families

### Onboarding Flow

1. Agent submits `invite_code` to `/agent/onboard`.
2. Service validates invite against configured allow-list.
3. Service creates a new wallet instance and seeds baseline records.
4. Service persists wallet identity in `RegisteredSafebox`.
5. Service returns operational credentials and recovery material:
   - `access_key`
   - `nsec`
   - `seed_phrase`
   - wallet identifiers (`handle`, `npub`, relay)

### Payment Flow (Invoice)

1. Agent calls `/agent/create_invoice` with SAT amount.
2. Service returns invoice + quote and starts async settlement monitoring.
3. On settlement, wallet state is updated via existing payment task path.
4. Agent can check state via `/agent/balance` or `/agent/info`.

### Payment Flow (Pay Invoice)

1. Agent calls `/agent/pay_invoice` with BOLT11 invoice.
2. Service executes multi-mint payment path.
3. Service reloads wallet state and persists updated balance snapshot.
4. API returns payment result and final balance.

### Ecash Flow

Issue:

1. Agent calls `/agent/issue_ecash` with amount.
2. Service swaps proofs and returns serialized Cashu token.
3. Wallet balance/tx history are updated.

Accept:

1. Agent calls `/agent/accept_ecash` with token.
2. Service validates token format and redeems/swallows proofs.
3. Wallet balance/tx history are updated and persisted.

## Relationship to NFC and QR

Agent flows reuse the same wallet core (`Acorn`) used by NFC and QR routes, but replace UI interaction with explicit API calls.  
This keeps payment and record semantics aligned across all channels while letting automation clients run unattended.

In practical terms:

- NFC and QR are interaction channels for humans and devices in-session.
- Agent flows are orchestration channels for bots, services, and back-office automation.

## Security Considerations

- `X-Access-Key` is a bearer credential; protect as a secret.
- Require HTTPS/TLS in production.
- Avoid logging secrets (`access_key`, `nsec`, tokens).
- Apply rate limits and request auditing on `/agent/*`.
- Treat onboarding responses as highly sensitive because they include recovery material.

## Operational Notes

- Agent onboarding is intentionally explicit and deterministic for automation.
- Agent APIs do not depend on CSRF cookies or browser session state.
- Agent and browser auth paths should remain isolated to reduce coupling and regression risk.

## Implementation References

- `app/routers/agent.py`
- `docs/specs/AGENT-API.md`
- `docs/specs/NFC-FLOWS-AND-SECURITY.md`
- `docs/specs/OFFERS-AND-GRANTS-FLOWS.md`
- `skills/agent-api/SKILL.md`
