# WebSocket Conformance

## Purpose

Provide runnable smoke tests for Agent API websocket endpoints.

This spec validates:

- auth and initial connection frame
- change-detection frames (`events` / `messages`)
- heartbeat behavior
- follow-scope policy enforcement
- websocket-to-GET fallback equivalence

## Prerequisites

- `wscat` installed:

```bash
npm i -g wscat
```

- environment variables:

```bash
BASE_URL="https://safebox.dev"
WS_BASE_URL="wss://safebox.dev"
API_KEY="your-access-key"
FOLLOWED_NIP05="trbouma@safebox.dev"
UNFOLLOWED_NIP05="someone-not-followed@example.com"
```

## Endpoints Under Test

- `WS /agent/ws/read_dms`
- `WS /agent/ws/nostr/latest_kind1`
- `WS /agent/ws/nostr/discovery/latest_kind1`
- `WS /agent/ws/nostr/my_latest_kind1`
- `WS /agent/ws/nostr/following/latest_kind1`

Fallback GET equivalents:

- `/agent/read_dms`
- `/agent/nostr/latest_kind1`
- `/agent/nostr/discovery/latest_kind1`
- `/agent/nostr/my_latest_kind1`
- `/agent/nostr/following/latest_kind1`

## Conformance Cases

### WS-CONN-001 Auth + Connected Frame

Expected:

- first response frame contains:
  - `"status":"OK"`
  - `"type":"connected"`

Example:

```bash
wscat -c "${WS_BASE_URL}/agent/ws/nostr/my_latest_kind1?limit=5&poll_seconds=3&access_key=${API_KEY}"
```

Pass criteria:

- first frame is `type=connected`.

### WS-DATA-002 Change Frame

Expected:

- frame type:
  - `messages` for `/agent/ws/read_dms`
  - `events` for `/agent/ws/nostr/*`

Example (kind-1 discovery stream):

```bash
wscat -c "${WS_BASE_URL}/agent/ws/nostr/discovery/latest_kind1?nip05=${FOLLOWED_NIP05}&limit=5&poll_seconds=3&access_key=${API_KEY}"
```

While stream is open, create a new post/DM in another client.

Pass criteria:

- receives a frame with `type=events` or `type=messages` and non-empty array when data exists.

### WS-HEARTBEAT-003 No-Change Frame

Expected:

- when no new data arrives in the current poll interval, stream emits:
  - `"type":"heartbeat"`

Pass criteria:

- at least one heartbeat frame observed after connected frame during idle period.

### WS-POLICY-004 Follow Scope Guard

Endpoint:

- `WS /agent/ws/nostr/latest_kind1`

Expected:

- for unfollowed `nip05`, server sends error payload and closes with policy behavior.

Example:

```bash
wscat -c "${WS_BASE_URL}/agent/ws/nostr/latest_kind1?nip05=${UNFOLLOWED_NIP05}&limit=5&poll_seconds=3&access_key=${API_KEY}"
```

Pass criteria:

- receives error payload containing `"Identifier is not followed by this wallet"`.
- connection closes shortly after error.

### WS-FALLBACK-005 GET Equivalence

When runtime cannot reliably consume websocket frames, use GET endpoints and verify logical parity.

Examples:

```bash
curl -sS -H "X-Access-Key: ${API_KEY}" \
  "${BASE_URL}/agent/read_dms?limit=20&kind=1059"

curl -sS -H "X-Access-Key: ${API_KEY}" \
  "${BASE_URL}/agent/nostr/my_latest_kind1?limit=5"

curl -sS -H "X-Access-Key: ${API_KEY}" \
  "${BASE_URL}/agent/nostr/discovery/latest_kind1?nip05=${FOLLOWED_NIP05}&limit=5"
```

Pass criteria:

- returned datasets are consistent with websocket stream content over the same time window.

## Optional Header-Auth WS Check

Some websocket clients can set headers. If supported, verify header mode without query `access_key`.

Example:

```bash
wscat -c "${WS_BASE_URL}/agent/ws/read_dms?limit=20&kind=1059&poll_seconds=3" \
  -H "X-Access-Key: ${API_KEY}"
```

Pass criteria:

- authenticated `connected` frame received.

## Test Record Template

Use this template for run logs:

```text
Run ID: WS-RUN-001
Date: YYYY-MM-DD
Environment: dev|prod
Tester:

WS-CONN-001: PASS|FAIL
Evidence:

WS-DATA-002: PASS|FAIL
Evidence:

WS-HEARTBEAT-003: PASS|FAIL
Evidence:

WS-POLICY-004: PASS|FAIL
Evidence:

WS-FALLBACK-005: PASS|FAIL
Evidence:
```
