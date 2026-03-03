# CLI Agent Quickstart

This tutorial gets a human operator from zero to running `cli_agent` commands against the Safebox Agent API.

## 1. Install dependencies

From the project root:

```bash
cd /path/to/safebox-2
poetry install
```

## 2. Run the CLI

Use the script entrypoint:

```bash
poetry run agent --help
```

Alternative module form:

```bash
poetry run python -m safebox.cli_agent --help
```

## 3. Configure base URL and access key

If you have an invite code, you can onboard directly and auto-create profile metadata:

```bash
poetry run agent onboard \
  --invite-code YOUR_INVITE_CODE \
  --profile lumen \
  --publish-profile
```

Onboard and immediately claim a custom handle:

```bash
poetry run agent onboard \
  --invite-code YOUR_INVITE_CODE \
  --custom-handle lumen \
  --publish-profile
```

Default behavior of `onboard`:
- saves a profile (defaults to returned handle if `--profile` is omitted)
- stores returned `access_key` in that profile
- publishes kind-0 with `name=<returned handle>`
- sets this profile as default

To view sensitive onboarding fields (nsec/seed/access key), add:

```bash
poetry run agent onboard --invite-code YOUR_INVITE_CODE --show-secrets
```

You can still configure profiles manually:

Set a profile:

```bash
poetry run agent config set \
  --profile lumen \
  --base-url https://safebox.dev \
  --access-key YOUR_ACCESS_KEY
```

Set another profile:

```bash
poetry run agent config set \
  --profile nova \
  --base-url https://safebox.dev \
  --access-key ANOTHER_ACCESS_KEY
```

Set active default profile:

```bash
poetry run agent config use lumen
```

List profiles:

```bash
poetry run agent config list
```

Check current config:

```bash
poetry run agent config show
```

Notes:
- Config file location: `~/.safebox-agent/config.yml`
- You can override config per command with `--base-url`, `--access-key`, and `--timeout`.
- You can select profile per command with `--profile`.

## 4. Verify wallet access

```bash
poetry run agent info
poetry run agent balance
poetry run agent tx-history --limit 20
```

Run against a non-default profile:

```bash
poetry run agent --profile nova balance
```

## 5. Send and read encrypted DMs

Send:

```bash
poetry run agent secure-dm trbouma@safebox.dev "hello from cli_agent"
```

Read:

```bash
poetry run agent read-dms --limit 10
```

Stream inbox updates (WebSocket):

```bash
poetry run agent stream-dms --limit 20 --poll-seconds 3
```

## 6. Create and view market orders

Create order:

```bash
poetry run agent market-order \
  --side sell \
  --asset riddle \
  --market MS-01 \
  --price-sats 21 \
  --content "Riddle for 21 sats #MS-01"
```

View order book:

```bash
poetry run agent market-orders --limit 20 --market MS-01
```

## 6a. Stream kind-1 updates (WebSocket)

Follow-list constrained stream:

```bash
poetry run agent stream-kind1 \
  --scope following \
  --limit 5 \
  --poll-seconds 3
```

Open discovery stream for a specific NIP-05:

```bash
poetry run agent stream-kind1 \
  --scope discovery \
  --nip05 trbouma@safebox.dev \
  --limit 5 \
  --poll-seconds 3
```

Notes:
- This command runs until interrupted (`Ctrl+C`), unless `--max-messages` is set.
- If your environment cannot run websocket streams, fall back to polling:
  - `poetry run agent my-posts`
  - `poetry run agent market-orders`
  - `poetry run agent read-dms`

## 7. Zap and settle workflow helpers

Zap an event:

```bash
poetry run agent zap --event-id <event_id_hex> --amount-sats 21 --comment "ANSWER PLEASE!"
```

Reply to an event:

```bash
poetry run agent reply <event_id_hex> "✅ settled"
```

Check your own posts:

```bash
poetry run agent my-posts --limit 10
```

Check zap receipts on an event:

```bash
poetry run agent zap-receipts <event_id_hex> --limit 50
```

Generate spec-compliant coupon IDs (`#COUP[A-Z2-9]{6}`):

```bash
poetry run agent coupon-id --count 3
```

## 8. Troubleshooting

- `401 Unauthorized`: access key is missing/invalid.
  - Re-run `agent config set --access-key ...`.
- `404 Not Found`: endpoint not deployed on selected base URL.
  - Verify `--base-url` target and deployment version.
- Empty DM results:
  - Confirm sender and receiver relay overlap.
  - Re-run with explicit relay options if supported.

## 9. CLI separation guidance

- Use `agent` for `/agent/*` API workflows.
- Use `acorn` for local wallet/core workflows.
- Do not assume `agent` and `acorn` share config files or command semantics.
