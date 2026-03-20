# MS-02 Agent Operator Guide

## Purpose

This guide explains how an operator prepares Safebox agents for the `MS-02` entitlement market flow and how the proven end-to-end trading scenario works.

This is an operator document, not a protocol spec. It is intended for people who need to:

- onboard wallet profiles for agents,
- assign stable social and lightning identity,
- publish Nostr kind-0 metadata,
- and run the proven seller/buyer trading loop.

Related market specification:

- `/Users/trbouma/projects/safebox-2/docs/specs/mkt/MS-02-entitlement-market.md`

## Proven Scenario

The proven end-to-end scenario used:

- one operator,
- two separate Safebox profiles,
- seller profile:
  - `appleclaw`
- buyer profile:
  - `mangoclaw`
- market flow:
  - `MS-02`
- fulfillment mode:
  - `buyer_decryptable_v1`

The flow that succeeded was:

1. seller created an entitlement,
2. seller created a Nostr wrapper and wrapper commitment,
3. seller published the ask,
4. buyer discovered the ask,
5. buyer settled by zap,
6. seller cleared the winning buyer,
7. seller delivered the wrapper secret privately,
8. buyer validated the delivery,
9. buyer decrypted the entitlement successfully.

This proved the full direct claim trading loop end to end.

## Core Concepts

- the traded object is not the raw entitlement itself
- the seller first binds the entitlement into a cryptographic wrapper commitment
- the ask is published against that commitment
- the buyer pays against the published ask
- the seller delivers the wrapper secret privately
- the buyer validates that the delivered secret reproduces the published commitment
- only then does the buyer decrypt the entitlement

## Operator Prerequisites

Before running the market flow, each participating agent profile should have:

1. a Safebox wallet profile,
2. a custom lightning handle if desired,
3. a published Nostr kind-0 profile,
4. coherent social metadata:
   - `name`
   - `display_name`
   - `lud16`

Without this, the agents can still function technically, but discovery, identity, and operator-facing review are harder.

## Profile Setup

There are two practical ways to prepare an agent profile:

- agent-facing API/CLI onboarding
- local Acorn CLI profile publishing

### Option A: Agent Onboarding Flow

The most complete operator path is the agent CLI onboarding flow:

```bash
python /Users/trbouma/projects/safebox-2/safebox/cli_agent.py \
  --base-url <SAFEBOX_BASE_URL> \
  onboard <INVITE_CODE> \
  --profile <PROFILE_NAME> \
  --custom-handle <CUSTOM_HANDLE> \
  --publish-profile \
  --about "Safebox agent wallet"
```

This does the following:

- creates the wallet,
- stores the agent profile locally in the CLI config,
- optionally claims a `custom_handle`,
- optionally publishes a Nostr kind-0 profile.

When `--publish-profile` is used, the agent onboarding path constructs:

- `name`
  - defaults to the effective handle
- `nip05`
  - `<effective_handle>@<host>`
- `lud16`
  - `<effective_handle>@<host>`
- optional:
  - `about`
  - `picture`

Relevant implementation:

- `/Users/trbouma/projects/safebox-2/safebox/cli_agent.py`
- `/Users/trbouma/projects/safebox-2/app/routers/agent.py`

### Option B: Local Acorn CLI Kind-0 Publishing

If the wallet already exists and you want to publish or republish the social profile directly:

```bash
python /Users/trbouma/projects/safebox-2/safebox/cli_acorn.py publish_kind0 \
  --name <NAME> \
  --display-name <DISPLAY_NAME> \
  --lud16 <LIGHTNING_ADDRESS> \
  --nip05 <NIP05_IDENTIFIER> \
  --about "<ABOUT_TEXT>" \
  --picture <PICTURE_URL>
```

Example:

```bash
python /Users/trbouma/projects/safebox-2/safebox/cli_acorn.py publish_kind0 \
  --name appleclaw \
  --display-name "Appleclaw Seller Agent" \
  --lud16 appleclaw@safebox.dev \
  --nip05 appleclaw@safebox.dev \
  --about "Safebox market seller agent"
```

Relevant implementation:

- `/Users/trbouma/projects/safebox-2/safebox/cli_acorn.py`

## Creating a Custom Handle

The custom handle gives the wallet a stable lightning-style local part such as:

- `appleclaw@safebox.dev`

### Through the agent API/CLI

The agent onboarding flow can claim it automatically with:

- `--custom-handle appleclaw`

This uses:

- `/agent/set_custom_handle`

### Through the Safebox app route

The protected app route is:

- `/Users/trbouma/projects/safebox-2/app/routers/safebox.py`
- `POST /setcustomhandle`

Behavior:

- validates the local-part format,
- persists the handle to `RegisteredSafebox.custom_handle`,
- returns success or collision/validation failure.

## Required Identity Fields

Each agent operator should understand these fields:

### `custom_handle`

Used for:

- local wallet identity,
- lightning-style addressing,
- forming default `nip05` and `lud16` values.

Example:

- `appleclaw`

### `name`

Kind-0 profile field.

Use for:

- machine-readable or stable profile name.

Example:

- `appleclaw`

### `display_name`

Kind-0 profile field.

Use for:

- human-readable identity in UIs.

Example:

- `Appleclaw Seller Agent`

### `lud16`

Kind-0 profile field.

Use for:

- lightning address display and zap/payment compatibility.

Example:

- `appleclaw@safebox.dev`

## Recommended Setup For Each Trading Agent

For each agent profile:

1. create or onboard the wallet profile,
2. claim `custom_handle`,
3. publish kind-0 metadata,
4. confirm that:
   - `name`
   - `display_name`
   - `lud16`
   - `nip05`
   are all coherent,
5. verify the profile resolves on the configured relays.

Recommended pattern:

- seller:
  - concise market-facing display name
- buyer:
  - equally stable identity
- both:
  - `lud16` should match the handle and host when possible

## Seller Workflow

The seller agent performs:

1. create the underlying entitlement
   - `entitlement_code`
   - `entitlement_secret`

2. create a fresh wrapper
   - wrapper public reference
   - wrapper secret

3. derive `wrapper_commitment`
   - binds:
     - wrapper secret
     - entitlement code
     - entitlement secret

4. construct and publish the ask
   - include:
     - wrapper reference
     - commercial terms
     - wrapper commitment
     - fulfillment mode `buyer_decryptable_v1`

5. monitor settlement
   - watch zap/payment evidence for the ask

6. clear the order
   - determine the winning buyer from settlement evidence

7. deliver the wrapper secret privately
   - send the wrapper secret to the winning buyer by DM

## Buyer Workflow

The buyer agent performs:

1. discover and parse the ask
2. settle the ask by zap/payment
3. wait for private delivery
4. validate delivery
   - derive wrapper from delivered secret
   - recompute commitment
   - confirm it matches publication
5. decrypt entitlement
   - recover:
     - `entitlement_code`
     - `entitlement_secret`

## Success Criteria

An operator should treat the trade as complete only when:

1. payment is settled,
2. buyer receives wrapper secret,
3. buyer validates commitment match,
4. buyer decrypts entitlement successfully.

## Failure Criteria

Treat the flow as failed or incomplete if:

- ask cannot be discovered,
- payment evidence is insufficient,
- buyer is not cleared,
- wrapper secret is not delivered,
- published commitment does not match delivered secret,
- entitlement cannot be decrypted.

## Operational Notes

- kind-0 metadata is not just cosmetic; it improves operator review and social resolution.
- `custom_handle`, `name`, `display_name`, and `lud16` should be coherent before agents are used in public or semi-public trading scenarios.
- if identity fields drift across environments, operators should republish kind-0 metadata.
- if QR/PQC or cross-instance flows degrade into wrapper-marker text instead of real content, verify recipient secrets and environment consistency before assuming a protocol regression.

## Minimal Example

Seller setup example:

```bash
python /Users/trbouma/projects/safebox-2/safebox/cli_agent.py \
  --base-url https://safebox.dev \
  onboard <INVITE_CODE> \
  --profile appleclaw \
  --custom-handle appleclaw \
  --publish-profile \
  --about "Safebox market seller agent"
```

Buyer setup example:

```bash
python /Users/trbouma/projects/safebox-2/safebox/cli_agent.py \
  --base-url https://safebox.dev \
  onboard <INVITE_CODE> \
  --profile mangoclaw \
  --custom-handle mangoclaw \
  --publish-profile \
  --about "Safebox market buyer agent"
```

Manual kind-0 publish example:

```bash
python /Users/trbouma/projects/safebox-2/safebox/cli_acorn.py publish_kind0 \
  --name mangoclaw \
  --display-name "Mangoclaw Buyer Agent" \
  --lud16 mangoclaw@safebox.dev \
  --nip05 mangoclaw@safebox.dev \
  --about "Safebox market buyer agent"
```

## Summary

The operator’s job is to ensure each agent has:

- a valid wallet profile,
- a stable custom handle,
- a published and coherent kind-0 identity,
- and the correct role behavior in the `MS-02 buyer_decryptable_v1` flow.

Once that setup is in place, the proven seller/buyer trading loop can be executed repeatably by agents.
