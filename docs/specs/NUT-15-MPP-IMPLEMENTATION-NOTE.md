# NUT-15 Partial Multi-Path Payments Implementation Note

## Purpose

This note records the current state of Safebox's partial multi-path payment (MPP)
work against Cashu NUT-15 and explains what remains to be done.

The goal is to capture:

- whether NUT-15 is still implementable in the current codebase,
- what is already present,
- what currently blocks a correct implementation,
- and the recommended order for future implementation.

## Conclusion

NUT-15 partial multi-path payments are still implementable in Safebox.

There is no structural blocker in the current architecture. Safebox already has:

- multi-keyset proof accounting,
- per-mint quote/melt logic,
- swap-for-payment logic,
- and an initial MPP planning branch in `Acorn.pay_multi(...)`.

However, the current implementation is incomplete and should be treated as
scaffolding rather than an active feature.

## Relevant Spec

Primary protocol reference:

- NUT-15 Partial Multi-Path Payments
  - [https://cashubtc.github.io/nuts/15/](https://cashubtc.github.io/nuts/15/)

Supporting capability discovery:

- NUT-06 Mint Info
  - used to determine whether a mint supports NUT-15 for the relevant method/unit

## Current Code Status

Relevant implementation areas:

- `/Users/trbouma/projects/safebox-2/safebox/acorn.py`
  - `pay_multi(...)`
  - `_multi_melt(...)`
  - `_do_mpp_requests(...)`
  - `_post_request(...)`

The current code includes an MPP branch in `pay_multi(...)`, but it is not
currently runnable as a complete payment path.

## What Already Exists

The current implementation already contains useful building blocks:

1. Multi-keyset selection
- The wallet can identify when no single keyset can cover the target payment.
- A branch exists to gather multiple keysets for a possible MPP plan.

2. Partial melt quote scaffolding
- The MPP branch sends melt quote requests with:
  - `options: { "mpp": { "amount": ... } }`

3. Per-keyset melt execution scaffolding
- `_multi_melt(...)` prepares per-mint melt requests for the selected keysets.

4. Existing proof mutation hardening
- swap/consolidate now fail closed on zero-proof replacement
- payment flows now avoid premature mutation of the active proof set

These hardening changes are important because MPP increases the chance of
partial failure across multiple mints.

## Current Blockers

### 1. MPP path is hard-disabled

In `pay_multi(...)`, the MPP branch currently raises:

- `RuntimeError("Multipath payments are not implemented yet!")`

That means the path never executes.

### 2. `_multi_melt(...)` is not awaited

The MPP branch currently calls:

- `self._multi_melt(keysets_to_use_for_multi)`

without `await`.

So even if the hard-disabled guard were removed, the melt phase would not run
correctly.

### 3. NUT-15 partial amount is likely being sent in sats instead of msat

The current code passes:

- `options.mpp.amount = amount_to_use`
- `options.mpp.amount = amount_to_pay`

Those values are handled elsewhere in the payment flow as sats.

NUT-15 requires the partial payment amount in millisats.

This is a protocol mismatch and must be corrected before MPP can work reliably.

### 4. No mint capability filtering

The current MPP branch chooses keysets based on available balance, but does not
check whether the corresponding mint supports NUT-15.

This must be gated through mint capability discovery, typically via NUT-06 mint
info.

Without that, the planner can choose mints that have enough funds but do not
support partial MPP melts.

### 5. `_multi_melt(...)` does not commit final wallet state

The current `_multi_melt(...)` path:

- prepares per-mint melt requests,
- sends them,
- but does not rebuild and commit the final proof state after success.

Specifically, it does not currently:

- verify all melt legs succeeded,
- compute final kept proofs across the participating keysets,
- assign `self.proofs`,
- or call `write_proofs()`.

So the local wallet state is not finalized transactionally after the MPP path.

### 6. `_do_mpp_requests(...)` suppresses errors

The current code uses:

- `asyncio.gather(..., return_exceptions=True)`

and then ignores the returned exceptions.

That means one or more melt legs can fail while the overall routine still
appears to complete.

That is not acceptable for a real money flow.

### 7. MPP failure semantics are not yet defined

MPP requires explicit handling for cases where:

- some mint legs have definitely not been submitted,
- some may have been submitted but not confirmed,
- all submitted successfully,
- or one leg failed after others were already accepted.

This needs a wallet-level state model consistent with the existing payment
resilience contract.

## Implementation Requirements

The following should be treated as required for a correct Safebox NUT-15
implementation.

### A. Capability gate before planning

Before including a mint/keyset in an MPP plan:

- verify that the mint advertises NUT-15 support
- verify support for the intended method and unit

If support is absent:

- exclude the mint from the MPP plan

### B. Use msat for `options.mpp.amount`

All NUT-15 `mpp.amount` values must be sent in millisats, not sats.

This conversion needs to be explicit and test-covered.

### C. Await the MPP melt path

The MPP path must execute as a real async flow:

- quote planning
- proof swap preparation
- melt submission
- result collection
- final proof commit

### D. Fail closed on partial planning failures

If quote planning or swap preparation fails before melt submission:

- payment must fail closed
- no proof replacement may occur

### E. Commit local proof state only after all required melt legs succeed

MPP local wallet mutation must be all-or-nothing from the wallet’s perspective.

That means:

- do not mutate active proof state per leg
- stage all proof changes
- only commit `self.proofs` and `write_proofs()` after all legs are confirmed successful

### F. Explicit uncertain-settlement handling

If one or more melt legs may have been submitted but confirmation is incomplete:

- the payment must be surfaced as uncertain
- not successful
- with enough diagnostic context for reconciliation

This should follow the same resilience principles already documented for other
payment methods.

## Recommended Implementation Order

### Step 1. Remove the hard-disabled branch

Enable the MPP branch in `pay_multi(...)` so it can execute.

### Step 2. Correct protocol units

Convert partial payment values used in:

- `options.mpp.amount`

from sats to millisats.

### Step 3. Add mint capability checks

Before planning:

- load mint info
- filter candidate mints to those that support NUT-15

### Step 4. Make `_multi_melt(...)` authoritative

Refactor `_multi_melt(...)` so it:

- tracks per-keyset selected proofs,
- stages the post-payment proof set,
- waits for all melt legs,
- fails if any leg fails,
- commits wallet state only after full success

### Step 5. Remove silent per-leg error suppression

Change `_do_mpp_requests(...)` and `_post_request(...)` so failures are
propagated and classified rather than ignored.

### Step 6. Add uncertain-state handling

If failure occurs after some melt legs may have reached the mint:

- return an uncertain result
- preserve enough reconciliation context for later verification

### Step 7. Add targeted tests

At minimum:

1. two-mint successful MPP payment
2. candidate mint does not support NUT-15
3. one quote leg fails before submission
4. one melt leg fails before commit
5. one melt leg times out after possible remote submission
6. local proof state remains unchanged on pre-commit failure

## Suggested State Model

MPP should use the same broad reliability model already adopted elsewhere:

- `ACCEPTED`
- `PROCESSING`
- `SETTLED`
- `FAILED`
- `UNCERTAIN`

Additional internal distinctions are useful:

- `PLAN_READY`
- `QUOTES_READY`
- `SWAPS_READY`
- `PARTIAL_MELT_IN_FLIGHT`

These internal states do not need to be exposed to end users, but they are
useful for logs and incident handling.

## Design Guidance

The key engineering rule is this:

MPP must not weaken proof safety in order to gain routing flexibility.

Safebox’s current hardening work on:

- zero-proof replacement guards,
- non-destructive payment assembly,
- and real error propagation

should be treated as prerequisites for MPP, not optional improvements.

## Summary

NUT-15 is still implementable in Safebox.

What exists today is enough to continue, but not enough to enable the feature.

The remaining work is primarily:

- protocol correctness,
- capability gating,
- transactional wallet-state commit,
- and explicit handling of partial/uncertain failures.

That work should be done before exposing MPP as an active payment path.
