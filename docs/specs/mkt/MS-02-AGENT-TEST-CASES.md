# MS-02 Agent Test Cases
**Spec Family**: `MS-02`  
**Version**: `1.1`  
**Status**: Draft  
**Date**: `2026-03-13`  
**Primary Spec**: `MS-02-entitlement-market.md`

---

## 1. Purpose

Provide reusable, copyable test cases that can be handed to agents to validate the current `MS-02` implementation surface.

This document is execution-oriented. It describes how an agent should test the implemented API methods and what outputs it must verify.

Normative market semantics remain in:

- `MS-02-entitlement-market.md`
- `MS-02-END-TO-END-SCENARIO.md`
- `MS-02-CONFORMANCE.md`
- `MS-02-AGENT-IMPLEMENTATION-CHECKLIST.md`

---

## 2. Current Implemented Surface

The current MS-02 agent test surface covers:

1. `POST /agent/market/ms02/generate_entitlement`
2. `POST /agent/market/ms02/generate_wrapper`
3. `POST /agent/market/ms02/derive_wrapper_commitment`
4. `POST /agent/market/ms02/construct_ask`
5. `POST /agent/market/ms02/publish_ask`
6. `GET /agent/market/ms02/asks`
7. `POST /agent/market/ms02/parse_ask_event`
8. `GET /agent/market/ms02/settlement_receipts`
9. `GET /agent/market/ms02/clear_order`
10. `POST /agent/market/ms02/deliver_wrapper_secret`
11. `POST /agent/market/ms02/encrypt_entitlement_nip44`
12. `POST /agent/market/ms02/decrypt_entitlement_nip44`
13. `POST /agent/market/ms02/validate_buyer_delivery`

These tests validate:

- seller-side build and publish
- ask discovery and parsing
- settlement evidence and clearing
- buyer-side wrapper delivery validation
- buyer-side decryptable fulfillment recovery

The full currently implemented `buyer_decryptable_v1` loop has now been executed successfully end to end under a single operator controlling two profiles.

---

## 3. Agent Output Rules

When running any test in this document, the agent MUST:

- stop immediately on the first failing required step
- report the step number and endpoint used
- report the exact returned error
- avoid printing sensitive values in the final summary unless needed for debugging

Sensitive values include:

- `entitlement_secret`
- `wrapper_secret_nsec`

The final summary SHOULD prefer non-secret identifiers:

- `entitlement_code`
- `wrapper_ref`
- `wrapper_commitment`
- `ask_id`
- `published_event_id`

---

## 4. Test Case Format

Each test case defines:

- objective
- required steps
- validation rules
- required report format

Agents SHOULD execute the steps exactly in order unless a step explicitly allows variation.

---

## 5. Test Cases

### TC-MS02-AGENT-001 Seller Flow Smoke Test

**Objective**

Verify that an agent can complete the currently implemented MS-02 seller-side flow from entitlement generation through ask publication.

**Steps**

1. Call `POST /agent/market/ms02/generate_entitlement`
- pass no arguments
- record:
  - `entitlement_code`
  - `entitlement_secret`

2. Call `POST /agent/market/ms02/generate_wrapper`
- pass no arguments
- record:
  - `wrapper_ref`
  - `wrapper_secret_nsec`

3. Call `POST /agent/market/ms02/derive_wrapper_commitment`
- input:
  - `nsec = wrapper_secret_nsec`
  - `entitlement_code`
  - `entitlement_secret`
- record:
  - `wrapper_commitment`

4. Call `POST /agent/market/ms02/construct_ask`
- input:
  - `wrapper_ref`
  - `wrapper_commitment`
  - `price_sats = 21`
  - `expiry = 2026-03-31T23:59:59Z`
- record:
  - `ask_id`
  - `content`
  - `tags`
  - `order_details`

5. Call `POST /agent/market/ms02/publish_ask`
- input:
  - `content` from step 4
  - `tags` from step 4
- omit `kind` so it defaults to `1`
- record:
  - `event_id`
  - `kind`
  - `ask_id`

**Validation rules**

- step 1 MUST return non-empty `entitlement_code` and `entitlement_secret`
- step 2 MUST return non-empty `wrapper_ref` and `wrapper_secret_nsec`
- step 3 MUST return non-empty `wrapper_commitment`
- step 4 MUST return:
  - non-empty `ask_id`
  - `order_details.wrapper_ref == wrapper_ref`
  - `wrapper_commitment` equal to the step 3 value
- step 5 MUST return:
  - `status = OK`
  - `kind = 1`
  - non-empty `event_id`
  - returned `ask_id` equal to the step 4 value

**Required report**

Return:

- `status: PASS` or `FAIL`
- `entitlement_code`
- `wrapper_ref`
- `wrapper_commitment`
- `ask_id`
- `published_event_id`
- failure details if unsuccessful

---

### TC-MS02-AGENT-002 Wrapper Normalization Test

**Objective**

Verify that `generate_wrapper` is stable when given an existing wrapper secret.

**Steps**

1. Call `POST /agent/market/ms02/generate_wrapper` with no arguments
- record:
  - `wrapper_ref_a`
  - `wrapper_secret_nsec`
  - `wrapper_commitment_hint_a`

2. Call `POST /agent/market/ms02/generate_wrapper`
- input:
  - `nsec = wrapper_secret_nsec`
- record:
  - `wrapper_ref_b`
  - `wrapper_commitment_hint_b`

**Validation rules**

- `wrapper_ref_a == wrapper_ref_b`
- `wrapper_commitment_hint_a == wrapper_commitment_hint_b`

**Required report**

Return:

- `status: PASS` or `FAIL`
- `wrapper_ref`
- `wrapper_commitment_hint`
- failure details if unsuccessful

---

### TC-MS02-AGENT-003 Wrapper Commitment Mutation Test

**Objective**

Verify that changing entitlement material changes the full wrapper commitment.

**Steps**

1. Generate one wrapper
2. Generate one entitlement
3. Derive commitment `C1` using:
- original `entitlement_code`
- original `entitlement_secret`

4. Derive commitment `C2` using the same wrapper and same `entitlement_code`, but a different `entitlement_secret`

5. Derive commitment `C3` using the same wrapper and same `entitlement_secret`, but a different `entitlement_code`

**Validation rules**

- `C1 != C2`
- `C1 != C3`

**Required report**

Return:

- `status: PASS` or `FAIL`
- `wrapper_ref`
- `commitment_original`
- `commitment_changed_secret`
- `commitment_changed_code`
- failure details if unsuccessful

---

### TC-MS02-AGENT-004 Alternate Publish Kind Test

**Objective**

Verify that `publish_ask` supports an explicit non-default event kind.

**Steps**

1. Repeat the build flow through `construct_ask`
2. Call `POST /agent/market/ms02/publish_ask`
- input:
  - `content`
  - `tags`
  - `kind = 30078`

**Validation rules**

- response MUST return `status = OK`
- response MUST return `kind = 30078`
- response MUST return non-empty `event_id`
- response MUST return the same `ask_id` present in the supplied tags

**Required report**

Return:

- `status: PASS` or `FAIL`
- `ask_id`
- `published_event_id`
- `kind`
- failure details if unsuccessful

---

### TC-MS02-AGENT-005 Single-Operator Full End-to-End Test

**Objective**

Verify the complete currently implemented `buyer_decryptable_v1` flow under a single operator controlling both sides:

1. seller agent creates and publishes an ask
2. buyer zaps the ask for the exact required amount
3. seller agent clears the order
4. seller agent delivers the wrapper secret
5. buyer agent validates the delivery
6. buyer agent decrypts the entitlement

**Test actor model**

- one operator controls:
  - `seller_profile`: creates and publishes the ask
  - `buyer_profile`: zaps the ask and receives the wrapper secret

The operator is one entity, but the test MUST still use two separate wallet identities/profiles so that settlement, clearing, delivery, and buyer-side validation are meaningful.

**Preconditions**

- both profiles are configured and can access the same relay set
- buyer wallet can zap the published ask event
- seller can send secure DMs to the buyer
- the single operator can switch between `seller_profile` and `buyer_profile` during the test

**Steps**

Seller-side build:

1. Under `seller_profile`, call `POST /agent/market/ms02/generate_entitlement`
- pass no arguments
- record:
  - `entitlement_code`
  - `entitlement_secret`

2. Under `seller_profile`, call `POST /agent/market/ms02/generate_wrapper`
- pass no arguments
- record:
  - `wrapper_ref`
  - `wrapper_secret_nsec`

3. Under `seller_profile`, call `POST /agent/market/ms02/derive_wrapper_commitment`
- input:
  - `nsec = wrapper_secret_nsec`
  - `entitlement_code`
  - `entitlement_secret`
- record:
  - `wrapper_commitment`

4. Under `seller_profile`, call `POST /agent/market/ms02/encrypt_entitlement_nip44`
- input:
  - `wrapper_ref`
  - `entitlement_code`
  - `entitlement_secret`
- record:
  - `sealed_delivery_alg`
  - `encrypted_entitlement`

5. Under `seller_profile`, call `POST /agent/market/ms02/construct_ask`
- input:
  - `wrapper_ref`
  - `wrapper_commitment`
  - `price_sats = 21`
  - `expiry = 2026-03-31T23:59:59Z`
  - `fulfillment_mode = buyer_decryptable_v1`
  - `sealed_delivery_alg = nip44_v2`
  - `encrypted_entitlement`
- record:
  - `ask_id`
  - `content`
  - `tags`

6. Under `seller_profile`, call `POST /agent/market/ms02/publish_ask`
- input:
  - `content`
  - `tags`
- omit `kind` so it defaults to `1`
- record:
  - `published_event_id`

Buyer-side discovery:

7. Under `buyer_profile`, call `GET /agent/market/ms02/asks`
- default `kind = 1`
- verify the published ask appears

8. Under `buyer_profile`, call `POST /agent/market/ms02/parse_ask_event`
- input:
  - `event_id = published_event_id`
- verify the parsed ask is well-formed and buyer-decryptable

Buyer-side settlement:

9. Under `buyer_profile`, zap the published ask event for exactly `21 sats`
- the zap MUST reference the published ask event id
- the zap receipt MUST resolve the buyer identity

Seller-side clearing:

10. Under `seller_profile`, call `GET /agent/market/ms02/clear_order`
- input:
  - `ask_event_id = published_event_id`
- poll until:
  - `clearing_state = CLEARED`
  - or the test timeout is reached

11. Under `seller_profile`, once cleared, call `POST /agent/market/ms02/deliver_wrapper_secret`
- input:
  - `ask_event_id = published_event_id`
  - `wrapper_secret_nsec`
- record:
  - delivery response
  - winning buyer identity

Buyer-side fulfillment verification:

12. Under `buyer_profile`, obtain the delivered `wrapper_secret_nsec`
- in this single-operator test, the preferred source is the secure DM sent in step 11
- an explicit harness handoff MAY be used only if DM readout is not yet automated in the test runner

13. Under `buyer_profile`, call `POST /agent/market/ms02/validate_buyer_delivery`
- input:
  - `wrapper_secret_nsec`
  - `ask_event_id = published_event_id`
- record:
  - `validated`
  - `wrapper_ref_matches`
  - `wrapper_commitment_matches`

14. Under `buyer_profile`, call `POST /agent/market/ms02/decrypt_entitlement_nip44`
- input:
  - `wrapper_secret_nsec`
  - `ask_event_id = published_event_id`
- record:
  - `decrypted_entitlement`

**Validation rules**

Seller-side:

- steps 1-6 MUST succeed
- published ask MUST have:
  - `fulfillment_mode = buyer_decryptable_v1`
  - `sealed_delivery_alg = nip44_v2`
  - non-empty `encrypted_entitlement`

Buyer discovery:

- step 7 MUST discover the ask
- step 8 MUST parse:
  - `market = MS-02`
  - `side = ask`
  - `wrapper_ref`
  - `wrapper_commitment`
  - `ask_id`
  - `fulfillment_mode = buyer_decryptable_v1`
  - `sealed_delivery_alg = nip44_v2`

Settlement and clearing:

- step 10 MUST eventually return:
  - `clearing_state = CLEARED`
  - non-null `winning_buyer`
  - `winning_buyer.total_sats_floor >= 21`

Delivery:

- step 11 MUST return:
  - `status = OK`
  - `delivery_method = secure_dm`
  - buyer identity matching the `winning_buyer`

Buyer validation:

- step 13 MUST return:
  - `validated = true`
  - `wrapper_ref_matches = true`
  - `wrapper_commitment_matches = true`

Buyer decrypt:

- step 14 MUST return `decrypted_entitlement`
- `decrypted_entitlement.entitlement_code` MUST equal the seller-generated `entitlement_code`
- `decrypted_entitlement.entitlement_secret` MUST equal the seller-generated `entitlement_secret`

**Required report**

Return:

- `status: PASS` or `FAIL`
- `operator_mode: single_entity_two_profiles`
- `seller_profile`
- `buyer_profile`
- `entitlement_code`
- `wrapper_ref`
- `wrapper_commitment`
- `ask_id`
- `published_event_id`
- `winning_buyer_npub`
- `validated`
- `buyer_decrypts`
  - `entitlement_code`
  - `entitlement_secret`
- failure details if unsuccessful

Sensitive values:

- do not print `wrapper_secret_nsec` in the final summary
- do not print `entitlement_secret` in the final summary unless debugging a failure

**Current result**

This test has been executed successfully against the current implementation surface.

What is now proven by execution:

- seller can create and publish a valid `buyer_decryptable_v1` ask
- buyer can discover and parse the ask
- buyer can settle via zap
- seller can clear the order deterministically
- seller can deliver the wrapper secret via secure DM
- buyer can validate the delivery
- buyer can decrypt the entitlement
- decrypted entitlement matches the seller-generated source values

---

## 6. Copy-Paste Prompt Template

Use this prompt when assigning a seller-flow test to an agent:

```text
Run MS-02 agent test case TC-MS02-AGENT-001 from `MS-02-AGENT-TEST-CASES.md`.

Execute the steps exactly as written.
Stop immediately on the first failed required step.
Do not print sensitive values such as `entitlement_secret` or `wrapper_secret_nsec` in the final summary unless required for debugging.

Return a compact report containing:
- status
- entitlement_code
- wrapper_ref
- wrapper_commitment
- ask_id
- published_event_id
- failure details if unsuccessful
```

---

## 7. Revision History

| Version | Date | Notes |
|---------|------|-------|
| `1.0` | 2026-03-13 | Initial MS-02 agent test case set covering seller-side build, wrapper normalization, commitment mutation, and ask publication. |
