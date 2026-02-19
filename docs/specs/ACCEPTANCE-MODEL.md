# The Acceptance Model
*A generic framework for how statements become facts*

## Overview

The **Acceptance Model** captures a simple idea:

> Facts and views are not created by a system; they exist in the world.  
> A system decides what it will treat as settled and actionable.

Across law, governance, science, and technical systems, disputes usually do not hinge on ultimate truth. They hinge on what the system is prepared to treat as **resolved, binding, and sufficient for action**.

The model provides a generic vocabulary for that process in decentralized contexts such as Nostr.

It is useful whenever:

- multiple actors make competing or complementary claims
- uncertainty or disagreement exists
- decisions must be made under incomplete information
- the system must eventually stop asking questions in a transparent, deterministic way

Typical applications:

- legal fact-finding
- administrative decision processes
- technical state validation
- ownership/control registries
- cryptographic transaction finalization

The model avoids metaphysical claims. It asks:

> What must be accepted so action can proceed?

## Working-Group Context and Safebox Position

This model is being developed in the context of an active Web of Trust working-group effort and is incorporated into Safebox as a generalized framework for determining:

- which parties are considered trustworthy in a given context
- what those parties are permitted to do under the relevant legal system or governance structure in effect

Safebox’s design objective is neutral infrastructure:

- Safebox aims to enforce and operationalize recognized decisions/policies.
- Safebox does not define substantive truth, legal outcomes, or governance legitimacy.
- Safebox is designed to minimize implication in, or influence over, those external determinations.

In practice, Safebox provides the verification, attestation, recognition, and policy-execution machinery while leaving normative authority to the governing institutions, communities, and legal frameworks that rely on it.

## Acceptance Model with Nostr

The Acceptance Model is implementation-agnostic, but Nostr provides minimal primitives that make it easy to demonstrate:

- the **system**: npubs + signed events
- the **world**: everything outside the protocol that claims refer to

Any system operating at scale must answer:

1. What is being claimed?
2. Who vouches for the claim (and how)?
3. When does uncertainty stop for operational purposes?

The model separates:

- reality from language
- claims from validation
- trust in statements from trust in action
- truth from recognition

## Core Concepts

- **Claim**: A declaration about reality at a point in time. A claim may be factual or evaluative.
- **Fact**: A claim that is defined in verifiable terms and can be accepted as true by a system.
- **View**: A claim that depends on judgment, perspective, or norms rather than factual conditions alone.
- **Assertion**: A claim put forward by an actor as true, with responsibility attached.
- **Attestation**: An assertion about another assertion or actor (for example, validity or control).
- **Recognition**: A system-level decision to treat an actor as having standing.
- **Acceptance**: A system-level decision to treat a claim-chain as operationally resolved.

## Recognition, Authority, and Delegation

Recognition, authority, and delegation are distinct:

- Delegation proposes authority.
- Recognition makes authority effective in a given system.
- Authority exists only to the extent recognized standing exists.

In this model:

- assertions introduce claims
- attestations qualify claims and actors
- recognition produces standing
- standing enables authority/delegation to operate

## Layers: Statements, Assertions, Attestations, Recognition

| Level | Layer | Refers To | Meaning | Example |
|---|---|---|---|---|
| 0a | Statement (Factual) | Reality | Verifiable condition | "The light is on" |
| 0b | Statement (Evaluative) | Reality + judgment | Interpreted condition | "The light is too bright" |
| 1 | Assertion | Statement | Actor claims a statement | Alice: "The light is on" |
| 2 | Attestation (2nd order) | Assertion | Assertion about an assertion | Bob: "Alice's claim is true" |
| 3 | Attestation (nth order) | Attestation | Assertion about an attestation | Carol: "Bob's attestation is valid" |
| - | Recognition | Actor | Actor standing decision | Bob: "Alice is authorized to act for me" |
| - | Acceptance | Chain | Stop condition for action | System concludes and proceeds |

The diagram below illustrates these relationships:

![Acceptance Model](./img/acceptance-model.png)

## Statements: Facts and Views

A statement is an expression about conditions. It is not automatically a fact.

### Factual statements

- defined in verifiable terms
- measurable or binary
- true/false capable

Example: *The light is on*

### Evaluative statements (views)

- include judgment or perspective
- depend on purpose, comfort, or norms
- require a standard to become testable

Example: *The light is too bright*

> Facts require conditions; views require interpretation.

## Assertions

An assertion introduces responsibility:

- assertions may concern facts or views
- a signed event binds the claim to an identity
- signing creates accountability, not truth

Example:

- Alice signs: *"The light is on"*

This is an assertion. It may later be accepted as a fact by the system.

## Attestations (Nth-Order)

An attestation is an assertion about another assertion:

- referential within the system
- affirms validity, truth, or control claims
- can recurse (attestation about attestation)

Example chain:

1. Alice asserts: *"The light is on"*
2. Bob attests: *"Alice's assertion is true"*
3. Carol attests: *"Bob's attestation is valid"*

Important:

> Attestations increase confidence, not truth by themselves.

## Recognition (Orthogonal to Attestation)

Recognition is actor-directed (not claim-directed) and creates standing.

Standing means the system treats an actor's assertions/actions as effective for specific purposes.

Example:

- Bob signs: *"Alice is reliable/authorized."*

Recognition can enable authorization or delegation policies, independent of any single fact claim.

## Standards: Turning Views into Facts

Evaluative statements become fact-capable when standards are applied.

Example:

- View: *"The light is too bright"*
- Standard: *Maximum brightness is 500 lux*
- Fact-capable claim: *"Brightness exceeds 500 lux"*

> Standards convert judgment into testable conditions.

## Acceptance and System Fact

A system-level fact emerges when:

- an assertion/attestation chain is accepted
- procedural inquiry is closed for the current context
- outcome is binding for action

Acceptance is:

- decisive
- context-specific
- operational (not metaphysical)

> A legal/system fact is reality as recognized by the system.

## Key Distinctions

- **State**: reality as it exists
- **Statement**: what is said about reality
- **Assertion**: a claim by an actor
- **Attestation**: vouching/qualification inside the system
- **Recognition**: standing granted to an actor
- **Acceptance**: system stop condition for action

## Acceptance Steps

Acceptance is a recursive resolution model that halts at first-order assertions.

![Acceptance Steps](./img/acceptance-steps.png)

## Synthesis

> The model explains how statements become assertions, assertions attract attestations, actors gain standing through recognition, and systems decide what counts as settled fact.

Or more sharply:

> Facts in a system emerge when the system stops asking questions.

## Safebox Implementation

Safebox implements this model for record acceptance and trust evaluation.

### Acceptance Stages

| No. | Stage | Confirmation | Success Criteria |
|---|---|---|---|
| 1 | Validated | Record is cryptographically correct | Signature validity checks pass |
| 2 | Attested | Owner attestation exists | Valid owner attestation event |
| 3 | Authorized | Actor appears in recognition/authorization policy | Membership or policy match |
| 4 | Trusted | Web-of-Trust or equivalent reputation policy | Score/policy threshold |

Acceptance is evaluated by the verifier. One or more stages may be required depending on verifier policy.

### Private Record Format

A **private record** is a signed [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) event embedded in a Safebox record payload rather than publicly posted to relays.

Private payloads are stored in Safebox as encrypted content (for example NIP-44 protected data) and may include structured record metadata.

### Attribution and Ownership Tags

Private records include tags such as:

- `["safebox", "<pubhex of safebox>"]`
- `["safebox_owner", "<pubhex of owner>"]`

Notes:

- `safebox` can be checked against event signer identity for consistency.
- `safebox_owner` must be independently verified.

Ownership attestation may be expressed using attestation events that bind owner identity to safebox control context (for example via deterministic tags such as `<safebox npub>:safebox-under-control` plus corresponding `p` tags).

### Trustworthiness

Trust scoring is verifier-controlled. A verifier may:

- use thresholds/scoring algorithms
- use allow/deny lists
- use Web-of-Trust policies

Trust policy remains local to the relying party unless explicitly federated.

### Verification Stages (Normative)

#### 1. Validated

Validation establishes technical integrity and MAY include:

- cryptographic signature checks
- hash/content identifier checks
- schema/format conformance
- metadata consistency checks (identifiers, timestamps, references)

Validation does not, by itself, establish entitlement or authority.

#### 2. Self-Presented

A record is self-presented when it is presented by the same holder/control context it was issued to.

This typically requires continuity of control proof (key/capability continuity).

#### 3. Attested

A record is attested when one or more independent parties provide verifiable assertions about:

- the record
- the presenter
- relevant attributes

Attestation is evidence, not automatic acceptance.

#### 4. Recognized

A record is recognized when attestations are accepted as effective within a defined realm (institution, network, community, jurisdiction, etc.).

Recognition may be time-limited, scoped, or revocable.

#### 5. Reputation (Optional)

Reputation may accumulate from repeated recognized interactions:

- can influence later decisions
- should remain advisory unless policy says otherwise
- should not replace validation or attestation requirements

### Stage Independence

- stages are distinct and should not be conflated
- validated does not imply recognized
- attested does not imply accepted
- reputation does not imply current authorization
