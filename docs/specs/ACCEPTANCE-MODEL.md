# The Acceptance Model
*A generic framework for how statements become system facts*

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

This specification updates the model by integrating two concrete Nostr-facing structures:

- the [**Attestations Custom Protocol**](https://nostrhub.io/naddr1qvzqqqrcvypzp384u7n44r8rdq74988lqcmggww998jjg0rtzfd6dpufrxy9djk8qyfhwumn8ghj7un9d3shjtnyv9ujuct89uqqcct5w3jhxarpw35k7mnnaawl4h), which standardizes attestation, attestation requests, and attestor recommendations
- [**NIP-85 Trusted Assertions**](https://nostrhub.io/naddr1qvzqqqrcvypzp384u7n44r8rdq74988lqcmggww998jjg0rtzfd6dpufrxy9djk8qyfhwumn8ghj7un9d3shjtnyv9ujuct89uqqcct5w3jhxarpw35k7mnnaawl4h), which standardize advisory reputation-style calculations used at scale

Taken together, these mechanisms explain how decentralized systems transform raw statements into operationally settled outcomes that are sufficient for taking action.

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
- validation from verification
- trust in statements from trust in action
- truth from recognition

## Core Concepts

- **Statement**: A raw expression about reality at a point in time. Statements may be factual or evaluative.
- **Claim**: A statement that is being proposed for system consideration.
- **Fact**: A claim that is defined in verifiable terms and can be accepted as true by a system.
- **View**: A claim that depends on judgment, perspective, or norms rather than factual conditions alone.
- **Assertion**: A claim put forward by an actor as true, with responsibility attached.
- **Validated Assertion**: An assertion that has been determined to be internally consistent, properly formed, and compliant with applicable rules, schema, or logical constraints.
- **Verified Assertion**: An assertion that has been confirmed as congruent with the relevant state of affairs, whether by observation, authoritative record, reliable attestation, or other accepted means of establishing correspondence.
- **Attestation**: An assertion about another assertion or actor (for example, validity, invalidity, revocation, or control).
- **Recognition**: A system-level decision to treat an actor as having standing.
- **Trusted Assertion**: A signed calculation or reputation-style output published by a designated service or authority and used as advisory input.
- **Acceptance**: A system-level decision to treat a claim-chain as operationally resolved.
- **System Fact**: A claim that has passed through the system’s required validation, attestation, recognition, and trust stages and is therefore treated as settled and actionable.

## Validation and Verification

In this model, **validation** and **verification** are not synonyms.

Safebox uses them in the following sense:

- **Validated**
  - internally consistent
  - rule-conformant
  - structurally correct
- **Verified**
  - checked against the relevant state of affairs
  - congruent with operative reality

This yields a deliberate distinction:

| Term | Meaning in this model | Main question |
|---|---|---|
| Validated | Conforms to expected rules, schema, logic, or internal consistency | “Does this hold together correctly?” |
| Verified | Congruent with the relevant world, record, event, or operative state of affairs | “Is this actually so?” |

This is a stronger epistemic distinction than the more common narrow software usage.

### Compact Formulation

> Validation asks whether the claim fits the system. Verification asks whether the claim fits the world.

Or, stated more compactly:

- validation = coherence test
- verification = correspondence test

### Drafting Note

Some technical readers may expect different terminology, especially in cryptography and software engineering, where:

- verification often means signature or proof checking
- validation often means rule, schema, or business-logic checking

This specification intentionally uses:

- **validation** for internal correctness and rule-conformity
- **verification** for correspondence with the relevant state of affairs

Those terms should therefore be read in that sense throughout this model.

### Why the Distinction Matters

This distinction separates three different questions:

1. coherence
2. correspondence
3. acceptance

That means an assertion may be:

- validated but not verified
- verified but not yet accepted
- accepted without being fully verified
- legally or institutionally recognized despite imperfect verification

This is useful in legal, records, and institutional systems, where system action often depends on more than one kind of sufficiency.

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

The layers above describe the conceptual relationship between statements, assertions, attestations, recognition, and acceptance. In implementation contexts, these layers are evaluated through explicit stage and policy checks rather than a single fixed graph.

## Foundation: Statements and Assertions

The first layer of the model concerns raw language about reality.

### Statements

A statement is an expression about conditions. It is not automatically a fact.

Statements may be:

- **factual**
  - defined in verifiable terms
  - measurable or binary
  - true/false capable
- **evaluative**
  - include judgment or perspective
  - depend on purpose, comfort, or norms
  - require a standard to become fact-capable

Examples:

- Factual statement: *"The light is on"*
- Evaluative statement: *"The light is too bright"*

### Assertions (Level 1)

An assertion is a signed statement for which an actor takes responsibility.

- assertions may concern facts or views
- a signed event binds the claim to an identity
- signing creates accountability, not truth

Example:

- Alice signs: *"The light is on"*

This is an assertion. It may later be accepted as a fact by the system.

> A statement becomes an assertion when an actor signs it and assumes accountability for it.

### Example: Validation vs Verification

Claim:

- “Invoice #123 is paid.”

Validated:

- invoice identifier exists
- required fields are present
- amount format is correct
- referenced payment record is properly linked

This means the claim is systemically coherent.

Verified:

- settlement actually occurred
- payment was received by the payee
- the operative state of affairs is in fact “paid”

This means the claim is congruent with the relevant state of affairs.

## Verification Layer: Attestations (Nth-Order)

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

### Standardized Attestation Primitives

The **Attestations Custom Protocol** provides explicit event structures for this layer:

Reference:

- [Attestations Custom Protocol](https://nostrhub.io/naddr1qvzqqqrcvypzp384u7n44r8rdq74988lqcmggww998jjg0rtzfd6dpufrxy9djk8qyfhwumn8ghj7un9d3shjtnyv9ujuct89uqqcct5w3jhxarpw35k7mnnaawl4h)
- [NIP-85 Trusted Assertions](https://nostrhub.io/naddr1qvzqqqrcvypzp384u7n44r8rdq74988lqcmggww998jjg0rtzfd6dpufrxy9djk8qyfhwumn8ghj7un9d3shjtnyv9ujuct89uqqcct5w3jhxarpw35k7mnnaawl4h)

- **Kind 31871**: Attestation Event
  - a signed attestation about an assertion or related claim
  - may communicate validity, invalidity, or revocation
- **Kind 31872**: Attestation Request
  - a request for verification or evaluation of a subject claim
- **Kind 31873**: Attestor Recommendation
  - a recommendation that a given attestor is suitable for evaluating specific subjects or event types

These structures formalize Level 2 and Level 3 of the Acceptance Model.

They also extend the model beyond passive evaluation by allowing systems to ask:

- who should verify this?
- how is a verifier discovered?
- what is the attestation status of the subject assertion?

## Standing Layer: Recognition and Authorization

Recognition is actor-directed (not claim-directed) and creates standing.

Standing means the system treats an actor's assertions/actions as effective for specific purposes.

Example:

- Bob signs: *"Alice is reliable/authorized."*

Recognition can enable authorization or delegation policies, independent of any single fact claim.

In Safebox and similar systems, this is the **Authorized** stage:

- the subject actor or issuer must appear in a recognition or authorization policy
- if the actor lacks standing, their otherwise valid records may still be rejected

Recognition is therefore orthogonal to the truth of a claim. It governs whether the actor has standing in the relevant system realm.

## Evaluation Layer: Trusted Assertions and Reputation

At scale, systems often need advisory inputs that are too expensive or dynamic to recompute inline for every decision.

**NIP-85 Trusted Assertions** provide a standardized way to publish such inputs.

Trusted assertion providers publish signed calculations such as:

- user rank
- follower count
- zap metrics
- other thresholdable or score-based signals

Relevant structures include:

- **Kind 30382**: user-scoped trusted assertions
- **Kind 30383**: event-scoped trusted assertions

These are not final determinations by themselves. They are advisory inputs used by the verifier to decide whether the subject meets the system’s required trust threshold.

In the Acceptance Model:

- recognition determines whether an actor has standing
- trusted assertions contribute reputation or scoring data
- verifier policy decides whether those scores are sufficient

This is the **Trusted** stage in implementation terms.

## Standards: Turning Views into Facts

Evaluative statements become fact-capable when standards are applied.

Example:

- View: *"The light is too bright"*
- Standard: *Maximum brightness is 500 lux*
- Fact-capable claim: *"Brightness exceeds 500 lux"*

> Standards convert judgment into testable conditions.

## Finality: Acceptance and System Fact

A system-level fact emerges when:

- an assertion/attestation chain is accepted
- procedural inquiry is closed for the current context
- outcome is binding for action

Acceptance is:

- decisive
- context-specific
- operational (not metaphysical)

> A legal/system fact is reality as recognized by the system.

Acceptance is the stop condition:

- the verifier stops asking further questions
- the claim-chain is treated as settled for the current purpose
- the system proceeds

This does not mean the claim is metaphysically or universally true. It means the system has enough validated, attested, authorized, and trusted material to act.

## Implementation Summary

The Acceptance Model can be implemented as a staged pipeline:

| Stage | Description | Technical Primitive |
| :--- | :--- | :--- |
| **Validated** | Internal correctness, structural integrity, and rule-conformity. | Signature, schema, and system-rule checks. |
| **Verified** | Congruence with the relevant world, record, event, or operative condition. | Observation, authoritative record, reliable attestation, or accepted correspondence check. |
| **Attested** | Independent parties vouch for the claim. | Kind 31871 Attestation Event. |
| **Authorized** | Actor has standing in the system. | Recognition or policy match. |
| **Trusted** | Reputation or Web-of-Trust thresholds met. | NIP-85 Trusted Assertions, e.g. Kind 30382 or Kind 30383. |
| **Accepted** | System stops asking questions and proceeds. | Verifier stop condition. |

## Key Distinctions

- **State**: reality as it exists
- **Statement**: what is said about reality
- **Assertion**: a claim by an actor
- **Attestation**: vouching/qualification inside the system
- **Recognition**: standing granted to an actor
- **Acceptance**: system stop condition for action

## Acceptance Steps

Acceptance is a recursive resolution model that halts when the verifier has enough information to act.

In implementation terms, the verifier evaluates a claim-chain through these steps:

1. **Validated**
   - the record or assertion is structurally and cryptographically valid
2. **Attested**
   - one or more competent parties vouch for the claim, issuer, or chain status
3. **Authorized**
   - the relevant actor has standing under the applicable recognition or authorization policy
4. **Trusted**
   - advisory trust or reputation thresholds are satisfied where policy requires them
5. **Accepted**
   - the verifier stops asking further questions and treats the matter as settled for action

Not every verifier requires every stage in every case. The required stop condition is policy-specific.

## Synthesis

> The model explains how statements become assertions, assertions attract attestations, actors gain standing through recognition, and systems decide what counts as settled fact.

Or more sharply:

> Facts in a system emerge when the system stops asking questions.

## Safebox Implementation

Safebox implements this model for record acceptance and trust evaluation.

### Acceptance Stages

| No. | Stage | Confirmation | Success Criteria |
|---|---|---|---|
| 1 | Validated | Record is internally coherent | Signature, schema, and structural checks pass |
| 2 | Verified | Record corresponds to the relevant operative state of affairs | Verification method defined by context |
| 3 | Attested | Owner or independent attestation exists | Valid Kind 31871 attestation event or equivalent attestation evidence |
| 4 | Authorized | Actor appears in recognition/authorization policy | Membership, standing, or policy match |
| 5 | Trusted | Web-of-Trust or trusted-assertion threshold is met | NIP-85-style score or policy threshold satisfied |
| 6 | Accepted | Verifier stops asking questions and proceeds | Stop condition reached for the current action |

Acceptance is evaluated by the verifier. One or more stages may be required depending on verifier policy.

## Synthesis

The updated Acceptance Model can be read as a layered system:

1. **Statements and Assertions**
   - raw statements become accountable assertions when signed
2. **Attestations**
   - other actors vouch for, reject, or revoke those assertions
3. **Recognition**
   - the system determines whether actors have standing
4. **Trusted Assertions / Reputation**
   - advisory scoring and reputation signals are incorporated
5. **Acceptance**
   - the system treats the claim-chain as sufficiently settled to act

In decentralized systems, the resulting system fact is not ultimate truth. It is a claim that has passed the required stages and is therefore treated as settled and actionable.

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
