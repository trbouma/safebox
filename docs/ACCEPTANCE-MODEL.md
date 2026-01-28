# The Acceptance Model  
*A generic framework for how statements become facts*



---

## Overview

The **Acceptance Model** expresses a simple idea:

> **Facts and views are not established by the system; they exist outside in the world, and are known and resolved to be true about assertions made about them.**

Across law, governance, science, and technical systems, disputes rarely hinge on *what might be true in some ultimate sense*. Instead, they hinge on **what a system is prepared to treat as settled and binding**.

The Acceptance Model provides a **generic vocabulary** for understanding how that settlement and binding happens using a decentralized protocol like Nostr.

The Acceptance Model is useful whenever:
- Multiple actors make competing or complementary claims about reality (i.e., the world)
- Disagreement or uncertainty exists
- Decisions must be made despite incomplete knowledge
- A system must eventually **stop asking questions** about the world, but in a way that is resolvable, transparent, deterministic and binding.

This model can apply to many different situations and use cases:
- Courts determining legal facts
- Administrations making binding decisions
- Technical systems validating states
- Registries recording ownership or control
- Cryptographic systems finalizing transactions

The Acceptanc Model deliberately avoids metaphysics or morality; it does not ask *what is ultimately true*, but rather:

> **What must be accepted in order for a decision to be made and action to proceed?**

---

## Acceptance Model implemented using Nostr

The Acceptance Model is intended to be agnostic in its implementation, however, the simplicity of the Nostr Protocol enables exploration and demonstration of the model.

In the context of Nostr: 

- The **system** is the Nostr protocol consisting of its core primitives of **npubs** and **signed events**.
- The **world** is everything out there that exists independently of nostr and which may, or may not be expressed using nostr.

zEvery **system** that operates at scale (i.e., nostr protocol and its artifacts)  must answer three questions:

1. **What is being claimed?**
2. **Who vouches for this claim (and how)?**
3. **When does the system stop pursuing the question of system uncertainty regarding this claim?** 

The Acceptance Model structures those questions into clear layers, separating:
- Reality from language
- Claims from validation
- Trust in statements from trust in action
- Truth from recognition

---

## Core Concepts (Plain Definitions)

- **Claim** A claim is a declaration of a condition or configuration of reality at a given moment. A claim may be a **Fact** or a **View**

- **Fact** A fact is a claim related to a state of affairs that is defined in verifiable terms and is capable of being accepted as true by a system.

- **View** A view is a claim that is an evaluative interpretation of a state of affairs that depends on judgment, perspective, or normative criteria (standar) rather than the fact alone alone.

- **Assertion** A claim put forward as true by an actor, taking responsibility for its truth.

- **Attestation** An assertion that affirms the truth or validity of another assertion (event) or an actor (npub).

- **Acceptance**  A decision based on the evalution of system-level artefacts that concludes that a fact or view can be accepted.

---
## Recogition, Authority and Delegation

Recognition, delegation, and authority are often conflated, but the Acceptance Model treats them as distinct. Authority does not arise from delegation alone; it exists only where it is recognized. Delegation is an act by which one actor purports to transfer or confer authority, but that act has no effect unless a system accepts it. Recognition is the system’s determination that an asserted authority will be treated as operative. Authority, in turn, is not a substance that flows from one actor to another, but a condition that stabilizes once recognition occurs. In this sense, delegation proposes authority, recognition produces standing which makes it effective. Authority exists only to the extent of the standing of an actors that makes it effective.

**In the Acceptance Model, assertions introduce claims about facts and views, attestations qualify them, and recognition produces standing which is the precondition authority and delegation.**

## The Acceptance Model

### States, Assertions, Attestations, and Recognitions

| Level | Layer | Refers To | What It Is | Example |
|---|---|---|---|---|
| 0a | **Statement (Factual)** | Reality | Verifiable condition | The light is on |
| 0b | **Statement (Evaluative)** | Reality + judgment | Interpreted condition | The light is too bright |
| 1 | **Assertion** | State (0a or 0b) | A claim regarding a statement | Alice: “The light is on” |
| 2 | **Attestation (2nd Order Assertion)** | Assertion | Validity of an assertion | Bob: “Alice’s claim is true” |
| 3 | **Attestation (nth Order Assertion)** | Attestation | Validity of an attestation | Carol: “Bob’s attestation is valid” |
| — | **Recognition** | **Actor** | Recognizing another actor which may result in an authorization or delegation | Bob: “I recognize that Alice is competent and can do something on behalf of me” |
| — | **Acceptance** | Chain | System recognition/authorization | Condition of when system reaches a conclusion regarding a statement |

---
The following diagram is a logical graphical rendition of the above. It is intended to illustrate that:
- an **Assertion** is an assertion (signed event) about a **Statement**
- an **Attestation** is an assertiona (signed event) about an **Assertion** (another signed event)
- an **Recognition** is an assertion (signed event) recognizing another **Npub** which may result in an authorized or delegation.

For simplicity, the diagram does not illustrate **nth Order Assertions**.

![Acceptance Mode](./img/acceptance-model.png)

## Statement: Facts and Views

A **statement** is simply an expression of condition of affairs. It is **not automatically a fact**.

### Factual states
- Defined in verifiable terms
- Binary or measurable
- Capable of being true or false

Example:
- *The light is on*

### Evaluative statements (views)
- Incorporate judgment or perspective
- Depend on purpose, comfort, or norms
- Not verifiable without a standard

Example:
- *The light is too bright*

> **Facts require conditions; views require interpretation.**

---

## Assertions

An **assertion** is the first step where responsibility enters.

- Assertions may concern factual statements or evaluative statements
- Signing an event regard a **statement** becomes an **assertion**:
  - Binds it to an identity
  - Creates accountability regarding the **statement**
  - The act of signing an event does not itself create a fact; it creates another point to reach a conclusion.

Example:
- Alice signs: *“The light is on”*

This is an **assertion** (signed event), not itself a **fact**, though the system might lead to this conclusion.

---

## Attestations (Nth-Order)

An **attestation** is an assertion **about another assertion**.

- It is referential within the system.
- It affirms truth or validity.
- It can recurse until it reaches an **assertion**
- The result of the recursion may lead to the conclusion of a **fact**

Example recursion:
1. Alice asserts: *“The light is on”*
2. Bob attests: *“Alice’s assertion is true”*
3. Carol attests: *“Bob’s attestation is valid”*
4. It can be conclude that *“The light is on”* is a **fact** because it was signed by Alice, attested by Bob, in turn, attested by Carol.


Important limitation:

> **Attestations increase confidence, not truth.**

'Truth' or **fact** is anchored to an assertion which is a **statement** about a state.

Multiple attestations can increase 'truthiness', but is not truth itself.

---

## Recognition (Orthogonal to Attestation)

A **recognition** produces **standing** of another **actor** which is the start of authority and/or delegation.

**Standing** is the condition created when the system recognizes an actor as one whose assertions or actions will be treated as effective.

- Actor-directed, not claim-directed
- Generalizes trust across future assertions
- Operates independently of specific facts

Example:
- Bob signs: *“Alice is reliable”*

A **recognition** is a type of assertion that produces standing of another **actor** for the purposes of **authorization** or **delegation**.

---

## Standards: Turning Views into Facts

Evaluative states become fact-capable only when a **standard** is applied.

Example:
- View: *“The light is too bright”*
- Standard: *Maximum brightness is 500 lux*
- Fact-capable claim: *“The light exceeds 500 lux”*

> **Standards convert judgment into testable conditions.**

This is how law, engineering, and governance discipline opinion.

---

## Acceptance and Legal Fact

A **fact (legal or system-level)** emerges when:

- A system accepts an assertion or attestation chain
- Further inquiry is procedurally closed
- The outcome becomes binding for action

Acceptance is:
- Decisive
- Context-specific
- Independent of metaphysical certainty

> **A legal fact is reality as recognized by the system, not reality itself.**

---

## Key Distinctions (Summary)

- **State** → what is actually reality - in the form of a **Fact** or **View**
- **Statement** → what is said about reality (fact or view)  
- **Assertion** → what is claimed of the world by an actor
- **Attestation** → what is vouched for in the system.  
- **Acceptance** → what can be deterministically and reliably resolved by the system

---
## Acceptance Steps

The acceptance steps is a (recursive) resolution model that halts at a first order assertion.

Below is an initial resolution model

![Acceptance Steps](./img/acceptance-steps.png)

## Synthesis

> **The Acceptance Model explains how statements become assertions, assertions attract attestations, delegations of actors by other actors, and systems ultimately decide which claims count as facts.**

Or more sharply:

> **Facts in the system emerge when the system stops asking questions.**

## Safebox Implementation of the Acceptance Model

Safebox provides an implementation of the acceptance model.

## Acceptance

`Acceptance` is the more generalized notion of `verification` and is performed in three discrete steps:

|No.|Step|Confirmation|Success Criteria|
|---|---|---|---|
|1.|Validated|The record is cryptographically correct|Successful signature validity check|
|2.|Attested|An attestion record signed by the owner referred to by the safebox|Valid owner attestation event|
|3.|Authorized|Member of list for authorization/recognition|Membership in List|
|4.|Trusted|Web of Trust |Score|

`Acceptance` is based on the evaluation of the above steps and is solely in the eyes of the verifier if one or several of the above steps are successful.


### Private Record Format

A **private record** is a signed event as per [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) that is embedded in a safebox record. This embedded record or payload can be considered a **private record** because it is not published to any relay; rather it stored as a safebox record payload and stored as a NIP-44 encrypted event.

### Attribution and Ownership
For attribution and ownership, two tags are added to each private record: `["safebox", "<pubhex of safebox>"]` and `["safebox_ower", <pubhex of purported safebox owner ]`

The `["safebox", , "<pubhex of safebox>"]` tag is easily validated because it should be the same as the `pubhex` that has signed the event. While this data might be considered redundant, the `["safebox"]` tag indicates that the the signed event should be considered and handled as a **private record** according to this specification.

The `["safebox_ower", <pubhex of purported owner ]` must be verified independently, because the safebox could add any owner to the private record. This independent verification is done using the [Attestations NIP](https://nostrhub.io/naddr1qvzqqqrcvypzp384u7n44r8rdq74988lqcmggww998jjg0rtzfd6dpufrxy9djk8qy28wumn8ghj7un9d3shjtnyv9kh2uewd9hsqrrpw36x2um5v96xjmmwwvuhdk8z) where the owner, using their `nsec' must sign a `31871' event attesting that they 'own' or control the safebox in question. 

This is done by creating a `d-tag` of the format: `"<safebox npub>:safebox-under-control"` to indicate which safebox instance is under the control of the owner (they may have many safeboxes under their control). The p-tag is populated as: `["p", f"<safebox pubhex"]` (note the pubhex format, instead of npub).

For additional context info, the `content` field may be populated as such: `"Npub holder: <npub owner> has attested ownership of safebox: <npub safebox> "`

This attestation event must be signed and published by the `<npub owner>`. During a verification process, there is step to retrieve this event to confirm that the safebox is indeed controlled by the owner that it claims.

### Trustworthiness

It is up to the verifier to decide the trustworthiness of a npub. This should be under the sole discretion of the verifier: they may use a scoring algorithm and threshold value to determine trustworthiness, or, referencing a list of which a npub is a member.



## Nostr Safebox Implementation

### Private Record Issuance
Nostr Safebox can issue private records. Private records are issued using the NIP-01 format with the following

Private record tags

The following tags are added to the private record:

`[["safebox", <pubkeyhex of safebox instance issuing the record>], ["safebox_owner", <pubkeyhex of safebox owner>],["safebox_holder", <pubkeyhex of safebox instance holding the private record]]`



### Verification Stages

This specification defines a staged verification model for records, progressing from technical integrity to social standing. Each stage answers a distinct question and may be evaluated independently. Failure at any stage does not imply failure at subsequent stages unless explicitly required by the relying party.

#### 1. Validated

A record is Validated if its internal integrity can be established.

Validation MUST include, as applicable:
	- Verification of cryptographic signatures
	- Verification of hashes or content identifiers
	- Conformance to required schemas or formats
	- Consistency of metadata (e.g., identifiers, timestamps)

Validation establishes that the record is technically sound.
Validation alone DOES NOT establish identity, authorship, entitlement, or authority.

⸻

#### 2. Self-Presented

A record is Self-Presented if it is presented by the same entity to whom the record was issued.

Self-presentation MUST demonstrate continuity of control between issuance and presentation, typically through proof of control over the same cryptographic key, credential, or capability bound to the record at issuance.

Self-presentation MUST NOT rely on delegation, proxy, or bearer transfer unless explicitly permitted by the record’s issuance policy.

Self-presentation establishes agency: the record is not only valid, but presented by its rightful holder.

⸻

#### 3. Attested

A record is Attested if one or more third parties have made explicit assertions regarding the record, its presenter, or associated attributes.

Attestations:
	- MAY assert facts, claims, or assessments
	- MUST be independently verifiable
	- MAY be additive and multiple

Attestation DOES NOT imply acceptance or standing; it represents witnessed or asserted information only.

⸻

#### 4. Recognized

A record is Recognized if one or more attestations are accepted as effective within a defined realm.

Recognition is context-dependent and MAY vary across jurisdictions, institutions, platforms, or communities. Recognition MAY be time-limited or revocable.

Recognition establishes standing: the record and its attestations are treated as meaningful for a given purpose within a specific realm.

⸻

#### 5. Reputation (Optional)

A record, presenter, or attester MAY accrue Reputation through repeated recognition over time.

Reputation:
	•	Is derived from historical interactions, outcomes, or reliance
	•	MAY influence future recognition decisions
	•	MUST NOT substitute for validation, self-presentation, or attestation

Reputation represents accumulated standing rather than a discrete verification event and is inherently non-portable across realms unless explicitly recognized.

⸻

Notes on Independence
	•	Each stage addresses a distinct verification concern and MUST NOT be conflated.
	•	A record MAY be validated but not self-presented.
	•	A record MAY be attested but not recognized.
	•	Reputation MUST be treated as advisory unless explicitly required by policy.

