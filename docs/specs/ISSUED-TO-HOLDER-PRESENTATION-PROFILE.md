# Issued-to-Holder Presentation Profile

## Overview

This specification defines a generic acceptance profile for a common record flow:

1. an issuer issues a record to a holder
2. the holder stores the record in their Safebox
3. the holder presents the record to a verifier
4. the verifier confirms:
   - the record is valid
   - the presenter is the same holder to whom the record was issued
   - the issuer is recognized under a specified root authority list

This profile is intentionally generic. It does not assume a medical, legal, employment, or educational domain. It is intended as a reusable baseline profile for any "issued to person A, presented by person A to person B" scenario.

## Scope

This specification covers:

- issuer, holder, presenter, and verifier roles
- required record tags and identity semantics
- minimum verification checks for acceptance
- how root-authority recognition is applied to the issuer
- how holder continuity is applied at presentation time

This specification does not define:

- domain-specific schemas
- revocation policy
- expiration or freshness policy
- institution-specific trust governance
- weighted or thresholded reputation policy

## Roles

- **Issuer**
  - the actor who signs and issues the record
- **Holder**
  - the actor to whom the record is issued
- **Presenter**
  - the actor who actively presents the record to the verifier
- **Verifier**
  - the actor or system evaluating whether the record is sufficient for action

In the normal case for this profile:

- holder = presenter

## Identity Neutrality

Nostr and Safebox are intentionally designed not to discriminate between `npub` identities based on role.

Within this profile:

- an issuer is an `npub`
- a holder is an `npub`
- a presenter is an `npub`
- a verifier is an `npub`

These are functional roles in a flow, not privileged identity classes at the protocol layer.

Safebox follows the same design principle:

- a Safebox instance exists on par with an `npub`
- that `npub` may happen to be used as a social identity by a person
- but the system does not assume that every `npub` is a natural person
- and it does not grant different base-protocol treatment to issuers, holders, or verifiers solely because of role naming

More generally, the protocol layer does not distinguish between whether an `npub` is being used by:

- a human being
- an agent
- a software service
- a hardware device
- a Safebox instance acting as an operational identity

All of these are peers at the identity layer.

That means:

- a device can issue
- an agent can hold
- a person can verify
- a Safebox service identity can attest

without any protocol-level class change being required.

The system therefore treats `npub` as the base unit of accountable identity, while leaving social, legal, institutional, or operational interpretation to higher layers.

If a verifier wants to know whether an issuer is:

- a doctor
- a ministry
- a person
- a device
- a regulated institution

that distinction must be established through:

- attestation
- recognition
- policy
- trusted assertions
- application-layer semantics

It is not established merely by the existence of an `npub`.

This neutrality is deliberate. Trust, recognition, attestation, and policy are layered on top of identity, rather than built into identity class distinctions.

## Required Record Semantics

The record is expected to carry these identity semantics:

- `safebox_owner`
  - the issuer identity
- `safebox_holder`
  - the intended holder identity

Additional tags may be present, but this profile depends on those two semantics.

### Issuer

The issuer is the actor whose key signs the record payload and is represented as:

- the event pubkey
- plus the `safebox_owner` tag for issuer identity semantics in the application layer

### Holder

The holder is the intended recipient of the issued record and is represented as:

- `safebox_holder`

## Acceptance Requirements

A verifier applying this profile MUST confirm all of the following before treating the record as accepted for action.

### 1. Record Validity

The record MUST be parseable as a Nostr event and MUST pass signature validation.

Safebox implementation:

- `Validated`

### 2. Holder Continuity

The verifier MUST confirm that the presenter is the same holder identified in the record.

In live presentation flows, this means:

- presenter identity equals `safebox_holder`

Safebox implementation:

- `Self-Presented == true`

This is the primary mechanism for confirming that the record is being presented by the intended holder.

### 3. Issuer Recognition

The verifier MUST confirm that the issuer is part of a specified root-authority recognition set.

Under the current Safebox implementation, this means:

- the issuer appears in the expanded trusted entity set derived from:
  - configured root authorities
  - plus first-hop kind-3 follow edges from those root authorities

Safebox implementation:

- `Recognized == true`
- `Recognized By` shows the recognizing root authority display names where available

### 4. Optional Owner Attestation

The verifier MAY require the issuer to have attested ownership/control of the issuing Safebox.

Safebox implementation:

- `Attested By Owner == true`

This is a stronger profile variant. It is not strictly required for the generic baseline profile unless verifier policy says it is required.

## Minimum Acceptance Rule

The minimum acceptance rule for this profile is:

1. `Validated == true`
2. `Self-Presented == true`
3. `Recognized == true`

If all three conditions are satisfied, the verifier MAY accept the record for generic issued-to-holder presentation purposes.

## Stronger Acceptance Rule

A verifier that wants stronger assurance MAY require:

1. `Validated == true`
2. `Self-Presented == true`
3. `Recognized == true`
4. `Attested By Owner == true`

This variant is appropriate when the verifier wants both:

- holder continuity
- issuer control continuity

## Recognition Policy

This profile assumes the verifier has selected a root-authority list in advance.

That list is verifier policy, not record content.

The record is not trusted simply because the issuer says it should be trusted. The issuer is trusted only if the verifier’s configured root-authority policy recognizes the issuer.

## Presentation Semantics

This profile applies to live presentation, not just stored display.

The critical acceptance question is:

> Is the current presenter the same actor to whom this record was issued?

That question is answered in Safebox live presentation flows by:

- comparing presenter identity to `safebox_holder`

Stored-record views use:

- `Held By Current Safebox`

but that is not a substitute for live presentation holder continuity.

## Advisory Signals

Trusted assertion providers and WoT scores MAY be shown to the verifier, but they are advisory under this profile.

Safebox implementation:

- `Issuer WoT Scores`

These scores:

- may inform manual or policy decisions
- do not replace the required validity, holder, and recognition checks

## Non-Goals

This profile does not attempt to answer:

- whether the record content is substantively true
- whether the issuer is licensed for a specific profession
- whether the record is fresh, current, or unrevoked
- whether the record satisfies a domain-specific policy regime

Those are higher-order profiles built on top of this one.

## Current Safebox Mapping

This profile maps cleanly onto current Safebox verification output for live request/presentation flows:

- `Valid`
- `Self-Presented`
- `Attested By Owner`
- `Recognized`
- `Recognized By`
- `Issuer WoT Scores`

Recommended verifier interpretation for the generic profile:

- required:
  - `Valid`
  - `Self-Presented`
  - `Recognized`
- optional stronger requirement:
  - `Attested By Owner`

## Security Considerations

- recognition is verifier-local policy, not issuer-controlled policy
- `Self-Presented` is the key control for holder continuity in live flows
- recognition alone does not prove holder continuity
- holder continuity alone does not prove issuer legitimacy
- advisory WoT scores do not replace required checks
- this profile does not currently define revocation or expiry semantics

## Implementation References

- `docs/specs/RECORD-PRESENTATION-NAUTH-STRATEGY.md`
- `docs/specs/WOT-ATTESTATION-AND-RECORD-VERIFICATION.md`
- `docs/specs/ACCEPTANCE-MODEL.md`
- `app/records_verification.py`
- `app/routers/records.py`
- `safebox/acorn.py`
- `safebox/func_utils.py`
