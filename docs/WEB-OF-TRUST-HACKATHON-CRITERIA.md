# Web of Trust Hackathon Criteria

This document captures the evaluation criteria shown in the shared hackathon judging slide.

## Evaluation Criteria

| Metric | What Judges Look For |
|---|---|
| Functional Readiness | End-to-end demo, secure key handling, polished UI (if applicable) |
| Depth & Innovation | Novel and creative strategies to advance the core mission |
| Interoperability | Full compliance with WoT-Protocols including NIP-85 (kinds 30382 & 10040), clean REST/Nostr API, and ability to exchange data with other submissions |
| Decentralizing Ecosystem Impact | Potential to become a reusable building block for nostr clients |
| Documentation & Openness | Clear README, architecture diagrams, tests, and license. etc |
| Business Model Sustainability | Ability to maintain sats flow after the wotathon |

## Notes

- This is a reference transcription of the criteria shown in the shared image.
- If the organizers publish an official written version, that version should take precedence over this transcription.

## Safebox Mapping

The following is a short mapping from the judging criteria to the current Safebox work.

### Functional Readiness

- end-to-end QR, NFC, payment, offer, grant, and record-presentation flows already exist
- secure key handling is reflected in the secret-file hardening, bootstrap controls, and fail-closed startup behavior
- web UI exists across wallet, access, records, trust, and presentation flows

Key references:

- `docs/specs/OFFERS-AND-GRANTS-FLOWS.md`
- `docs/specs/RECORD-PRESENTATION-NAUTH-STRATEGY.md`
- `docs/specs/PAYMENTS-SAFEBOX-CASHU-LIGHTNING-FALLBACK.md`
- `docs/devops/zero-config-docker-bootstrap-and-production-path.md`

### Depth & Innovation

- Safebox combines wallet, records, attestation, trust, and agent flows in one system
- the acceptance-model and issued-to-holder profiles give a generalized trust framework, not just an app-specific workflow
- hybrid QR/NFC/bootstrap plus secure transmittal model is broader than a single-purpose credential flow

Key references:

- `docs/specs/ACCEPTANCE-MODEL.md`
- `docs/specs/ISSUED-TO-HOLDER-PRESENTATION-PROFILE.md`
- `docs/specs/AGENT-FLOWS.md`

### Interoperability

- Safebox uses Nostr events, relays, and explicit attestation/trust structures
- trusted assertion provider support is implemented through the current `npub:tag[:relay]` WoT-provider model
- REST endpoints and websocket flows are already part of the application surface

Key references:

- `docs/specs/WOT-ATTESTATION-AND-RECORD-VERIFICATION.md`
- `docs/specs/AGENT-API.md`
- `docs/specs/NAUTH-PROTOCOL.md`

### Decentralizing Ecosystem Impact

- Safebox is designed as reusable infrastructure for records, attestation, and trust evaluation
- the profile/spec approach is meant to support generic issuance and presentation, not just one vertical
- the system treats `npub` identities neutrally across people, agents, services, and devices

Key references:

- `docs/specs/SAFEBOX-ALTERNATIVE-ECOSYSTEM-APPROACH.md`
- `docs/specs/ISSUED-TO-HOLDER-PRESENTATION-PROFILE.md`
- `docs/specs/AGENT-API.md`

### Documentation & Openness

- the repo includes specs, operator guides, devops docs, test plans, and implementation notes
- recent trust and verification behavior is now documented explicitly

Key references:

- `docs/specs/INDEX.md`
- `docs/specs/WOT-ATTESTATION-AND-RECORD-VERIFICATION.md`
- `docs/operators/ms02-agent-operator-guide.md`

### Business Model Sustainability

- Safebox already includes sats-native payment and Lightning-address flows
- agent-to-agent and human-to-human exchange patterns are documented as market-capable flows
- the architecture is capable of supporting reusable payment-bearing service patterns

Key references:

- `docs/specs/PAYMENTS-SAFEBOX-CASHU-LIGHTNING-FALLBACK.md`
- `docs/specs/EMERGENT-MARKETS-OVER-SAFEBOX.md`
- `docs/specs/mkt/MS-02-entitlement-market.md`

## Planned Demo Script

### Title

- Issue, Hold, Present, Verify

### Goal

Show that:

- one user can issue a signed record to another user
- the holder can present that record to a verifier
- the verifier can confirm:
  - the record is valid
  - the presenter is the intended holder
  - the issuer is recognized in the verifier’s configured Web of Trust

### Actors

- `Issuer`
- `Holder`
- `Verifier`

### Preconditions

- `Verifier` has already configured:
  - root authorities
  - optional trusted assertion providers
- `Issuer` is recognized through the verifier’s configured root-authority list
- all three actors already have Safebox instances and are logged in

### Record Type

Use a simple signed record such as:

- `Access Pass`
- `Member Credential`
- `Proof of Attendance`

### Demo Flow

1. **Issuer issues the record to Holder**
   - issuer opens the record issue/offer flow
   - issuer selects a simple record
   - issuer sends it to holder
   - holder receives and stores it

2. **Holder presents the record to Verifier**
   - holder opens the received record
   - holder selects the presentation flow
   - verifier scans or accepts the live presentation

3. **Verifier reads the verification panel**
   - verifier sees:
     - `Valid`
     - `Self-Presented`
     - `Recognized`
     - optionally `Attested By Owner`
     - `Recognized By`
     - `Issuer WoT Scores`

### Success Criteria

The demo is successful if the verifier can see:

- `Valid = true`
- `Self-Presented = true`
- `Recognized = true`

Optional stronger result:

- `Attested By Owner = true`

### Suggested Spoken Script

- “First, an issuer gives a signed record to a holder.”
- “Second, the holder presents that same record to a verifier.”
- “Third, the verifier confirms that the record is valid, that it is being presented by the intended holder, and that the issuer is recognized in the verifier’s Web of Trust.”

## Stage Demo Card

### Total Time

- target: under 2 minutes

### 0:00-0:20 Setup Line

Action:

- briefly identify the three actors on screen:
  - `Issuer`
  - `Holder`
  - `Verifier`

Say:

- “This is a generic Web of Trust flow: one user issues a signed record to another user, and that holder presents it to a verifier who has already configured a Web of Trust.”

### 0:20-0:45 Issue

Action:

- issuer sends a simple signed record to holder
- holder receives it

Say:

- “First, the issuer creates and sends a signed record to the holder.”

Callout:

- “The holder now has the issued record in their Safebox.”

### 0:45-1:15 Present

Action:

- holder opens the record
- holder starts presentation
- verifier scans or accepts the presentation

Say:

- “Now the holder presents that exact record to the verifier.”

Callout:

- “This is a live presentation flow, not just a static file handoff.”

### 1:15-1:45 Verify

Action:

- keep focus on verifier screen
- point to verification output

Say:

- “The verifier can now confirm three things: the record is valid, it is being presented by the intended holder, and the issuer is recognized in the verifier’s Web of Trust.”

Call out these fields:

- `Valid`
- `Self-Presented`
- `Recognized`

Optional callout:

- `Attested By Owner`
- `Recognized By`
- `Issuer WoT Scores`

### 1:45-2:00 Close

Say:

- “So in under two minutes, we’ve shown issuance, holder continuity, and issuer recognition using a reusable Web of Trust verification model.”

### Hard Success Criteria

For the demo to count as complete on stage, the verifier must visibly show:

- `Valid = true`
- `Self-Presented = true`
- `Recognized = true`

### Backup Simplicity Rule

If time is tight:

- use a single pre-created simple record
- skip explaining optional WoT scores
- focus only on:
  - issuance
  - presentation
  - `Valid`
  - `Self-Presented`
  - `Recognized`

## Presenter Checklist

Use this as the short stage-facing version.

### Before Going Live

- verifier has WoT configured
- issuer is already recognized by verifier roots
- holder already has a working Safebox session
- simple record is ready

### Demo Sequence

1. show `Issuer`, `Holder`, `Verifier`
2. issuer sends record to holder
3. holder confirms record received
4. holder starts presentation
5. verifier accepts/scans presentation
6. stop on verifier screen

### Say

- “Issuer sends a signed record to Holder.”
- “Holder presents that same record to Verifier.”
- “Verifier confirms the record is valid, self-presented, and issued by a recognized issuer.”

### Point To

- `Valid`
- `Self-Presented`
- `Recognized`

### Optional Point To

- `Attested By Owner`
- `Recognized By`
- `Issuer WoT Scores`

### End Line

- “This shows issuance, holder continuity, and Web of Trust issuer recognition in one reusable flow.”

## Two-Minute Overview Script

Use this before the live demo.

“Safebox is a Nostr-native wallet and records system designed around a simple idea: an `npub` is the base unit of accountable identity, whether it is used by a person, an agent, a service, or a device.

That matters for Web of Trust because it lets us build trust as a protocol layer on top of identity, instead of hard-coding special identity classes into the system.

In Safebox, trust is evaluated in stages.

First, a record must be valid: it has to parse correctly as a signed Nostr event and pass signature verification.

Second, the issuer can be attested as the owner of the Safebox that issued the record.

Third, the issuer can be recognized through a verifier-configured root authority list. In our current implementation, that means the verifier chooses root authorities, and Safebox expands trust from those roots through contact-list relationships.

Fourth, the verifier can also see advisory trusted assertion signals, such as NIP-85-style scores, without confusing those scores with core validity or authorization.

So the model is: valid, attested, recognized, and optionally trusted.

The important point is that acceptance is local to the verifier. Safebox does not decide ultimate truth. It gives the verifier enough structured evidence to stop asking questions and act.

In the demo, we’ll show a simple issued-to-holder presentation flow.

One user issues a signed record to another user. That holder then presents the record to a verifier who has already configured a Web of Trust. The verifier will be able to confirm three things live: that the record is valid, that it is being presented by the intended holder, and that the issuer is recognized in the verifier’s root-authority trust set.

That gives us a reusable building block for credentials, access records, attestations, and other person-to-person or agent-to-agent trust flows on Nostr.”

## Suggested Slides

### Slide 1: Title

- `Safebox: Web of Trust Record Verification`
- subtitle:
  - `Issued, Held, Presented, Verified`

Suggested content:

- Safebox logo
- one-sentence framing:
  - `A Nostr-native wallet and records system with staged trust verification.`

### Slide 2: Core Idea

Title:

- `Identity Neutrality`

Suggested content:

- `npub = base unit of accountable identity`
- no protocol distinction between:
  - person
  - agent
  - service
  - device
  - Safebox instance

Suggested visual:

- a simple row of icons or labels showing different actors using the same `npub` model

### Slide 3: Acceptance Model

Title:

- `How Safebox Decides Enough Is Enough`

Suggested content:

- `Validated`
- `Attested`
- `Recognized`
- `Trusted`
- `Accepted`

Suggested short line under each:

- `Valid signature`
- `Owner control claim`
- `Issuer in verifier WoT`
- `Advisory score inputs`
- `Verifier proceeds`

### Slide 4: Demo Flow

Title:

- `What You’re About To See`

Suggested content:

1. `Issuer sends signed record to Holder`
2. `Holder presents record to Verifier`
3. `Verifier confirms:`
   - `Valid`
   - `Self-Presented`
   - `Recognized`

Suggested visual:

- `Issuer -> Holder -> Verifier`

### Slide 5: Why It Matters

Title:

- `Reusable WoT Building Block`

Suggested content:

- `Not limited to one vertical`
- `Works for records, credentials, attestations, and agent flows`
- `Verifier-local trust policy`
- `Interoperable Nostr-native model`
