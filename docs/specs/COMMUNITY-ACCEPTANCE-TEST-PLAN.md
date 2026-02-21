# Community Acceptance Test Plan (CLRK-Oriented)

## 1. Purpose

This plan is a community-oriented acceptance framework for groups adopting Safebox as part of a Community-Led Recordkeeping (CLRK) model. It is similar to a user acceptance test (UAT), but evaluates not only software behavior, also community governance fit, stewardship practice, social trust workflows, and legal/ethical readiness.

It is designed for communities that want to integrate secure, portable, verifiable records without displacing local judgment, witnessing, and governance.

## 2. Community Acceptance Goals

A deployment is acceptable when the community can demonstrate all of the following:

- Governance fit:
  - local roles and procedures are clear, understood, and followed.
- Operational usability:
  - real participants (not only technical admins) can complete core workflows.
- Record stewardship quality:
  - records are accurate, retrievable, and responsibly handled.
- Trust and fairness:
  - acceptance/rejection decisions are transparent and consistent with agreed rules.
- Safety and resilience:
  - users can recover from ordinary failure scenarios (lost device, rotated NFC card, interrupted payment flow).
- Legal and ethical alignment:
  - local regulatory/privacy obligations are acknowledged and operationalized.

## 3. Scope

In scope:

- Community onboarding and governance setup
- Record creation, witnessing, offer/request/present workflows
- NFC and QR interactions for records and payments
- Operator/steward workflows
- User recovery and dispute handling
- Payment support for light operational use (dues/fees/reproduction costs)
- Evidence and auditability for community and external oversight

Out of scope:

- replacing formal registries
- legal adjudication by software

## 4. Community Readiness Preconditions

Before test execution, confirm:

1. Community constitution/rules are documented (simple written form is acceptable).
2. Steward roles are assigned (minimum):
   - Record Steward
   - Archivist
   - at least two Key Holders / backup custodians
3. Meeting cadence is defined (e.g., bi-weekly).
4. Minimal consent and privacy guidance is documented.
5. Device and connectivity assumptions are realistic for the local context.

## 5. Role-Based Test Participation

Run acceptance with real participants in these roles:

- Community member (record holder)
- Record Steward
- Witness/Verifier
- Archivist/Operator
- Observer for governance committee (optional but recommended)

Pass condition:

- each role can perform required actions without hidden technical intervention.

## 6. Test Tracks

### Track A: Governance and Process Fit

Objective:
- verify Safebox workflows align with community decision-making practice.

Scenarios:
1. Propose a new record category and approve it through community process.
2. Accept and reject sample records using agreed criteria.
3. Escalate one disputed record and resolve through meeting process.

Pass criteria:
- decisions are reproducible and documented.
- roles/responsibilities are clear at each step.

### Track B: Core Record Lifecycle

Objective:
- confirm end-to-end record behavior under normal usage.

Scenarios:
1. Create a basic record and issue to holder.
2. Offer record via QR and via NFC.
3. Request/present record via QR and via NFC.
4. Validate rendered output (including blob/PDF fallback behavior on older devices).

Pass criteria:
- holder receives expected record.
- verifier receives only intended data.
- failed flows return clear, actionable error states.

### Track C: Consent, Privacy, and Minimum Disclosure

Objective:
- ensure the community’s privacy norms are technically enforceable in practice.

Scenarios:
1. Share only required record fields for a specific purpose.
2. Test a request for unnecessary data and reject it.
3. Confirm sensitive fields are not displayed in logs/UI unintentionally.

Pass criteria:
- minimum necessary disclosure can be achieved.
- privacy violations are detectable and blocked by process.

### Track D: Payment Support for Community Operations

Objective:
- validate light operational payments (e.g., dues/copy fees) in a community-safe way.

Scenarios:
1. Request payment from card and complete settlement.
2. POS invoice flow with correct `PENDING -> processing -> settled` status transitions.
3. Interruption test (refresh/network drop) during ecash/NFC processing.
4. Verify rollback and recovery behavior (`ecash-recovery-*` if required).

Pass criteria:
- no silent proof/funds loss.
- no premature “complete” status.
- recovery path is understandable to non-technical stewards.

### Track E: Stewardship, Custody, and Continuity

Objective:
- validate that community stewardship survives personnel/device disruption.

Scenarios:
1. Steward handoff: secondary steward performs same workflow.
2. Lost-device simulation and holder recovery path.
3. NFC secret rotation and revocation of old cards.
4. Validate continuity of records after role rotation.

Pass criteria:
- no single-person dependency for normal operations.
- continuity maintained through documented handoff process.

### Track F: Transparency and Community Trust

Objective:
- ensure participants can understand “what happened” in important events.

Scenarios:
1. Reconstruct an acceptance decision from records/log evidence.
2. Reconstruct a payment outcome from status and transaction history.
3. Explain one failed operation in plain language to participants.

Pass criteria:
- stewards can explain outcomes without deep technical tooling.
- evidence is sufficient for community review.

## 7. Inclusion and Accessibility Checks

Required checks:

- low-literacy/low-digital-familiarity walkthrough with support prompts
- mobile-first operation on older devices where possible
- language clarity for key states (pending, failed, completed, revoked)
- explicit tests for shared-device usage patterns

Pass criteria:
- critical workflows are usable by intended community participants, not just technical administrators.

## 8. Legal/Ethical Community Safeguards

Validate the community can operationalize:

- lawful-use statement and prohibited uses
- privacy and stewardship expectations
- authority request handling process (who receives, who reviews, who responds)
- non-complicity posture and evidence retention

Pass criteria:
- community has agreed and documented procedures before production use.

## 9. Evidence Package for Community Sign-Off

Collect and store:

- test roster by role
- scenario checklist with pass/fail and notes
- screenshots/log excerpts for major flows
- unresolved issues and remediation owners
- community committee sign-off statement

## 10. Go/No-Go Criteria (Community Deployment)

Go if all are true:

1. All Track B and D critical scenarios pass.
2. At least one full cycle (meeting -> issuance -> verification -> archival) succeeds with real participants.
3. Recovery and continuity tests (Track E) pass.
4. Community governance committee approves documented operating rules.
5. Open issues are low-risk or have agreed mitigation timelines.

No-Go if any of the following remains:

- unresolved proof/funds integrity issue
- inability to recover critical records/payments after expected failure modes
- unclear role accountability for stewardship decisions
- unresolved legal/privacy handling ambiguity

## 11. Recommended Pilot Sequence

Phase 1 (2–4 weeks):
- 10–25 participants, limited record categories, supervised workflows.

Phase 2 (4–8 weeks):
- add NFC/QR mixed flows, add POS/dues pattern if applicable, run interruption drills.

Phase 3 (production community operation):
- broader participant onboarding, scheduled governance review, periodic acceptance re-test (quarterly).

## 12. Mapping to CLRK Principles

This test plan explicitly supports CLRK principles from the policy brief:

- local stewardship over distant dependency
- witnessed verification and transparent process
- practical portability of records
- complementary (not replacement) relationship with formal institutions
- continuity of community trust practices in digital form

The result should be a community system that is technically credible, socially legitimate, and operationally sustainable.
