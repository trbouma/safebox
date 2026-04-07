# Progress Report 2026-04
Reference: [Phase 3 Proposal](PHASE3-PROPOSAL.md)

Date: 2026-04-02

Status: Active Delivery

Proof of Work:
- 291 commits landed between 2026-01-02 and 2026-04-02
- 1087 total commits in the repository as of 2026-04-02
- demonstration instances and operator materials continue to be maintained in the repo and associated deployment environments

## Purpose

This report summarizes progress over roughly the last three months and relates that work to the commitments stated in the Phase 3 proposal. The Phase 3 proposal framed the project as taking experimental Phase 2 features and scaling and hardening them into a product that can support interoperable, pilot-ready deployment.




## Changed Environment and Development Context

An important part of understanding this reporting period is that the environment around the project changed in meaningful ways. Progress during this period was not only a matter of executing the original plan, but also of responding to new technical realities and opportunities that emerged.

### 1. Increased sensitivity to post-quantum cryptography risks

During this period, there was increased sensitivity to post-quantum cryptography risk. In response, significant effort was spent integrating OQS libraries and testing quantum-safe paths across Safebox flows.

This work mattered for two reasons:

- to prove that post-quantum components could be practically integrated into the Safebox stack
- to demonstrate that Safebox could evolve toward a genuinely quantum-safe architecture for record exchange and related trust-sensitive flows

This materially influenced work on:
- KEM handling
- quantum-safe record transmission
- PQC offer/request flows
- troubleshooting and recovery procedures for KEM material and recipient secret drift

### 2. The emergence of agents as a first-class user of Safebox

A second major environmental change was the rise of agents as serious participants in the ecosystem. This shifted Safebox from being only a user-facing wallet and records system toward also being an execution surface for autonomous software actors.

In response, a dedicated agent API was expanded so Safebox could be used directly by agents for:
- messaging
- social interactions
- payments
- offer and market flows
- discovery and streaming workflows

This was not merely an extra interface layer. It changed the functional expectations of the system by requiring cleaner APIs, more deterministic workflows, better documentation, and stronger protocol clarity.

### 3. The use of agent coding, especially Codex

A third important change was the practical adoption of agent-assisted coding, especially through Codex. This significantly changed the development approach during the reporting period.

The effect was not simply faster coding. It changed the rhythm and structure of development by making it more feasible to:
- iterate quickly on hardening work
- maintain momentum across many interacting flows
- produce more extensive documentation in parallel with implementation
- run tighter refactor / regression / patch loops on complex subsystems

This also influenced the project operationally by encouraging:
- finer-grained modularization
- more explicit specs and operator guidance
- clearer diagnostics and recovery flows

In short, the environment changed in ways that made Safebox both more ambitious and more demanding. The work completed in this reporting period should be understood partly as a response to those shifts.

### 4. The continuing influence of the Nosfabrica health-record context

Another important driver of requirements during this period was the problem framing established in [Nosfabrica Proposal](NOSFABRICA-PROPOSAL.md). That proposal helped situate Safebox not merely as a wallet, but as a system for managing private records, secure exchange, credential-style presentation, and trust-sensitive interoperability in real-world institutional contexts.

That influence can be seen throughout the work completed in this reporting period, especially in:

- record offer and grant flows
- presentation and verifier workflows
- attestation and Web of Trust requirements
- selective disclosure and holder/presenter semantics
- secure transmittal and cross-instance reliability
- deployment and pilot-readiness thinking for real ecosystem stakeholders

In practice, the Nosfabrica framing continued to shape what counted as “done.” It pushed Safebox toward supporting not only private payments, but also durable person-centered record handling in environments such as health, credentials, and related trust-bound service ecosystems.

## Executive Summary

Progress during this period was substantial.

Safebox advanced across five major fronts:

1. Web of Trust, attestation, and acceptance-model architecture matured significantly
2. cross-instance record exchange, NFC, QR, and offer/request flows were hardened
3. agent APIs and market surfaces expanded, especially around the MS-02 entitlement-market flow
4. deployment and secret-management posture improved materially
5. Cashu proof lifecycle resilience became a major focus, with new repair, audit, and recovery mechanisms

Overall, the repository reflects a transition from experimental capability-building toward product hardening and pilot readiness, though proof lifecycle maintenance and some complex multi-step flows remain active stabilization areas.

## Progress Against Phase 3 Commitments

### 1. Commitment: Harden experimental features into a real product/service

The proposal emphasized turning Phase 2 experimental work into a hardened product that can support diverse stakeholders.

#### Evidence of progress

- Significant hardening landed for NFC, QR, record exchange, cross-instance offer/request flows, and presentation flows.
- Record verification was refactored into shared helpers with request-scoped trust context and caching.
- Trust verification now includes:
  - owner attestation
  - recognized issuer evaluation
  - recognized-by root authority provenance
  - holder/self-presented semantics
  - advisory WoT score handling
- The trust-management UI was substantially improved:
  - trust page cleanup
  - root authority profile view
  - validation and duplicate handling for trusted lists
- Payment and wallet proof maintenance received focused hardening:
  - swap diagnostics improved
  - proof safety audit added
  - stale-proof recovery path introduced
  - receive-side maintenance thresholds added
  - repair-proofs command and UI action added

#### Assessment

This commitment is clearly in progress and materially advanced. The codebase now looks far more like a product surface with operational safeguards than a purely exploratory prototype.

#### Remaining gap

Proof lifecycle correctness is still the most active operational risk. Recent work improved visibility and recovery, but this area still needs continued regression testing and refinement before it can be considered fully stable for broad pilot use.

### 2. Commitment: Support interoperable multiple instances and implementations

The proposal emphasized building multiple instances and implementations that can interoperate.

#### Evidence of progress

- Cross-instance NFC/QR and record-offer flows were hardened repeatedly during February and March.
- KEM fallback and quantum-safe handshakes were improved for mixed-instance flows.
- Relay selection, request scope parsing, nonce enforcement, and recipient-initiated offer flows were all tightened.
- Offer/request exchange logic now better supports:
  - recipient-initiated flows
  - presenter-initiated flows
  - direct host routing
  - signed requester/service bindings
  - allowlist enforcement
- Documentation now captures interoperability architecture more explicitly:
  - hybrid HTTP control-plane / relay data-plane notes
  - alternative ecosystem and cross-instance flow notes
  - Willow comparative analysis

#### Assessment

This commitment is being actively delivered. Interoperability work is one of the strongest visible themes in the commit history.

#### Remaining gap

The system now supports many interoperability modes, but that flexibility increases edge-case complexity. The implementation is much stronger than it was, but the operational surface is broad and still benefits from disciplined end-to-end testing.

### 3. Commitment: Scale toward a service that can support large user populations

The proposal calls out the need to robustly support a service that could eventually serve thousands or millions of users.

#### Evidence of progress

- Wallet-lock handling became re-entrant and more robust under nested flows.
- Proof persistence now verifies post-write state and attempts restore when relay state is incomplete.
- Browser-agent CORS coverage was expanded and normalized.
- NWC listener lifecycle, reconnect, and relay behavior were improved.
- Deployment work added:
  - migration-aware startup
  - deterministic currency seed initialization
  - postgres readiness
  - host-based branding
  - secret bootstrapping and externalized secret files

#### Assessment

This commitment has advanced mostly through reliability and operational hardening rather than horizontal scaling features. The groundwork for more serious service operation is stronger now than it was three months ago.

#### Remaining gap

The codebase is better prepared for scale, but pilot-scale validation and longer-lived operational observations are still needed before any claim of large-scale readiness.

### 4. Commitment: Add product discipline through testing, QA, documentation, support, and operational clarity

The proposal explicitly called for more commercial-product discipline.

#### Evidence of progress

- Documentation volume increased significantly across:
  - protocol specs
  - market specs
  - operator guides
  - resiliency notes
  - deployment procedures
  - security and architecture notes
- Focused regression tests were added around record verification helpers.
- Many recent changes include explicit diagnostics, safer error handling, and clearer operator feedback.
- A GitHub Pages documentation surface and presentation materials were added.
- DevOps docs now cover:
  - secret bootstrap and migration
  - OpenBao integration
  - Kubernetes promotion workflow
  - troubleshooting notes for recipient secret drift

#### Assessment

This commitment has seen strong progress. Documentation and operational clarity are now a real strength of the project rather than a secondary concern.

#### Remaining gap

Test coverage still appears focused and selective rather than broad. There is clear improvement, but more systematic regression coverage across proof maintenance, cross-instance exchange, and payment flows would strengthen pilot readiness further.

## Progress Toward Phase 3 Milestones

The proposal named four end-state milestones.

### Milestone 1. A product/service ready for deployment

#### Current status: Substantially progressed, not fully complete

Supporting evidence:
- deployment hardening across Docker, Postgres, secret management, and startup behavior
- host-based branding and productized UI improvements
- trust and record flows are much more mature
- operator and devops documentation are significantly improved

Remaining work:
- continue reducing proof-state fragility
- continue tightening end-to-end operational flows
- broaden regression coverage

### Milestone 2. A running demonstration instance used by test users

#### Current status: In progress and materially supported

Supporting evidence:
- demo-oriented docs, operator workflows, and hackathon presentation materials
- continuing support for live instances and cross-instance flows
- multiple changes explicitly reference real deployment and runtime troubleshooting

Remaining work:
- maintain stable demo flows
- keep operational recovery procedures simple and well documented

### Milestone 3. A willing operating partner

#### Current status: Not directly evidenced in the commit history reviewed here

The last three months of repository work do not by themselves prove an operating partner commitment. However, the deployment and operations work clearly supports that objective by making the system more legible and operable for a partner.

### Milestone 4. A community ready and willing to pilot

#### Current status: Emerging, with stronger supporting materials

Supporting evidence:
- improved specs and architecture notes
- operator guide for MS-02
- Web of Trust hackathon materials
- trust/acceptance model clarification
- community-facing documentation and comparative analysis

This suggests improved readiness to explain, demonstrate, and pilot the system, even if pilot commitments are not demonstrated directly in git history.

## Major Workstreams Completed or Advanced

### Web of Trust and Trust Architecture

- trust list support and NIP-85-related work matured
- trust admin page improved
- root authority profile display added
- record verification now exposes trust provenance and holder semantics
- acceptance model expanded and clarified

### Record Exchange and Credential Presentation

- request/presentation and offer/accept flows hardened
- nonce handling, KEM handling, and cross-instance logic improved
- verification helpers were centralized and tested
- stored-record and live-presentation verification semantics were clarified

### Agent and Market Surfaces

- agent APIs expanded for social publishing, DMs, reactions, replies, follows, offers, and payments
- MS-02 entitlement-market design matured significantly
- buyer-decryptable fulfillment and end-to-end documentation were developed

### Deployment and Operations

- deterministic startup and configuration handling improved
- mounted secrets replaced riskier embedded bootstrap patterns
- Kubernetes/OpenBao/devops guidance was added
- host-based branding and demo presentation surfaces improved

### Wallet Proof Resilience

- proof safety audit introduced
- swap error diagnostics improved
- stale-proof repair paths introduced
- receive-side maintenance thresholds added
- race-condition fixes added for swap/repair under lock
- user guidance and dangerzone tooling improved

## Current Risks and Active Areas

### 1. Proof lifecycle and wallet state reconciliation

This is the clearest active engineering risk.

Recent work fixed multiple real defects, including:
- stale-proof payment failures
- race conditions around payment and swap/repair operations
- a serious early-return bug in `repair_proofs()`

This area is improving quickly, but it is still the main place where pilot-grade caution is warranted.

### 2. Complexity of supported flow combinations

Safebox now supports a wide range of combinations:
- QR
- NFC
- offer/request
- cross-instance routing
- PQC/KEM-protected flows
- agent and browser clients

That breadth is a strategic advantage, but it increases testing burden and edge-case exposure.

### 3. Need for broader regression coverage

There are focused tests in place, especially around record verification, but broader coverage around proof maintenance, payment recovery, and cross-instance record exchange would improve confidence further.

## Overall Status

The Phase 3 proposal asked for a move from experimentation toward hardened, interoperable, pilot-ready product capability.

Based on the repository activity over the last three months, that transition is clearly underway and materially advanced.

Most notably:
- trust and acceptance architecture is much stronger
- interoperability work is significantly more mature
- market and agent surfaces are more coherent
- deployment posture is more serious
- documentation is now a major project strength

The main remaining technical concern is wallet proof lifecycle reliability under long-lived and mixed payment conditions. That area is receiving direct attention and has seen meaningful progress, but it remains the most active stabilization front.

## Conclusion

Relative to the commitments in `docs/PHASE3-PROPOSAL.md`, the project has made strong progress in:
- product hardening
- interoperability
- deployment readiness
- documentation and operational discipline
- readiness for demonstration and pilot conversations

The project appears to be on a credible trajectory toward the stated Phase 3 goal of being ready for community pilot in the early-to-mid 2026 timeframe, with the caveat that proof maintenance and complex multi-step runtime flows should remain a priority for near-term stabilization.
