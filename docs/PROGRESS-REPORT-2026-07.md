# Progress Report 2026-07

Reference: [Phase 3 Proposal](PHASE3-PROPOSAL.md)

Date: 2026-07-06

Status: Phase 3 Commitments Largely Complete; Preparing for Pilot

Proof of Work:

- all completed work has been merged into the `main` branch
- 49 commits landed between 2026-04-03 and 2026-07-06
- 1,136 total commits are present in the repository as of 2026-07-06
- the repository remains available under the MIT License
- deployment, operator, protocol, testing, and troubleshooting materials are maintained alongside the implementation

## Purpose

This report summarizes progress since the April 2026 report and assesses the
project against the commitments in the Phase 3 proposal.

Phase 3 has focused on taking the experimental capabilities developed in Phase
2 and scaling and hardening them in several dimensions so that SafeBox can
become a real product serving diverse ecosystem stakeholders. This has meant:

- building multiple instances and implementations that can interoperate
- strengthening the system so it can grow from small demonstrations toward
  services supporting thousands, and eventually potentially millions, of users
- introducing the discipline expected of a commercial product, including
  testing, QA, support, documentation, deployment practices, diagnostics, and
  operational recovery

The central conclusion of this reporting period is that these Phase 3
engineering commitments are now largely complete. SafeBox has moved well beyond
an experimental feature set. It is deployable in several forms, its principal
payment and record workflows have been hardened, its interoperability model is
substantially documented and implemented, and its operational posture is much
stronger.

The remaining work is primarily user and operator polish. That work is best
completed through a real pilot, where actual users, operators, devices,
networks, and support needs will reveal which refinements matter most.

There is now concrete external interest in taking that next step. The project
has been approached by a telecommunications provider that wishes to investigate
using SafeBox in a pilot for issuing and sharing health care records. The
provider cannot be identified because the discussions are subject to a
non-disclosure agreement. The engagement remains exploratory and should not yet
be represented as a finalized pilot or operating commitment, but it is a
significant validation of the Phase 3 direction and of SafeBox's relevance to
real institutional record ecosystems.

## Executive Summary

Since the April report, work has concentrated on closing the gap between a
technically capable system and one that can be operated and piloted with
confidence.

Important advances include:

1. payment, proof, NWC, and LNURL paths were further hardened against concurrency,
   stale state, callback inconsistencies, and long-lived session failures
2. QR and NFC record workflows were aligned and stabilized across both
   presenter-initiated and recipient-initiated exchanges
3. browser and interface behavior was cleaned up, particularly where HTMX,
   navigation, payment settlement, and live status updates could interfere with
   multi-step workflows
4. first-run configuration and secret bootstrap were simplified while retaining
   fail-closed handling for partial or inconsistent secret state
5. deployment portability advanced from Docker and VPS patterns toward a
   dedicated FreeBSD appliance model, including native compilation and FreeBSD
   jail deployment
6. operational and protocol documentation continued to expand, including
   specifications, conformance materials, implementation checklists, security
   guidance, and deployment runbooks
7. architectural lessons from SafeBox have produced a spin-off project,
   [OpenETR](https://github.com/trbouma/openetr), applying durable, portable,
   and independently verifiable record concepts to digital trade documentation

The project is now at the point where a pilot is not merely a demonstration of
whether the architecture can work. A pilot is the next product-development
instrument: it will identify user-facing friction, installation and support
burden, terminology problems, workflow confusion, and operational edge cases
that cannot be fully discovered through engineering work alone.

## Progress Against Phase 3 Commitments

### 1. Commitment: Scale and harden the experimental Phase 2 features

Phase 2 established that SafeBox could combine private payments, private
records, NFC interactions, NWC, nAuth, nembed, and Nostr-based secure messaging.
Phase 3 committed to turning those experiments into dependable product
capabilities.

#### Work completed or substantially delivered

- Cashu proof handling now includes stronger protection, recovery, auditing,
  repair, and receive-side maintenance behavior.
- Mutating NWC wallet actions are queued to reduce concurrent proof races.
- Failed Lightning melts and no-route failures are handled more carefully so
  proofs are not incorrectly discarded or repeatedly repaired.
- Long-lived NWC listener sessions are refreshed to prevent silent stalls.
- NWC replies, notifications, URI information, and service identity handling
  have been made more consistent.
- LNURL callbacks now use canonical public origins and more explicit JSON and
  CORS behavior.
- Payment settlement interfaces better distinguish sender and receiver state,
  avoid duplicate success effects, and synchronize displayed balances.
- Record QR flows were stabilized for both sender-presented and
  recipient-presented patterns.
- QR and NFC were brought under a more unified workflow model, with explicit
  attention to replay protection and cross-device continuity.
- Session-sensitive pages and multi-step flows were protected from navigation
  optimizations that could reset runtime state.
- Route handling was hardened against missing or stale sessions.

#### Assessment

This commitment is largely complete. The experimental features have been
translated into substantially more coherent and recoverable product workflows.
There will continue to be defects and edge cases, particularly where payments,
relays, browsers, NFC devices, QR handoffs, and multiple SafeBox instances meet.
However, the remaining work is now characteristic of pilot refinement rather
than unresolved architectural feasibility.

### 2. Commitment: Enable multiple interoperable instances and implementations

Interoperability has remained one of the strongest themes of Phase 3.

#### Work completed or substantially delivered

- SafeBox supports cross-instance record offers, requests, grants,
  presentations, and transfers.
- Both QR and NFC can carry or initiate related workflows without making a
  single device, browser, or application platform the sole authority.
- nAuth and nembed provide protocol-level building blocks for authentication,
  addressing, and portable payload exchange.
- KEM material can be carried through authenticated flows or resolved through
  defined fallback mechanisms.
- Post-quantum record transfer paths are implemented using Open Quantum Safe
  libraries.
- Host, relay, requester, presenter, issuer, and holder roles are documented
  more explicitly across the protocol specifications.
- Agent APIs and market specifications provide another implementation surface
  beyond the interactive browser wallet.
- Conformance notes, test cases, implementation checklists, and end-to-end
  scenarios now accompany important market and agent workflows.

#### Assessment

This commitment is largely complete at the implementation and specification
level. SafeBox is no longer limited to a single monolithic deployment or a
single interaction style. The next step is interoperability testing in a pilot
across separately operated instances, varied network conditions, and real user
devices.

### 3. Commitment: Prepare SafeBox to scale toward large service populations

The Phase 3 proposal set an intentionally ambitious direction: SafeBox should
be able to evolve toward a robust service supporting thousands, and potentially
millions, of users.

#### Work completed or substantially delivered

- database migration practices and PostgreSQL deployment paths have been
  documented and incorporated into deployment planning
- concurrency-sensitive wallet operations now have stronger locking and queueing
- proof persistence, reconciliation, repair, and failure recovery have been
  strengthened
- relay and NWC lifecycle behavior has been made more resilient for long-running
  services
- configuration and secret material can be externalized for container and
  orchestrated deployments
- OpenBao and Kubernetes deployment procedures document a path toward managed
  secrets and repeatable promotion
- host-based configuration and branding allow one codebase to support varied
  operating contexts
- the application can be deployed through Docker, a conventional VPS/native
  service, or a FreeBSD appliance and jail model
- operational specifications now cover monitoring, SLO/SLA expectations,
  incident response, backup and recovery, retention, resiliency testing, and
  security testing

#### Assessment

The architectural and operational foundations for scale are largely in place.
This does not mean that SafeBox has already demonstrated million-user capacity;
that would require dedicated performance testing, production telemetry,
capacity planning, and infrastructure investment. It does mean that Phase 3
has moved the project from a prototype architecture toward one that can be
deployed, measured, replicated, and progressively scaled.

The appropriate next proof point is sustained pilot operation. That will
provide real workload information and establish which components require
optimization before broader growth.

### 4. Commitment: Introduce commercial-product discipline

Phase 3 explicitly included testing, QA, support, documentation, and related
product disciplines.

#### Work completed or substantially delivered

- protocol documentation has expanded across authentication, record exchange,
  payment, market, trust, agent, NFC, QR, PQC, and storage concerns
- operator guides, deployment runbooks, troubleshooting procedures, and
  post-deployment checks are maintained with the code
- focused regression tests cover important verification and record behavior
- conformance documents and implementation checklists define expected behavior
  beyond informal demonstrations
- safer error handling and more actionable diagnostics have been added to
  complex payment and exchange paths
- configuration and secret inventories make deployment requirements more
  legible to operators
- guarded first-run bootstrap reduces setup burden while preventing silent
  replacement of partially initialized identity material
- UI cleanup has addressed navigation, status reporting, callback handling,
  table layout, payment feedback, and other practical product concerns

#### Assessment

This commitment is largely complete as a Phase 3 foundation. Documentation and
operational clarity are now material parts of the project rather than
afterthoughts.

The remaining gap is the difference between internally driven QA and
user-validated product quality. A pilot is needed to establish repeatable
onboarding, support expectations, accessibility needs, user comprehension,
operator burden, and the severity of real-world failure modes. Those insights
will guide the next layer of automated tests and documentation.

## Deployment Portability and the FreeBSD Appliance Direction

A major outcome of the recent work is that SafeBox can be approached as a
deployable service rather than only as an application tied to one development
environment.

### Supported deployment directions

The project now has documented paths for:

- Docker-based development and service deployment
- zero-configuration container bootstrap with a production promotion path
- PostgreSQL-backed and migration-aware operation
- external secret files and Kubernetes secret promotion
- OpenBao-backed secret management
- native VPS or server installation
- native FreeBSD operation
- a dedicated FreeBSD appliance
- SafeBox running as a service inside a FreeBSD jail

### Why FreeBSD matters

The most recent deployment focus is a SafeBox appliance built on FreeBSD. This
direction combines several technologies that fit the project well:

- ZFS provides datasets, checksums, snapshots, clones, replication, and rapid
  rollback.
- FreeBSD jails provide lightweight service isolation without requiring a full
  virtual machine for each SafeBox instance.
- Native `rc.d` services provide predictable boot-time and runtime lifecycle
  management.
- A host-level reverse proxy and Tailscale can provide controlled public and
  administrative access.
- Separate jails can eventually isolate SafeBox, relays, Blossom storage,
  databases, and supporting services.

The FreeBSD work has also forced deployment assumptions to become more
explicit. SafeBox includes Python packages with native C and Rust components,
and its post-quantum capabilities depend on `liboqs`. Running natively on
FreeBSD—particularly on ARM hardware—required documenting compiler toolchains,
library discovery, package-versus-source installation, constrained-memory
builds, service accounts, and runtime linking.

This work is now captured in:

- [Running SafeBox on FreeBSD](FREEBSD-INSTALL.md)
- [SafeBox FreeBSD Appliance Specification](devops/SAFEBOX-FREEBSD-APPLIANCE-SPEC.md)
- [SafeBox in a FreeBSD Jail: From-Scratch Runbook](devops/freebsd-jail-from-scratch.md)

The significance extends beyond one operating system. A successful appliance
and jail deployment demonstrates that the application can be separated from
its original environment, rebuilt from documented dependencies, operated as an
unprivileged service, isolated, backed up, upgraded, and rolled back. Those are
important properties of a product intended for diverse ecosystem operators.

## Architectural Knowledge Transfer and OpenETR

The architectural lessons learned through SafeBox have also resulted in a
spin-off project for digital trade documentation:
[trbouma/openetr](https://github.com/trbouma/openetr).

OpenETR explores a minimal interoperable layer for electronic transferable
records, including instruments such as bills of lading, warehouse receipts,
promissory notes, certificates, and other records whose control must be proven
and transferred. It builds on lessons developed through SafeBox concerning
portable records, cryptographic control, signed events, independent
verification, interoperability, and reducing dependence on a single platform
or registry.

OpenETR is a distinct project rather than an additional SafeBox feature. Its
emergence is nevertheless an important Phase 3 outcome: the work has produced
reusable architectural knowledge that can be applied beyond payments and
personal or health records to another complex institutional domain. This
demonstrates that the SafeBox effort is contributing not only an application,
but also patterns for durable, portable, and verifiable digital records across
ecosystems.

## Progress Toward the Phase 3 Milestones

The Phase 3 proposal identified four concluding milestones.

### Milestone 1: A product/service ready for deployment

#### Current status: Largely complete

The code is merged into `main` and available under the MIT License. Multiple
deployment models are documented, first-run configuration is more predictable,
and the application has a substantially stronger operational foundation.

The product still requires pilot-driven user polish, but it is ready to move
from developer-led demonstrations into structured pilot deployment.

### Milestone 2: A running demonstration instance used by test users

#### Current status: Substantially supported

The application and its principal workflows have been developed through live
demonstration and test-instance use. Cross-instance, payment, NFC, QR, record,
trust, and agent scenarios now have significantly stronger implementation and
supporting documentation.

The next useful evolution is a more structured pilot with defined users,
feedback channels, service expectations, and success criteria.

### Milestone 3: A willing operating partner

#### Current status: Active exploratory partner engagement

The project has been approached by a telecommunications provider interested in
investigating a SafeBox pilot for issuing and sharing health care records. The
provider's identity is protected under a non-disclosure agreement. Discussions
are exploratory, and no finalized pilot or operating commitment is claimed at
this stage.

This interest nevertheless represents meaningful progress toward the operating
partner milestone. The repository now gives a prospective operator a concrete
basis for evaluating deployment architecture, secret handling, recovery,
security, monitoring, and platform alternatives before accepting responsibility
for a service.

The FreeBSD appliance direction may be particularly useful for a partner that
wants a bounded and reproducible system rather than a bespoke cloud deployment.

### Milestone 4: A community ready and willing to pilot

#### Current status: Technical readiness established; a health-record pilot is under investigation

SafeBox now has the technical breadth needed to support a meaningful community
pilot. The telecommunications-provider discussions offer a potential bounded
use case centered on issuing and sharing health care records. If the exploratory
engagement proceeds, the remaining work will include defining the participating
community, governance and privacy expectations, operating responsibilities,
support and feedback mechanisms, and pilot success criteria. The system must
then run long enough to distinguish usability problems from underlying
technical problems.

## Major Workstreams Since the April Report

### Payment and proof resilience

- protected proofs during failed Lightning melt attempts
- prevented inappropriate proof-recovery retries for no-route failures
- queued mutating NWC actions to reduce wallet races
- improved long-lived NWC session behavior
- aligned NWC service identity and notifications
- hardened LNURL callbacks, success state, and balance refresh behavior

### QR, NFC, and record exchange

- stabilized recipient-presented QR offer flows
- added compact receive-offer QR resolution
- corrected presentation record lookup and KEM handling
- documented convergence between QR and NFC reference flows
- added replay and workflow considerations for unified QR/NFC operation

### User-interface hardening

- reduced HTMX-related regressions in stateful workflows
- protected runtime-sensitive pages from inappropriate boosted navigation
- improved status text and removed confusing object-string leakage
- cleaned up shared client behavior across wallet, point-of-sale, and invite flows
- improved account-history layout and payment-settlement feedback
- hardened routes against missing sessions and stale authentication state

### Configuration and first-run operation

- added guarded bootstrap for an empty secret store
- enabled safe automatic bootstrap on first startup
- retained fail-closed handling for partial or previously initialized secret state
- allowed unrelated environment keys without breaking settings validation
- made explicit `.env` branding the final override
- documented canonical public base URL behavior

### FreeBSD, appliance, and jail deployment

- documented native FreeBSD dependencies and build times
- documented Open Quantum Safe package and source-build paths
- developed a FreeBSD appliance architecture
- defined native daemon and `rc.d` service operation
- documented ZFS-backed jail creation, snapshots, upgrades, and rollback
- captured ARM and constrained-hardware compilation considerations

## Remaining Work: Pilot-Led Product Polish

The phrase “largely complete” does not mean that development is finished. It
means that the character of the remaining work has changed.

The highest-value next work is expected to include:

- simplifying onboarding for users unfamiliar with Nostr, relays, Cashu, or
  post-quantum terminology
- reducing the number of decisions required during initial setup
- refining QR, NFC, and cross-device status messages based on observed behavior
- improving accessibility, mobile layout, and recovery guidance
- defining operator support procedures and escalation paths
- broadening automated regression tests around the failures actually observed
  during pilot use
- collecting performance and reliability telemetry under sustained workloads
- validating backup, restore, upgrade, and identity recovery with an operator
  other than the primary developer
- testing interoperability across independently administered SafeBox instances
- producing concise user-facing guides alongside the detailed technical material

These are not reasons to delay a pilot. They are reasons to run one carefully.
Without real users and operators, additional polish risks optimizing imagined
problems instead of the barriers that actually affect adoption.

## Current Risks

### 1. Breadth of interaction modes

SafeBox supports payments, records, QR, NFC, browser clients, agents,
cross-instance exchange, and PQC-protected flows. That breadth is strategically
important, but creates a large test matrix. A pilot should begin with a bounded
set of supported journeys before progressively enabling every combination.

### 2. Long-lived wallet and proof state

Proof lifecycle reliability has improved materially, but sustained operation is
still the best test of reconciliation, relay availability, mint behavior, NWC
sessions, and recovery tooling.

### 3. Native dependency portability

The FreeBSD work demonstrates portability, but native C and Rust dependencies
increase build time and platform-specific risk. Reproducible appliance images,
pinned dependencies, and tested upgrade procedures should remain priorities.

### 4. User comprehension and support

The protocol and operational documentation is extensive, but end users need a
much smaller and more task-oriented surface. Pilot observation is needed to
learn where concepts, labels, and recovery steps remain unclear.

## Overall Status

Phase 3 set out to turn the experimental achievements of Phase 2 into a
scalable, hardened, interoperable, and operable product.

That commitment is now largely complete:

- the principal experimental features have been hardened into product workflows
- multiple SafeBox instances and interaction surfaces can interoperate
- reliability and operational foundations for future scale are in place
- testing, specifications, conformance material, deployment guidance, and
  troubleshooting have become first-class parts of the project
- SafeBox can be deployed through different infrastructure models
- the newest work demonstrates a credible path to a dedicated FreeBSD appliance
  and isolated jail-based services
- architectural lessons from SafeBox have enabled the separate OpenETR digital
  trade documentation project
- all completed work is consolidated on the `main` branch

The project should now be understood as pilot-ready, with an explicit caveat:
user experience and operator experience still require refinement through
structured real-world use.

## Conclusion

SafeBox has crossed an important threshold during Phase 3. The question is no
longer whether the Phase 2 experiments can be assembled into a coherent and
deployable product. They can, and the implementation, documentation, and
deployment work now demonstrate that across multiple dimensions.

The next phase should emphasize learning through operation. A bounded community
pilot can validate interoperability, sustained wallet behavior, support needs,
deployment procedures, and user comprehension. It can also turn the remaining
polish work into an evidence-driven product backlog.

The FreeBSD appliance and jail work is a useful symbol of this transition. It
takes SafeBox out of a single development context and treats it as an
independent service that can be installed, isolated, started automatically,
secured, monitored, snapshotted, upgraded, and recovered. That is precisely the
kind of practical hardening Phase 3 was intended to achieve.
