# Progress Report — July 2026

Reference: [Phase 3 Proposal](PHASE3-PROPOSAL.md)

Previous report: [April 2026 Progress Report](PROGRESS-REPORT-2026-04.md)

Reporting date: 2026-07-06

Status: **On track — Phase 3 commitments are largely complete; pilot preparation is next**

## Summary

**In brief:** SafeBox has moved from experimental Phase 2 capabilities to a
deployable, interoperable, and substantially hardened product. All completed
work has been merged into `main`. The remaining work is primarily user and
operator polish that should be guided by a real pilot.

Phase 3 committed to scaling and hardening the Phase 2 experiments: supporting
interoperable instances, preparing for services that could eventually support
large populations, and adding commercial-product discipline through testing,
QA, support, documentation, and repeatable operations.

Since the April report, 49 commits have landed, bringing the repository to
1,136 commits. Work concentrated on payment and proof reliability, QR/NFC
record exchange, NWC and LNURL behavior, browser workflow stability,
first-start configuration, and deployment portability. The newest deployment
focus is a dedicated FreeBSD appliance with SafeBox isolated in a ZFS-backed
jail.

I am pleased with the progress. The central Phase 3 engineering questions have
been answered positively, and SafeBox is ready to move into a bounded pilot.
I am not claiming that every workflow is polished or that million-user scale
has already been demonstrated. Those require pilot feedback, sustained
operational data, and dedicated performance testing.

## Progress Against the Phase 3 Plan

**In brief:** The four engineering commitments in the proposal are largely
delivered. The work completed since April directly closes risks identified in
the previous report, particularly wallet proof state and complex cross-instance
flows.

### Harden the Phase 2 experiments

Payment and wallet behavior received another hardening pass. Mutating NWC
actions are now queued to reduce proof races; failed Lightning melts better
protect proofs; long-lived NWC listeners refresh rather than silently stall;
and LNURL callbacks use canonical origins with clearer JSON and CORS behavior.
Payment screens now synchronize balances and avoid duplicate or misleading
success states.

Relevant work:

- [Queue mutating NWC actions](https://github.com/trbouma/safebox/commit/8c8ba0d)
- [Protect proofs on failed Lightning melts](https://github.com/trbouma/safebox/commit/59fa776)
- [Refresh long-lived NWC sessions](https://github.com/trbouma/safebox/commit/b755a70)
- [Stabilize LNURL callbacks](https://github.com/trbouma/safebox/commit/aebc481)
- [Stabilize payment settlement and balance refresh](https://github.com/trbouma/safebox/commit/bd7eb24)

QR and NFC record workflows were also aligned and stabilized. Recipient- and
sender-presented flows now have clearer KEM handling, replay considerations,
and cross-device continuity.

- [Unified QR and NFC flow design](https://github.com/trbouma/safebox/commit/df2a44a)
- [Stabilize recipient-presented QR offers](https://github.com/trbouma/safebox/commit/71d5f0c)
- [Fix QR presentation lookup and KEM handling](https://github.com/trbouma/safebox/commit/4d653bc)

### Support interoperable instances and implementations

SafeBox now supports cross-instance record offers, requests, presentations, and
transfers through browser, QR, NFC, and agent-oriented surfaces. nAuth, nembed,
relay messaging, direct host resolution, and Open Quantum Safe KEM paths are
documented as interoperable building blocks rather than implementation details
of one server.

The repository now includes protocol specifications, conformance documents,
agent test cases, and end-to-end scenarios. This substantially meets the Phase
3 interoperability commitment. The next validation should occur across
independently operated pilot instances rather than only developer-controlled
environments.

### Prepare for future scale

The project has stronger foundations for scale: PostgreSQL and migrations,
serialized wallet mutations, proof recovery, managed-secret patterns,
long-lived listener recovery, host-based configuration, and multiple deployment
models. These make SafeBox replicable and measurable.

This is readiness to scale, not a claim of demonstrated million-user capacity.
A pilot should supply workload data, failure rates, and support observations;
larger-scale claims will require load testing and production telemetry.

### Add commercial-product discipline

Testing, specifications, conformance material, deployment procedures,
troubleshooting, backup/recovery guidance, and security planning are now
first-class repository content. Guarded first-run bootstrap reduces setup
friction while failing closed if secret state is partial or inconsistent.

- [Add guarded first-run bootstrap](https://github.com/trbouma/safebox/commit/19dc08c)
- [Enable safe automatic bootstrap](https://github.com/trbouma/safebox/commit/ed205dc)
- [FreeBSD jail deployment and liboqs runbook](https://github.com/trbouma/safebox/commit/6866dae)

This commitment is largely complete as a foundation. A pilot is still needed
to establish user comprehension, accessibility needs, operator burden, and the
most valuable additions to automated regression coverage.

## Challenges and How They Were Addressed

**In brief:** The hardest problems were stateful payment concurrency,
browser-driven multi-step flows, and portable native builds. These caused plans
to shift toward deeper reliability and deployment work, but did not prevent the
Phase 3 objective from being reached.

Wallet proofs can be affected by mint responses, relay state, concurrent NWC
requests, and failed Lightning routes. The April report identified proof
lifecycle correctness as the largest operational risk. This was addressed with
stronger locking and queueing, proof protection, recovery and repair behavior,
and clearer diagnostics. Sustained pilot operation remains the appropriate test
of this work.

QR, NFC, payments, WebSockets, and cross-instance transfers depend on browser
state across several pages. HTMX navigation optimizations sometimes reset that
state or produced stale sessions. Runtime-sensitive pages were opted out of
boosted navigation, routes were hardened, and client status handling was
simplified.

- [Fix HTMX regressions in NFC and POS flows](https://github.com/trbouma/safebox/commit/9090947)
- [Guard routes against missing and stale sessions](https://github.com/trbouma/safebox/commit/0e2187f)

Finally, FreeBSD and ARM exposed assumptions hidden by Linux containers.
SafeBox depends on native C and Rust packages, including `liboqs`. The response
was to document package and source-build paths, linker discovery, constrained
parallel builds, service accounts, `rc.d`, ZFS snapshots, and jail rollback.
This took time away from visible features, but produced a more portable and
operable product.

## Deployment and Pilot Readiness

**In brief:** SafeBox can now be deployed through Docker, a conventional server,
managed container infrastructure, or a FreeBSD appliance/jail. External pilot
interest provides a concrete next step.

The FreeBSD direction combines ZFS snapshots and rollback, lightweight jail
isolation, native service management, and host-level reverse proxy/Tailscale
access. The deployment work is documented in:

- [Running SafeBox on FreeBSD](FREEBSD-INSTALL.md)
- [FreeBSD Appliance Specification](devops/SAFEBOX-FREEBSD-APPLIANCE-SPEC.md)
- [FreeBSD Jail From-Scratch Runbook](devops/freebsd-jail-from-scratch.md)

The project has also been approached by a telecommunications provider wishing
to investigate a pilot for issuing and sharing health care records. The
provider cannot be identified because discussions are under a non-disclosure
agreement. This is exploratory and is not yet a finalized pilot or operating
commitment, but it is meaningful progress toward the Phase 3 operating-partner
and community-pilot milestones.

## Architectural Impact Beyond SafeBox

**In brief:** SafeBox has produced reusable architectural knowledge, now being
applied to digital trade documentation through a separate spin-off project.

The lessons around portable records, signed events, cryptographic control,
independent verification, and cross-system interoperability have resulted in
[OpenETR](https://github.com/trbouma/openetr). OpenETR applies these ideas to
electronic transferable records such as bills of lading, warehouse receipts,
promissory notes, and certificates.

OpenETR is a distinct project, not a SafeBox feature. Its emergence is still an
important Phase 3 outcome: the architecture has proven useful beyond payments
and personal or health records and can inform another demanding institutional
domain.

## Milestone Status and Next Steps

**In brief:** The product and demonstration milestones are substantially met;
partner and community milestones have moved into active exploration. The next
work should be pilot-led rather than another broad expansion of features.

1. **Product/service ready for deployment — largely complete.** Code is on
   `main` under the MIT License, with several documented deployment paths.
2. **Running demonstration used by test users — substantially complete.** The
   major payment, record, trust, agent, NFC, QR, and cross-instance workflows
   have been exercised and hardened.
3. **Willing operating partner — active exploration.** The NDA-protected telecom
   discussion is a credible opportunity, but no final commitment is claimed.
4. **Community ready to pilot — technical readiness established.** A health
   record pilot offers a possible bounded use case, subject to agreement on
   governance, privacy, support, operating responsibilities, and success
   criteria.

The next priorities are to simplify onboarding, improve user-facing language
and recovery guidance, broaden tests around failures observed in the pilot,
collect reliability and performance data, validate backup/restore with an
independent operator, and test interoperability between separately administered
instances.

## Overall Assessment

**In brief:** The project is on track, and I am pleased with the outcome of this
period. Phase 3 has largely achieved its intended transition from experiment to
pilot-ready product.

The remaining imperfections should be stated plainly: SafeBox has a broad test
matrix, long-lived proof state still deserves close observation, native
dependencies complicate some platforms, and the user experience contains
concepts unfamiliar to most users. These are real risks, but they are now best
addressed through a carefully bounded pilot.

The FreeBSD appliance work captures the progress well: SafeBox can be rebuilt
from documented dependencies, isolated, started automatically, secured,
snapshotted, upgraded, and recovered. The next phase is to learn from users and
operators and turn that evidence into focused product polish.
