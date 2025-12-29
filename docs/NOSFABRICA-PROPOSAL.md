# Nosfabrica Hackathon Proposal

## Project Name: Acceptance Model - Extending the Web of Trust

The **Acceptance Model** expresses a simple idea:

> **Facts and views are not established by the system; they are resolved by statements made about them by trusted and authoritative actors.**

## Elevator Pitch  The Acceptance Model & Web of Trust

Everyone has a need to be able to issue and verify facts (i.e.,records) to anyone and from anyone without any sort of centralized gatekeeping organization getting in the way (technologically, morally or institutionally). Nostr Safebox, in addition to payments, is intended to embody this capability.

Key to this capability is the [Acceptance Model](./ACCEPTANCE-MODEL.md) which explains how records can become verifiable facts in decentralized systems — not by discovering truth, but by deciding when to stop asking questions of the system.

In the **Web of Trust**, nobody has global authority, just **Points of View** who can be trusted to what degree.  Similarly, with NOSTR, everyone can be their own **Issuing and Verifying Authority**. In this decentralized model, any actor can make assertions, others can issue attestations, and the system-level protocols objectively apply validation and recognition procedures to enable anyone to independently decide whose statements carry standing and trustworthiness. The **Acceptance Model** extends the **Web of Trust** to give a clear lineage for any issued record and to enable any verifier to be prepared to treat any claim as settled (or not) and act on it.

Rather than assuming truth is objective or centralized, the model recognizes that system facts are the result of objective procedural outcomes facilited by a unbiased protocol. The protocol does produce 'facts' but rather a 'fact' emerges when a verifier accepts a chain of signed statements: based on cryptographic validity of assertions and attestations by recognized actors have sufficient trust signals. The verification halts when the system cannot do more. In the end, the **Web of Trust** or **Acceptance Model** does not produce 'truth' — it affords acceptance based on what is made available by the system. The **Acceptance Model** extends the **Web of Trust** to makes the process explicit, inspectable, and programmable. The **Web of Trust**, extended by the **Acceptance Model** makes it directly applicable to Nostr Safebox and any decentralized identity and authorization system where trust is earned and discerned rather than imposed by an authority.

## Problem & Solution

The problem is that most protocols and platforms reinforce the inequitable status quo. Users are at mercy of platforms, apps and protocols. 

Using Nostr Safebox as the solution, every user (i.e., every npub - there is no distinction between human and machine) is considered equal - a first class citizen, without discrimination. This includes equal access to all capabilities of the Nostr network to be an **issuer**, **verifier** and **holder** of records that can be accepted as being authentic and attested by trustworthy participants.

The overall model being developed is inspired by **zero trust networks** and is employing free and open access components such as a **control plane** to make trust (acceptance) decisions, and a **data plane** to securely communicate data.

In the end, the solution hopes to move the needle of control back toward the user. Maybe not 100%, but enough for users to realize that they have independent agency in what they do and there is reduced reliancy on vendors and providers that have captured many ecosystems, such as health and social media.

## Current state 

This current proposal builds on what was developed for the first Nosfabrica Hackathon which resulted in a secure, direct record-sharing capability between Nostr Safebox instances. For this hackathon, this capability is being extended to share verifiable **private records** which can be issued from one Safebox user to another, who then can verify and accept the record based on its **cryptographic validity**, **owner attestation**, and **web of trust standing**.

Most of the components have been architected and are under construction; the goal by the end of the hackathon is to practically demonstrate how a physician can issue a prescription (private record) to a patient, and the patient can present the prescription to a pharmacist or health card provider who can independently verify that the prescription has not been tampered with, was issued by a safebox under the control of the physician, and that the physician has proper authoriative standing, and is trusted (reputable).

The [Acceptance Model](./ACCEPTANCE-MODEL.md) under development will be refined during the course of the hackathon and is intended to leverage the ongoing discussions and to test out the following NIPS and specifications (non-exhaustive):

- [Attestations](https://nostrhub.io/naddr1qvzqqqrcvypzp384u7n44r8rdq74988lqcmggww998jjg0rtzfd6dpufrxy9djk8qy28wumn8ghj7un9d3shjtnyv9kh2uewd9hsqrrpw36x2um5v96xjmmwwvuhdk8z)
- [NIP-85 Trusted Assertions](https://nostrhub.io/naddr1qvzqqqrcvypzq3svyhng9ld8sv44950j957j9vchdktj7cxumsep9mvvjthc2pjuqy28wumn8ghj7un9d3shjtnyv9kh2uewd9hsqyn5wf6hxar9vskkzumnv4e8g6t0deesu5l7ne)
-[Properties for Decentralized Lists](https://nostrhub.io/naddr1qvzqqqrcvypzpef89h53f0fsza2ugwdc3e54nfpun5nxfqclpy79r6w8nxsk5yp0qy28wumn8ghj7un9d3shjtnyv9kh2uewd9hsqgnswfhhqetjw35k2uedvehhyttyv43k2mn5wfskc6t6v4jz6mrfwd68xy0e5q2)
- [Trust Registry Query Protocol](https://trustoverip.github.io/tswg-trust-registry-protocol/)

## Roadmap & Future scope

The focus on the **Prescription Use Case** is intended to demonstrate and drive out requirements for a generic decentralized issuance and verification capability that is outside the control of any one organization (permissionless), and which should be instead, built using a more fundamental protocol, such as Nostr. This proposal is also intended to crystallize some emerging concepts such as the **control plane** using NOSTR which can be a permissionless alternative to **public registries** that are REST/API gateways to platform-controlled databases. The capability being developed as part of this hackathon has applicability in many areas and disciplines, such as:

- Skilled Trades Certification
- Educational Credentials
- Official Government Documentation
- Any polity (i.e., network state) that wishes to stand up a resilient digital infrastructure. 

Potential scenarios for use include:

- [Community Led Recordkeeing](./POLICY-BRIEF.md)
- [Indigenous and Northern Development](./NortherLinkCaseStudy.md)

This proposal is complementary to ongoing work outline in the [Phase3 Proposal](./PHASE3-PROPOSAL.md) currently funded by [OpenSats](https://opensats.org)