# Nostr Safebox NOVEMBER 2024
## Progress Report # 1: Nov 2024 - Feb 2025

[Initial Proposal](INITIAL-PROPOSAL.md)

## 1) How did you spend your time?

- I used the time to achieve the deliverables outlined in my project proposal:
    - A stable prototype implemented in Python. Code repo is [here](https://github.com/trbouma/safebox)
    - Compiled binaries for mac-os and ubuntu. Binary repo is [here](https://github.com/trbouma/safebox-binaries)
    - Demonstrated of backend integration for [openbalance.app](https://openbalance.app)
    - Draft specification - an Open API REST API [docs](https://openbalance.app/docs) 

- The majority of my time was dedicated to engineering, coding and operations. My estimate is that I spent 20 plus hours each week since the beginning of the grant. Overall for the grant period I spent (conservatively) 250 hours of development time. 
- I also spent a week (Dec 8-15,2024), meeting in-person with the Sovereign Engineering Cohort to demonstrate and discuss the Safebox concept.
- A considerable amount of time was dedicated to experimenting, engineering and architectural design. Mostly, figuring out how to make things work in a scalable way with relays and integrating with failure-prone mints and lighting address services. Another significant amount of time was dedicated to refactoring code that the core component could be deployed either in a synchronous or asynchronous context.
- Approximately 15,000 lines of code have been written for the core components collectively called 'Acorn', invoked by a cli (safebox) and a web app called 'GetSafebox'.
- A REST API has been developed for clients wishing take advantage of the web app implementation. The documented OpenAPI interface can be found here. [docs](https://getsafebox.app/docs)
- Significant effort was expended to develop and implement a robust proof management system for the storing, redeeming and swapping of Cashu proofs in a multiple mint scenario. Also significant effort was expended to ensure tight integration with the Nostr ecosystem - the core component supports the sending and recieving of zaps, either to an event, to an owner's public key (npub) or their NIP-05 address.
- The core wallet functionality has been implemented as per the NIP-60 specification. Specifically, the wallet configuration data have been implemented as kind 37375, and Cashu proofs implemented as kind 7375. 
- Additional security safeguards for Safebox implementation have been implemented, beyond the scope of NIP-60, but necessary to work in an adversarial environment. For example, the #d tag is hashed using the private key as one of the the seeds. Only the owner of wallet who has knowledge of the  private key and the correct label can generate the #d tag to locate the record. 
- Additional functionality has been implemented to support the secure transmittal of records between Safebox instances using NIP-44 encryption and NIP-59 Gift Wrapping. 
- In carrying out the project, I have developed a decentralized authentical protocol, which I am calling #nAuth, and have contributed to developing an embedded bech32 format called nembed to transmitt health records.
- At the conclusion of this project, I have proven to myself and others that it is possible to create a payment and personal data wallet that exists 'out in the network' (in relays) that is independent of device, app, or platform. I am ready for the next phase.

Summary of Proof of Work: 
- Over 400 commits to [main branch](https://github.com/trbouma/safebox/tree/main), 2 forks of the repo and 31 stars
- Runing demo instance of web [here](https://getsafebox.app). Invite code can be provided upon request.
- Blogging in real time on Nostr using the hashag [#safebox](https://tim-bouma.npub.pro/tag/safebox). Many of the insights I gained during the project have been documented in real-time here.

## 2) What do you plan to work on next quarter?

- As indicated in my proposed Phase 3 (not yet funded) is about 'Scalability'. That is, 'scaling' Safebox in different dimensions to become a real product that can serve diverse ecosystem stakeholders. In this last phase I have proven that the core mechanisms work. This phase entails building or supporting other reference implementations that can interoperate with one another, ensuring that Safebox can scale to support a service and/or ecosystem that could support thousands if not millions of users.
- Building in the discipline of a commercial product (testing, QA, support, documentation, etc.). This requires significant effort to build on the test cases, perform regression testing, and be positioned to provide effective maintenance and product support to anyone wishing to operate Safebox as a service.
- This phase intends to zero in on a use case that could have a positive systemic benefit to an ecosystem. I have identified that a payments-first wallet with health records capability is the best option to demonstrate a systemic benefit.
- I have identified partners, namely Nosfabrica to develop capabilities for storing and transmitting health records between physician and payments using Nostr Safebox. Also, a partner servicing a health care institution in a developing country has expressed interest to partner. 
- I also want to focus on understanding the dev ops requirements. Finding out what is required to set up a highly-available, failover-capable service, impervious to cyber-attacks, and which can scale to serve thousands (millions) of users.
- NIP-60 compatibility of other implementations will also be explored. The main focus will be on embedded solutions where a minimal Safebox could be implemented for embedding into hardware, such a network router for accepting payments (TollGate Project)

## 3) How did you make use of the money?*

- To fund the opportunity cost of my time. It works out to approximately $40 USD per hour as personal income.
- Since the grant is over the 2024/2025 period, I will be claiming 33% of the grant as income for the 2024 taxation year and 67% of the grant as income for the 2025 taxation year.
- To fund operating costs. The supporting infrastructure for my project (hosted lightning node, servers, etc) costs me approximately $100USD per month.
- To fund travel (as after tax). As a result of the grant, I had sufficient funds to travel  to have in-depth in-person discussions with the sovereign engineers. A tangible example was tighter compliance to NIP-60 after discussion the pros and cons with the NIP author.

## 4) Is there anything we could help with?**

- Continued grant support. Details will be in next proposal application. 
- Introductions to interested stakeholders who wish to create a decentralized infrastructure that first and foremost respects the needs of every user. The initial focus is health care in developing countries.
