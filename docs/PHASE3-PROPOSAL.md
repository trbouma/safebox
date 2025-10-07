# Nostr Safebox Phase 3
## Description
 
 Nostr Safebox is a fully functional wallet that is native to the nostr network. The initial version (Phase
1, funded by Opensats) took its inspiration from NIP-60 where Cashu tokens are stored as encrypted events on relays, and whoever has the corresponding nsec can access and spend the tokens. Phase 1 was successfully delivered. 

Now Nostr Safebox is evolving into a wallet that can offer and receive records, such as health records, badges, tickets, or any type of personal record that is important to the user. These records can also be selectively presented as 'credentials' which can be verified. This work was done as Phase 2 (self-funded and with an award of 4M sats from nosfabrica to support the development of decentralized health record ecosystem.). Phase 2 will be largely complete by August 2025.

During Phase 2, several key innovations have emerged along the way and will be consolidated in this project, or Phase 3. The payments wallet is complete, using the Cashu protocol as a Layer 3 micropayment transfer. Further experimentation has yielded an approach that allows a simple NFC card to be used to make payments, accept payments, offer records and accept records using an extension of Nostr Wallet Connect (NWC). The NFC card has massive potential to enable the distribution of a fully functional wallet to populations who may not have phones. Also, in developing the secure record sharing for health records, the nostr secure messaging (NIP-17, NIP-59, NIP-44) were used to develop a secure record transmittal protocol called nAuth. An agnostic Bech32 record encoding scheme was also developed, called nembed. This revealed the potential of a wallet that
can securely manage both "funds" and "records" for the user.

Phase 3 - the focus of this project, is about taking the experimental features developed in Phase 2 and 'scaling' and 'hardening' these features in different dimensions to enable Safebox to become a real product that can serve diverse ecosystems stakeholders. This entails building multiple instances and implementations that can interoperate with one another, ensuring that Safebox can scale to robustly support a service that could support thousands if not millions of users, and building in the discipline of a commercial product (testing, QA, support, documentation, etc.)

## Potential Impact
Phase 1 and Phase 2 have proven that Nostr Safebox using the nostr protocol can be the decentralized backbone for private payments and private records. Furthermore, it has been demonstrated that it is possible to build an application using the nostr protocol that is independent of mobile OS platforms and centralized services. This is crucial to remove the potential chokepoints that can demobilize a user or expose them to harm.

So far, this project (Phase 1 and Phase 2) have demonstrated that the nostr protocol is far more than an alternative social media protocol - nostr has the potential to reconfigure global services, dethrone centralized services, and defang government enforcement. If done right, the nostr protocol can be as
consequential as TCP/IP in reconfiguring the global communication networks 35 years ago. Back then, it was the network routable packets - nostr is about cryptographically signed events. This project has revealed the potential to make global changes.

Phase 3 is about showing a community that, with Safebox, or more generally with the nostr protocol they can build capabilities that are not at the whim of governments and commercial providers. Timeline & Milestones

The goal of Phase 3 is to have a Nostr Safebox product/service ready for "Community Pilot" by early-mid 2026. Simply put, well-baked enough that it is ready for a community to trust and pilot. 

## Milestones

The milestones for the conclusion of the project and Phase 3 are:
1. A product/service ready for deployment (code in Github repo under MIT License),
2. A running demonstration instance used by test users
3. A willing operating partner (organization willing to operate the service
4. A community that is ready and willing and ready to pilot.

