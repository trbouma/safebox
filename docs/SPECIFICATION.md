# Safebox Reference Implementation Specification
## Introduction
Currently, safebox is being prototyped and implemented using Python. As features and functions stabilize, they will be documented here for other reference implementations.

### NIPS
Safebox takes its primary inspiration from [NIP-60 Cashu Wallet](https://github.com/nostr-protocol/nips/blob/master/60.md). 
 * `kind:37375` is used to manage wallet configuration and state
 * `kind:7375` is used to store proofs that are used to generate Cashu tokens
 * `kind:7376` is not used.

All other NIPS are implemented to be compliant

* NIP-01 for core interoperability with NOSTR
* NIP-17 for secure messaging
* NIP-57 for zaps

 ### Cashu
 Safebox uses Cashu for its management of funds. 

 ### Lightning
 Safebox uses Lightning for Layer 2 bitcoin interoperability.

 ### Bitcion 
Safebox depends on for Layer 1 bitcoin interoperability.