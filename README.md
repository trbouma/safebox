# Nostr SafeBox
Your own private portable safebox on nostr!

## General Concept 

Nostr SafeBox is like those hotel safeboxes where you put your passport and money in while you are travelling. Digital travelling should be no different. You should be able to access your safebox whenever you need it - and get rid of it, when you no longer need it.

Still super-early - working on the concept of a ‘safebox’ for Nostr. It’s a generalization of the wallet concept for storing secure, private personal information.

The idea is that the safebox contains different item types, wallets, records, etc. You can give a client access by providing the `nsec` of the safebox. If you no longer trust the client, you can transfer the data to another safebox and delete the current one (no guarantees on deletion, of course)

In terms of nostr implementation, the safebox index will be a NIP44 encrypted replaceable event and the items within the safebox NIP44 encrypted parametrized replaceable events with opaque ‘d’ tags. The safebox has an ```nsec``` (it can be yours, not recommended ) or one generated by you or a custodial service. The safebox can be used by any service/client that knows the safebox ```nsec```

Initial implementation will be a Python class that is invoked by a command line utility for ease of development and testing. The eventual goal is to create a drop-in component for a custodial service.

The initial use case will be holding Cashu tokens for the purposes of accepting and sending payments via Lighting and Nostr.

You can install via pip. Make sure you have a virtual enviroment set up first
```
python3 -m venv .venv
source .venv/bin/activate
pip install git+https://github.com/trbouma/safebox.git
safebox info
```


Alternatively, if you have Poetry installed, you can do the following:
```
poetry new safebox
cd safebox
poetry add git+https://github.com/trbouma/safebox.git
poetry shell
safebox --help
```
You can see the help for each command, for example
```
safebox set --help
```

Before you start using, you need to set your nsec. 

```
safebox set --nsec <nsec> # Warning don't use your nsec you use as your identity!
```
You can add other relays and mints. For example to add relays:
```
safebox set --relays relay.damus.io,pub-nostr.wellorder.net
```
Don't bother adding the `https://` or `wss://` prefixes - they are added automtically. For a list of relays or mints specify the list separated by a comma (no spaces)



No guarantees. No promises of support. This is very experimental - more to come! 

![](./assets/safebox-nostr.png)
