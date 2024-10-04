# Nostr Safebox
Your own private portable safebox on nostr!

*Just want to try it out? [Get the binary executables](https://github.com/trbouma/safebox-binaries).*

*You can follow my development journey on Nostr [here](https://tim-bouma.npub.pro/tag/safebox).*

## General Concept 

Nostr Safebox is like those hotel safeboxes where you put your passport and money in while you are travelling. Digital travelling should be no different. You should be able to access your safebox whenever you need it - and get rid of it, when you no longer need it.

Still super-early - working on the concept of a ‘safebox’ for Nostr. It’s a generalization of the wallet concept for storing secure, private personal information.

The idea is that the safebox contains different item types, wallets, records, etc. You can give a client access by providing the `nsec` of the safebox. If you no longer trust the client, you can transfer the data to another safebox and delete the current one (no guarantees on deletion, of course)

In terms of nostr implementation, the safebox index will be a NIP44 encrypted replaceable event and the items within the safebox NIP44 encrypted parametrized replaceable events with opaque ‘d’ tags. The safebox has an ```nsec``` (it can be yours, not recommended ) or one generated by you or a custodial service. The safebox can be used by any service/client that knows the safebox ```nsec```

Initial implementation will be a Python class that is invoked by a command line utility for ease of development and testing. The eventual goal is to create a drop-in component for a custodial service.

The initial use case will be holding Cashu tokens for the purposes of accepting and sending payments via Lighting and Nostr.



Detailed install instructions are being developed [here](./INSTALL.md).

In the meantime, f you have Poetry installed, you can do the following:
```
poetry new sbtest
cd sbtest
poetry add git+https://github.com/trbouma/safebox.git
poetry shell

```
If you are feeling wreckless and want the latest code, do this `poetry add` instead
```
poetry add git+https://github.com/trbouma/safebox.git#latest-development
```


General help. Warning - everything is not fully implemented yet!
``` 
safebox --help
Usage: safebox [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  accept   Accept cashu token
  balance  show balance
  check    Check for payment
  delete   Delete proofs
  deposit  deposit funds into wallet via lightning invoice
  get      get a private wallet record
  info     display info
  init     initialize a new safebox
  pay      Payout funds to lightning address
  post     Do a post
  profile  display nostr profile
  proofs   list proofs
  put      help for put
  receive  Receive cashu token
  set      set local config options
  swap     swap proofs for new proofs
```
You can see the help for each command, for example
```
safebox set --help
```
You need to set some boot relays and mints, first. For example to add relays:
```
safebox set --relays pub-nostr.wellorder.net
safebox set --mints mint.belgianbitcoinembassy.org
```

Don't bother adding the `https://` or `wss://` prefixes - they are added automtically. For a list of relays or mints specify the list separated by a comma (no spaces)


To create a new safebox:
```
safebox init
```
To see how your safebox has been created on nostr.  
```
safebox profile
```
If it is successful, you will see something like below: a fancy memorable name, the profile information and an `#introduction` post.

```
--------------------------------------------------------------------------------
Profile Information for: Abstract Sticky Macaw Of Debate
--------------------------------------------------------------------------------
npub: npub1yryug4wku085eu0y85y4csy6x8tjgph55qq33npj0yt4a9mg3fcs48p6fk
nsec: nsec1y2zltqrn0ayhm8v73zlurqd5kaur09dj6lyddvjxxx5dz8fyphsq9wvnke
--------------------------------------------------------------------------------
name           : stickymacaw
display_name   : Abstract Sticky Macaw Of Debate
about          : Resident of Fancy Sea Spa
picture        : Not set
nip05          : Not set
banner         : Not set
website        : Not set
lud16          : Not set
--------------------------------------------------------------------------------
Mints ['https://mint.belgianbitcoinembassy.org']
Relays ['wss://nostr-pub.wellorder.net']
--------------------------------------------------------------------------------
Hello World from stickymacaw! #introductions

```
You deposit funds
```
safebox deposit 21
# Pay the invoice and then run the follow
safebox check invoice
```
You can pay to a lightning address
```
safebox pay 19 creampanther1@primal.net -c "This is from safebox!! "
# Check your balance
safebook balance
# Check your proofs
safebook proofs
```
You can put and retrieve secret information!
```
safebox put mypassphrase "The wolf howls at midnight"
Do you want to continue? [y/N]: Y
safebox get mypassphrase
The wolf howls at night
```






No guarantees. No promises of support. This is very experimental - more to come! 

![](./assets/safebox-nostr.png)
