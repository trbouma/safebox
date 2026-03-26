# Web of Trust Hackathon Deck

## Slide 1: Safebox: Web of Trust Record Verification

### Subtitle

Issued, Held, Presented, Verified

### Content

- Safebox logo
- A Nostr-native wallet and records system with staged trust verification.

### Speaker Note

Introduce Safebox as a Nostr-native wallet and records system and frame the talk around a simple issued-to-holder verification flow.

State the motivation explicitly:

- Safebox is intended to be “client-zero”
- a playful variation on “patient-zero”
- meaning an early real client that demonstrates the practical potential of the Web of Trust work emerging from this group

Call out that this demo is grounded in the NIPs and protocol work already being established here, especially:

- NIP-85 Trusted Assertions
- Attestations

---

## Slide 2: Identity Neutrality

### Content

- `npub = base unit of accountable identity`
- No protocol distinction between:
  - person
  - agent
  - service
  - device
  - Safebox instance

### Speaker Note

Explain that Safebox and Nostr do not hard-code identity classes. Roles like issuer, holder, presenter, and verifier are functional roles built on top of the same identity primitive.

Tie this back to the “client-zero” idea:

- if these NIPs are going to matter, they need to be exercised by a real client
- Safebox is trying to be that proving ground for Web of Trust flows

---

## Slide 3: How Safebox Decides Enough Is Enough

### Content

- `Validated`
  - Valid signature
- `Attested`
  - Owner control claim
- `Recognized`
  - Issuer in verifier WoT
- `Trusted`
  - Advisory score inputs
- `Accepted`
  - Verifier proceeds

### Speaker Note

Explain that Safebox does not declare ultimate truth. It gives the verifier structured evidence to decide when enough checks have passed to act.

Mention that this is where the NIP work becomes concrete:

- Attestations support ownership and issuer assertions
- NIP-85 supports trusted advisory signals
- Safebox combines them into a verifier-facing acceptance flow

---

## Slide 4: What You’re About To See

### Content

1. Issuer sends signed record to Holder
2. Holder presents record to Verifier
3. Verifier confirms:
   - `Valid`
   - `Self-Presented`
   - `Recognized`

### Suggested Visual

`Issuer -> Holder -> Verifier`

### Speaker Note

Set up the live demo and tell the audience exactly what three fields to watch for on the verifier screen.

---

## Slide 5: Reusable WoT Building Block

### Content

- Not limited to one vertical
- Works for records, credentials, attestations, and agent flows
- Verifier-local trust policy
- Interoperable Nostr-native model

### Speaker Note

Close by positioning the demo as a reusable trust primitive rather than a one-off application flow.
