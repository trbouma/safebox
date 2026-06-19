# HATEOAS Backlog

This backlog captures the remaining work to move Safebox further toward a
hypermedia-first architecture while preserving the pragmatic realtime behavior
that is useful for payments, NFC interactions, and wallet status updates.

## Current State

Safebox is no longer primarily a JavaScript redirect application. The access
page now uses real links for simple navigation, real POST form endpoints for
core browser payment actions, and server-rendered page state for scanned and
loaded payment inputs.

At the same time, the application still intentionally uses websocket and
polling-based enhancements for live settlement feedback. The current system is
best described as a hybrid:

- Hypermedia-first for navigation and ordinary browser actions
- Realtime-enhanced for payment settlement and device-driven flows

This document is a backlog for continuing that transition in a deliberate way.

## Backlog

### 1. Access page: finish browser-action normalization

- Replace remaining JS-only submit behaviors where practical
- Standardize success/error notices through server-rendered flash messages
- Goal: all ordinary browser actions on `/safebox/access` should be link/form driven

### 2. Access page: isolate realtime UX from navigation/state transitions

- Keep websockets only for live status updates
- Do not let websocket handlers own page navigation
- Goal: websockets enhance the page, but the page still works as a server-driven document

### 3. Scanner flow: move to explicit server handoff patterns

- Treat scan results as redirects into canonical GET routes with query/state
- Reduce custom client branching after scan
- Goal: scanner returns users to a real server state, not a JS-only mode switch

### 4. Records pages: replace remaining JS navigation helpers

- Audit `offer`, `grantlist`, `retrieve`, `present`, `request`
- Convert add/edit/manage transitions to links/forms where possible
- Goal: records workflow becomes bookmarkable and server-state driven

### 5. Record actions: add PRG endpoints consistently

- For issue/accept/request/present flows, use POST -> redirect -> GET
- Avoid direct JS fetch for ordinary browser-originated state changes
- Goal: browser behavior becomes predictable and reload-safe

### 6. Flash message system

- Create one standard notice mechanism for:
  - success
  - error
  - advisory
  - pending
- Reuse it across access, records, invite, POS fallback pages
- Goal: remove ad hoc notification handling

### 7. Page-state contracts

- Formalize server-rendered view-state values for major pages
- Examples:
  - `idle`
  - `invoice_loaded`
  - `invoice_amount_required`
  - `lnaddress_loaded`
  - `creq_loaded`
  - `ecash_loaded`
- Goal: client JS enhances known server states instead of inventing state locally

### 8. Transaction history and detail pages

- Audit `txhistory`, `privatedata`, message detail, inbox, grant detail pages
- Ensure navigation is link-based and tables/details degrade cleanly without JS
- Goal: read-only pages should be fully hypermedia-native

### 9. POS boundary decision

- Decide explicitly whether POS remains a JS/websocket application
- If yes, document it as an intentional exception to the HATEOAS direction
- Goal: avoid pretending POS should follow the same constraints as ordinary account pages

### 10. NFC/Web NFC boundary decision

- Treat NFC interactions as capability-driven exceptions
- Wrap them around server endpoints rather than letting them define app structure
- Reference: `docs/HTMX-NFC-CONSIDERATIONS.md` documents why global `htmx` boosting must not control NFC/device-runtime entry points
- Goal: keep NFC as an enhancement layer, not the primary navigation model

### 11. Remove dead client code

- Audit templates for obsolete redirect helpers, stale handlers, and duplicate UI paths
- Goal: reduce ambiguity about which path is canonical

### 12. Documentation pass

- Add a short architecture note:
  - what is hypermedia-first
  - what is intentionally realtime/client-driven
  - what exceptions remain
- Goal: keep future work from drifting back into mixed patterns accidentally

## Suggested Execution Order

1. Records workflow cleanup
2. Flash message system
3. Scanner handoff normalization
4. Read-only/detail page audit
5. POS/NFC architectural exception documentation

## Practical Position

Safebox does not need to become HATEOAS-pure to benefit from HATEOAS.

The practical goal is:

- server-rendered navigation
- server-owned page state
- forms for ordinary browser mutations
- realtime enhancements only where they materially improve UX

That keeps the application understandable, reload-safe, and easier to maintain,
while still supporting the payment and device behaviors that make Safebox
useful.
