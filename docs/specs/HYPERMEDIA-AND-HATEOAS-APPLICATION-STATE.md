# Hypermedia And HATEOAS Application State Strategy

## Overview

Safebox is evolving toward a hypermedia-first web architecture where server responses drive client state transitions directly. This follows a HATEOAS-style model (Hypermedia As The Engine of Application State): clients discover valid next actions from the current representation, instead of relying on hardcoded front-end flow logic.

The practical goal is to improve resiliency, simplify UX flow control, and make behavior more stable across browsers/devices/network conditions.

## Scope

This specification defines:

- Hypermedia/HATEOAS principles for Safebox web flows.
- Component placement and ownership boundaries.
- Migration direction for existing dynamic pages and action handlers.
- UI quality constraints, especially around jitter and layout instability.

## Why Hypermedia For Safebox

Safebox runs in an environment where:

- websocket state can reconnect/reorder,
- asynchronous payment and record flows can complete later than initial user action,
- users switch between mobile/desktop and constrained devices.

A hypermedia approach helps by:

- making state transitions explicit in server-driven representations,
- reducing stale client assumptions,
- lowering coupling between UI scripts and backend sequencing.

## HATEOAS Model

Each page/view should be treated as a state representation containing:

- current state data,
- available next actions,
- links/forms to execute those actions,
- and optional policy hints (timeouts, retry guidance, constraints).

Clients should:

- render current representation,
- trigger linked/form actions,
- and refresh view state from server responses rather than maintaining hidden local state machines where possible.

## Component Boundaries And Implementation References

### Web App Shell And Wallet Access

- Route/controller layer:
  - `app/routers/safebox.py`
  - `app/routers/records.py`
  - `app/routers/public.py`
- Template layer:
  - `app/templates/access.html`
  - `app/templates/pos.html`
  - `app/templates/mybalance.html`

### Reusable Payment Requests

Reusable Payment Requests are implemented in the access page as a dedicated section with server action binding:

- UI composition and form:
  - `app/templates/access.html`
  - section id: `reusable-request`
- request generation endpoint:
  - `/safebox/requestqr`
  - rendered into target container `#request_qr`

This section is a strong candidate for deeper hypermedia treatment because it naturally maps to:

- form submission,
- server-rendered result,
- and repeatable stateful interaction without heavy client-side orchestration.

### Event/Status Surfaces

Current runtime status mixes websocket events and UI-side conditionals. Hypermedia migration should standardize status surfaces so they can be rendered consistently as state transitions:

- `/safebox/ws/status`
- `/safebox/ws/notify`
- view-level status elements such as `#payment_notification`.

## UI Jitter And Stability Concerns

### Problem

“Jitter” in Safebox UI typically appears as:

- layout shift when dynamic content appears/disappears,
- status text causing panel reflow,
- image/QR/state swaps resizing containers,
- repeated updates from multiple async channels.

### Why It Matters

- Reduces trust during payment/record operations.
- Increases accidental double-actions.
- Makes older devices/browsers appear unreliable.

### Mitigation Guidelines

- Reserve fixed visual space for status and media regions.
- Keep image/QR containers dimensionally stable across state changes.
- Use state classes to toggle visibility without changing layout geometry.
- Coalesce duplicate async updates before repainting.
- Prefer deterministic “state blocks” (Idle/Processing/Complete/Error) over ad hoc text replacement.
- Avoid full-page reload as a primary state transition unless explicitly needed for recovery.

### HATEOAS Alignment For Jitter Reduction

By making the server return explicit next-state fragments (or whole representations), the client can:

- perform fewer speculative transitions,
- reduce conflicting updates from local heuristics,
- and preserve consistent layout scaffolding while content changes.

## Migration Strategy

1. Identify high-churn views (Access, POS, Offer/Grant flows).
2. Define canonical state representations for each operation.
3. Move “what happens next” decisions to server-side response semantics.
4. Keep client JS focused on transport/events and rendering only.
5. Gradually retire fragile query-parameter mode branching and duplicated UI side effects.

## Security Considerations

- Hypermedia does not replace cryptographic/payload controls; it complements them by reducing UI logic ambiguity.
- State transitions exposed as links/forms must still enforce auth, CSRF/session policy, and operation validation server-side.
- Async event handlers must not assume trust in transport ordering.

## Implementation References

- `app/templates/access.html`
- `app/templates/pos.html`
- `app/templates/mybalance.html`
- `app/routers/safebox.py`
- `app/routers/records.py`
- `app/routers/public.py`
