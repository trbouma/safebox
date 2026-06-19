# HTMX and Web NFC Considerations

This note documents an implementation constraint discovered during the `webapp-cleanup` work: global `htmx` boosting and Web NFC flows do not mix well when `htmx` is allowed to intercept the same links and forms that are responsible for NFC page setup or NFC-triggered actions.

Safebox can use both `htmx` and Web NFC on the same page, but they must have clearly separated responsibilities.

## Summary

The short version is:

- `htmx` is good for partial page updates, fragment refresh, and ordinary document-style navigation.
- Web NFC is sensitive to browser lifecycle, inline script initialization, and direct user-gesture event handling.
- When a link or form involved in an NFC flow is globally `hx-boost`ed, the browser may no longer treat the interaction like a normal full-page navigation or plain form submit.
- That can break page-scoped NFC JavaScript in ways that look like “NFC is broken,” even when the underlying NFC routes and token logic are fine.

The correct design rule is not “never use `htmx` with NFC.” The correct rule is: do not let `htmx` control the NFC entry points.

## What Regressed

During cleanup, the shared shell enabled global boosting:

- `app/templates/uxbase.html`
  - `<body hx-boost="true">`

That changed the behavior of ordinary links and forms throughout the app.

Two regressions followed:

1. `Issue Card` stopped behaving reliably for card read/write.
2. `Pay to NFC Tag` on the access page stopped behaving like a normal user-driven submit flow and lost some expected browser behavior, including the explicit confirmation step.

The NFC logic itself had not fundamentally failed. The problem was that `htmx` was now sitting in the middle of browser actions that need to remain direct.

## Why Web NFC Is Different

Web NFC is not just another async API call. It depends on several browser-side conditions that are easy to disrupt:

- the page needs to be initialized in a normal browser context
- the correct inline or page-scoped JavaScript needs to be active
- the NFC action often must happen inside a direct user gesture chain
- the timing of `scan()` or `write()` matters
- swapping DOM fragments is not equivalent to a normal page load

For ordinary HTML forms and links, `htmx` interception is often harmless or beneficial. For Web NFC flows, it can alter the exact event path that the browser API expects.

## Concrete Regressions in Safebox

### 1. Issue Card page

The `Issue Card` page depends on page-local JavaScript in:

- `app/templates/issuecard.html`

That script defines the functions used for:

- `readTag()`
- `writeTag()`

When the page was reached through a globally boosted link, it could be loaded as an `htmx`-managed navigation rather than a plain browser navigation. In practice, that made the page behave differently enough that NFC read/write no longer worked reliably.

The fix was to opt that link out of boosting:

- `app/templates/access.html`
  - `<a id="issue_card" class="action-button" href="/safebox/issuecard" hx-boost="false">Issue Card</a>`

### 2. Pay to NFC Tag flow on access page

The NFC payment flow on the access page is controlled by JavaScript in:

- `app/templates/access.html`

The relevant path is:

- user submits the regular payment form
- `handlePaymentFormSubmit(event)` checks whether the recipient is `NFC Tag`
- if so, the handler prevents the normal form post and calls `paytoNFC()`
- `paytoNFC()` starts the NFC scan and then calls `submitNFCPayment(...)`

This is a browser-controlled runtime flow, not a plain document submit flow.

When the form lived under global boosting, the risk was that `htmx` would participate in submit handling in a way that interfered with the direct JavaScript branch used by the NFC path.

The fix was to opt the relevant forms out:

- `app/templates/access.html`
  - `/safebox/access/forms/pay`
  - `/safebox/access/forms/payinvoice`
  - `/safebox/access/forms/acceptecash`

Those forms now use `hx-boost="false"`.

## Current Safebox Guardrails

At the time of writing, Safebox uses global boosting at the shell level:

- `app/templates/uxbase.html`

But NFC-sensitive controls are explicitly carved out:

- `app/templates/access.html`
  - `Issue Card` link: `hx-boost="false"`
  - payment form: `hx-boost="false"`
  - invoice payment form: `hx-boost="false"`
  - ecash accept form: `hx-boost="false"`
  - `My Balance (NFC)` link: `hx-boost="false"`

This is the correct pattern: broad `htmx` use for the document-oriented app, local opt-outs for device/API-sensitive paths.

## Design Rule

Use `htmx` for:

- server-rendered fragment updates
- balance refreshes
- QR fragment rendering
- partial page interactions
- ordinary links and forms that do not depend on special browser APIs

Do not let `htmx` own:

- Web NFC read/write entry points
- camera or scanner flows that depend on direct browser gesture handling
- clipboard or permission-sensitive flows where browser gesture chains matter
- pages whose critical behavior is initialized by page-scoped script and expects a normal full-page load

## Recommended Implementation Pattern

For pages that combine `htmx` and NFC:

1. Keep `htmx` for non-device UI behavior.
2. Keep NFC actions behind explicit JavaScript button handlers.
3. Use `hx-boost="false"` on links/forms that open NFC pages or initiate NFC actions.
4. Treat NFC flows as app-runtime behavior, not document navigation behavior.
5. Avoid relying on an `htmx` swap to “initialize” a page that uses browser device APIs.

This lets both models coexist without fighting each other.

## UX Implications

Another lesson from this work is that NFC flows should present action-specific prompts rather than generic submit prompts.

For example, the payment confirmation for NFC should say:

- `Ready to tap the recipient NFC tag?`

That reflects the actual next step in the browser/device flow, which is different from a normal payment confirmation.

## Testing Guidance

Whenever global shell behavior changes, re-test at least these NFC-sensitive paths:

1. Access page -> `Issue Card` -> `Card Read`
2. Access page -> `Issue Card` -> `Card Write`
3. Access page -> pay to `NFC Tag`
4. Access page -> request payment from NFC card
5. Any page reached from an NFC-oriented link that relies on page-local JavaScript

If NFC breaks while the backend routes still look correct, inspect the navigation and submit layer before changing token formats, route logic, or cryptography.

## Practical Lesson

The main lesson is:

Global `htmx` boosting is too broad for device-sensitive workflows.

`htmx` and Web NFC can absolutely coexist in Safebox, but NFC entry points need explicit carve-outs so the browser stays in control of the interaction lifecycle.
