# Web Wallet User Considerations

## Overview

This document captures the user-experience considerations for the Safebox web wallet based on the current hardening and polish pass. It records the rationale for major UI behaviors so future changes can preserve flow clarity, reduce user error, and keep security-relevant actions understandable.

This web UX is the current reference implementation. Once it is stable and validated in field use, it should serve as the baseline interaction model for native mobile app development.

## Scope

In scope:

- `/safebox/access` wallet landing and action hub
- In-session payment actions (scan, POS, clipboard import, direct send)
- Receive/payment-address presentation
- Status communication and completion feedback
- Visual hierarchy for frequent vs occasional actions

Out of scope:

- Full POS workflow details (covered in POS/NFC specs)
- Record protocol internals and nAuth handshake details
- Agent API and machine-only interaction paths

## Core UX Principles

1. Prioritize high-frequency actions first.
2. Keep transactional state visible without intrusive popups.
3. Minimize accidental taps and wrong-flow entry.
4. Preserve safety context for sensitive operations.
5. Keep labels short, literal, and action-oriented.

## Current UX Decisions

### 1) Top Action Cluster

The top panel now groups immediate actions:

- `Scan`
- `Point of Sale`
- `Copy from Clipboard`

Rationale:

- These are in-the-moment actions and should be reachable first.
- Grouping improves one-handed mobile usage and reduces scan-to-action delay.
- Slightly increased vertical separation improves tap targeting accuracy.

### 2) Helper Text Only for Immediate Actions

Helper text is intentionally limited to top actions:

- `Scan QR code`
- `Receive payments in person`
- `For invoices or ecash tokens`

Rationale:

- Clarifies intent where users move quickly.
- Avoids clutter in lower-frequency sections.
- Keeps long-lived management sections clean.

### 3) Simplified Receive Section

`Request a Payment` was changed to `My Payment Address` and stripped to:

- QR image
- Lightning address text

Rationale:

- The section is now informational/receiving-focused.
- Invoice-entry controls were redundant with POS and other dedicated flows.
- Lower cognitive load and fewer error-prone fields on the main wallet page.

### 4) Compact Section Labels

Major section headings were converted from prominent heading blocks to compact labels.

Examples:

- `My Payment Address`
- `Make a Payment`
- `My Records`
- `Community`
- `Reusable Payment Request`
- `My Account`
- `Technical Info`

Rationale:

- Reduces vertical consumption and visual heaviness.
- Preserves structure while improving information density.
- Better matches mobile-first scanning behavior.

### 5) Consistent Action Wording

Button labels were normalized for clearer intent:

- `Pay to Recipient` -> `Send Payment`
- `Pay with Ecash` -> `Redeem Ecash`

Rationale:

- Uses explicit verbs tied to user intent.
- Reduces ambiguity for new users.

### 6) Inline Status over Modal Alerts

The wallet favors inline status updates (`payment_notification`) over `alert()` dialogs for routine flow feedback.

Rationale:

- Avoids blocking interaction.
- Preserves context during asynchronous operations.
- More consistent across browser/platform variations.

### 7) Freshness Indicator for Balance

A `Last updated` timestamp is shown and refreshed when wallet updates are processed.

Rationale:

- Improves trust in real-time state.
- Helps users distinguish pending vs stale states.
- Useful on slower or lossy networks.

### 8) Visual Risk Cue for Dangerous Actions

`Danger Zone` is styled as a distinct risk action.

Rationale:

- Reinforces consequence awareness.
- Reduces accidental navigation into destructive workflows.

## Behavioral Expectations

1. A user should identify how to send, receive, and scan within one screenful.
2. Payment status should remain visible without modal interruption.
3. Common action buttons should be easy to target on mobile.
4. Lower-frequency management functions should be available but visually de-emphasized.
5. Error and progress messages should be specific and non-ambiguous.

## Accessibility and Device Considerations

- Maintain high-contrast text/button styles in panel backgrounds.
- Preserve consistent button width and spacing for touch interaction.
- Prefer short labels and predictable section order for quick scanability.
- Avoid dependence on hover-only affordances.

## Mobile App Baseline Statement

This web wallet UX is the intended baseline for native app UX design once field stability criteria are met. Native implementations should preserve:

- Primary action ordering
- Status signaling model
- Risk signaling conventions
- Terminology and button semantics

Platform-native interaction patterns may differ, but these behavioral invariants should remain consistent to avoid user retraining and cross-surface confusion.

## Security Considerations

- UX must not expose sensitive values unnecessarily in default state.
- Status/error messaging should avoid leaking private balance or secret details where not required.
- High-risk actions should retain explicit visual distinction.
- Async operations should avoid misleading “completed” states before settlement confirmation.

## Implementation References

- `app/templates/access.html`
- `app/templates/pos.html`
- `app/templates/uxbase.html`
- `app/routers/safebox.py`
- `app/routers/scanner.py`

