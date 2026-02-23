# Mobile App Development Strategy (Flutter, Android First)

## Overview

This document defines the strategy for building a Safebox mobile app with:

- Android as the first production target
- iOS support from the same codebase as a planned second target
- Flutter as the primary framework for UX consistency and development speed

The product direction is to mirror the operational strengths of the current web wallet while adopting a mobile-native interaction model inspired by strong Nostr mobile clients (including the design language seen in Divine-style apps).

## Goals

1. Deliver a stable Android app first.
2. Avoid Android-only architecture decisions that block iOS.
3. Preserve existing Safebox protocol behavior (NWC, nAuth, nembed, NFC flows).
4. Reuse backend endpoints and security guarantees already proven in web flows.
5. Provide a responsive, low-jitter mobile UX for payments, records, and NFC interactions.

## Non-Goals (Phase 1)

- Rewriting Safebox backend protocols for mobile-specific APIs.
- Fully offline wallet operation.
- Platform-specific feature divergence between Android and iOS.

## Platform and Framework Choice

### Primary UI Framework

- Flutter (single UI codebase for Android + iOS)

### Language

- Dart for app code

### Native Integration

- Use platform channels only where required:
  - NFC tag read/write
  - secure key storage APIs
  - background lifecycle events

## Product Scope by Phase

### Phase A: Mobile Foundation (Shared Core)

- Auth/session handling using existing Safebox access model
- Wallet overview (balance, currency, transaction summary)
- QR scan/generate support
- Payment request + send flows
- Record list and record display flows
- Websocket status channel integration for terminal updates

### Phase B: Android-First Production

- NFC login and NFC payment initiation
- NFC offer/request record initiation
- Robust lifecycle handling for app background/foreground transitions
- Crash-safe state restoration for in-progress workflows

### Phase C: iOS Enablement

- Enable iOS build target with same Flutter app layer
- Implement iOS-specific secure storage and NFC constraints via platform bridge
- Validate parity for all Phase A/B flows where iOS APIs permit

### Phase D: Hardening and Scale

- Performance profiling on lower-end devices
- background reconnection and retry tuning
- telemetry and in-app diagnostics for field failures

## Architecture

### 1) Layered Structure

1. Presentation layer:
   - Flutter widgets/screens
   - route/state orchestration
2. Application layer:
   - payment flow coordinator
   - record flow coordinator
   - NFC flow coordinator
3. Infrastructure layer:
   - REST client
   - websocket client
   - secure storage adapter
   - NFC adapter

### 2) State Management

Use explicit state machines for asynchronous flows:

- `idle -> pending -> processing -> success|error|timeout`

Apply to:

- POS-like payment confirmations
- NFC request/offer steps
- QR auth/request handshakes

This prevents ambiguous UI states and aligns with existing Safebox resiliency semantics.

### 3) Network Model

- REST for command initiation and data fetch
- Websocket for status and terminal events
- bounded timeout/retry policies with user-visible status transitions

### 4) Security Model

- Never store private key material in plain local storage.
- Use platform secure keystore/keychain wrappers.
- Bind sessions to short-lived tokens and refresh policies.
- Keep `nembed`/token parsing in shared app logic with strict validation.

## UX Strategy

### Source of Truth

The current web wallet UX is the baseline behavior specification.

### Mobile UX Principles

1. Fast primary actions:
   - pay, request, scan, NFC
2. Clear terminal states:
   - no silent hangs
3. Minimize visual jitter:
   - stable component sizing during status transitions
4. Touch-first affordances:
   - larger hit targets and consistent spacing
5. Explicit lane visibility:
   - indicate QR/NFC/payment path when relevant

### Divine-Style Alignment (Without Copying)

Adopt comparable strengths:

- clean and minimal navigation depth
- high signal-to-noise action screens
- fast scan-to-action handoff
- strong feedback loops for asynchronous operations

## NFC Strategy for Mobile

### Android First

- Implement complete NFC read path first (login, payment, request/offer token capture)
- Add write path for card issuance where supported/needed
- Ensure listener-before-submit ordering in NFC request flows to avoid race conditions

### iOS Considerations

- Design adapters so iOS NFC capability differences do not change domain logic
- Keep fallback paths (QR/manual) for unsupported device/API constraints

## Testing Strategy

### Phase Gates

1. Unit tests:
   - token parsing/validation
   - flow state transitions
2. Integration tests:
   - REST + websocket lifecycle
   - timeout/retry behavior
3. Device tests:
   - Android real-device NFC and camera
   - iOS parity tests once enabled

### Regression Checklist Focus

- QR request/offer handshake reliability
- NFC request sequencing reliability
- multi-record receive paths
- payment completion signaling (pending -> processing -> complete)
- recovery behavior on app backgrounding/network loss

## Delivery Plan

### Milestone 1

- Flutter app shell + login + balance + QR core flows

### Milestone 2

- Android NFC read flows + payment/request/offer workflows

### Milestone 3

- Android production hardening and telemetry

### Milestone 4

- iOS target enablement and parity rollout

## Risks and Mitigations

1. Risk: race conditions in async workflows
   - Mitigation: state machines + listener-before-submit where required
2. Risk: platform NFC differences
   - Mitigation: adapter abstraction + QR fallback
3. Risk: websocket instability on mobile networks
   - Mitigation: reconnect/backoff + terminal timeout messaging
4. Risk: UX drift between web and mobile
   - Mitigation: shared behavior specs and regression checklist

## Implementation References

- `docs/specs/WEB-WALLET-USER-CONSIDERATIONS.md`
- `docs/specs/HYPERMEDIA-AND-HATEOAS-APPLICATION-STATE.md`
- `docs/specs/NFC-FLOWS-AND-SECURITY.md`
- `docs/specs/NWC-NFC-VAULT-EXTENSION.md`
- `docs/specs/NAUTH-PROTOCOL.md`
- `docs/specs/NEMBED-PROTOCOL.md`
- `docs/specs/ACORN-RESILIENCY-AND-GUARDS.md`
