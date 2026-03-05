# MS-00: Market Conventions
**Version**: `1.2`  
**Status**: Draft  
**Date**: 2026-03-04  

---

## 1. Purpose

Define shared conventions used across `MS-*` market specifications so pricing, quoting, and settlement metadata are comparable across implementations.

`MS-00` is a common layer and does not replace market-specific rules in `MS-01`, `MS-02`, etc.

---

## 2. Scope

This document defines:

- canonical quote unit names
- required disclosure fields for token-priced markets
- normalization rules for cross-market comparison

This document does not define market-specific fill, redemption, or dispute logic.

---

## 3. Normative Language

The key words `MUST`, `MUST NOT`, `REQUIRED`, `SHALL`, `SHALL NOT`, `SHOULD`, `SHOULD NOT`, `RECOMMENDED`, `MAY`, and `OPTIONAL` are to be interpreted as described in RFC 2119 / RFC 8174.

---

## 4. Pricing Primitive for Tokenized Markets

For tokenized markets, implementations SHOULD expose a user-visible execution price in sats per token.

Canonical expression:

`effective_price = sats / tokens`

Canonical `quote_unit` base:

`SAT_PER_TOKEN`

Rationale:

- The internal cost stack may vary by market (compute, inventory, logistics, etc.).
- User-facing execution price is the unit price per token.
- This applies to digital and real-world redemption semantics (for example, a token redeemable for one banana).

---

## 5. Required Fields for Token-Priced Quotes

A token-priced quote/trade record SHOULD include:

- `quote_unit`: MUST be `SAT_PER_TOKEN` for per-token pricing.
- `effective_price_sats_per_token`: numeric execution price.
- `token_basis`: REQUIRED for domains with multiple token classes; for inference this MUST be one of `INPUT`, `OUTPUT`, `TOTAL`.
- `token_definition`: REQUIRED, short statement of what one token redeems or represents.
- `model_id`: implementation-defined model identifier.
- `pricing_timestamp`: ISO-8601 UTC timestamp.

If `token_basis` is absent, the quote is non-comparable and SHOULD be treated as informational only.

---

## 6. Optional Cost Decomposition

Implementations MAY include internal decomposition metadata:

- `compute_price_sats_per_credit`
- `credits_per_token`

When present, the following identity SHOULD hold (within rounding tolerance):

`effective_price_sats_per_token ~= compute_price_sats_per_credit * credits_per_token`

This decomposition is optional and does not change settlement semantics.

---

## 7. Hash Display and Encoding Conventions

For human-readable quotes and order previews, implementations MAY include a shortened hash display value.

Recommended fields:

- `secret_hash`: REQUIRED canonical commitment value (full hash).
- `secret_hash_display`: OPTIONAL human-readable fingerprint derived from `secret_hash`.

Recommended display format:

- Prefix with `h:` and include first 10-12 characters of canonical hash encoding.
- Example: `h:7f3a9c2d41b8`

Conformance rule:

- Matching, clearing, and redemption validation MUST use full `secret_hash`.
- `secret_hash_display` MUST NOT be used for any authoritative verification or settlement decision.

---

## 8. Interoperability Rules

- Systems MUST NOT use `SAT_PER_1K_TOKEN` and `SAT_PER_TOKEN` interchangeably without explicit conversion.
- Systems SHOULD store canonical execution price as `SAT_PER_TOKEN`.
- Systems MAY present alternate display units in UI, but API payloads SHOULD remain canonical.
- For high-volume inference markets, `SAT_PER_1K_TOKEN` MAY be used as a display or transport alias if conversion is explicit:
  - `effective_price_sats_per_1k_token = effective_price_sats_per_token * 1000`
  - `effective_price_sats_per_token = effective_price_sats_per_1k_token / 1000`

---

## 9. Example

```json
{
  "quote_unit": "SAT_PER_TOKEN",
  "effective_price_sats_per_token": 100.0,
  "token_definition": "1 token redeemable for 1 banana",
  "secret_hash": "7f3a9c2d41b8d4479c31c6f3a4b7a1e1d0f9d8c7b6a5e4d3c2b1a09182736455",
  "secret_hash_display": "h:7f3a9c2d41b8",
  "token_basis": "REDEMPTION_UNIT",
  "model_id": "banana-market-v1",
  "pricing_timestamp": "2026-03-04T15:00:00Z",
  "compute_price_sats_per_credit": 0.05,
  "credits_per_token": 2000.0
}
```

---

## 10. Revision History

| Version | Date | Notes |
|---------|------|-------|
| `1.0` | 2026-03-04 | Initial market conventions document with normalized token pricing primitive. |
| `1.1` | 2026-03-04 | Updated canonical price to `effective_price = sats / tokens`, generalized beyond inference tokens, and added `token_definition`. |
| `1.2` | 2026-03-04 | Added `secret_hash_display` readability convention and clarified full-hash-only conformance requirements. |
