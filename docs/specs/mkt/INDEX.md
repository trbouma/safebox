# Market Specifications Index

This folder contains numbered market specifications (`MS-*`) for agent/human market behavior over Safebox.

Numbering convention:

- `MS-01`, `MS-02`, ...
- Each spec defines one market model with explicit message contracts, execution flows, and guardrails.

## Registry

| ID | Title | Version | Status | File |
|----|-------|---------|--------|------|
| `MS-00` | Market Conventions | `1.3` | Draft | [MS-00-market-conventions.md](./MS-00-market-conventions.md) |
| `MS-01` | Safebox Coupon Market Specification | `1.1` | Deprecated Draft | [MS-01-coupon-market.md](./MS-01-coupon-market.md) |
| `MS-01` | Conformance Checklist | `1.1` | Deprecated Draft | [MS-01-CONFORMANCE.md](./MS-01-CONFORMANCE.md) |
| `MS-02` | Hash-Committed Entitlement Market | `2.1` | Draft | [MS-02-entitlement-market.md](./MS-02-entitlement-market.md) |
| `MS-02` | End-to-End Scenario | `1.0` | Draft | [MS-02-END-TO-END-SCENARIO.md](./MS-02-END-TO-END-SCENARIO.md) |
| `MS-02` | Conformance Checklist | `2.1` | Draft | [MS-02-CONFORMANCE.md](./MS-02-CONFORMANCE.md) |

## Notes

- New market specs SHOULD be added with the next unused sequential ID (`MS-03`, `MS-04`, ...).
- Spec updates SHOULD increment version and append an entry in that spec's revision history table.
- `MS-01` is retained as a deprecated legacy reference and is not the recommended base for new market work.
