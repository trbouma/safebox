# Branding and Host Resolution

## Overview

Safebox supports host-based branding so a single service instance can present different brand identity values (name/message/theme metadata) based on the incoming domain name.

This capability is intentionally lightweight and presentation-focused. It does not provide tenant-level data isolation. At this stage, branding controls UI text and optional display metadata while core wallet/payment/record logic remains shared.

## Scope

This specification describes:

1. Branding file discovery by hostname
2. Fallback behavior
3. Startup bootstrap behavior for empty deployments
4. Runtime context injection into templates
5. Operational deployment patterns

It does not define:

1. Per-brand database routing
2. Per-brand key management boundaries
3. Full multi-tenant policy enforcement

## Branding Data Model

Branding files are loaded from `BRANDING_DIR` (default: `branding`).

Supported file formats:

1. `.yml`
2. `.yaml`
3. `.json`

Supported keys:

1. `brand_name` (alias: `branding`)
2. `brand_message` (alias: `branding_message`)
3. `branding_retry_message` (alias: `branding_retry`)
4. Optional passthrough keys:
   - `logo_url`
   - `logo_path`
   - `theme`
   - `brand_url`

## Host Resolution Logic

Branding selection is resolved per request using:

1. `X-Forwarded-Host` (preferred when reverse-proxied)
2. `Host` header
3. Request URL hostname fallback

Normalization rules:

1. Lowercase hostname
2. Strip port suffix
3. Allow only safe hostname characters (`a-z`, `0-9`, `.`, `-`)
4. Reject invalid host values to `default`

Lookup order:

1. Exact host file (for example: `openbalance.com.yml`)
2. Host without `www.` prefix (if request host starts with `www.`)
3. `default.yml` (or equivalent extension)
4. Built-in settings fallback from app config

## Startup Bootstrap Behavior

On application startup:

1. Ensure `BRANDING_DIR` exists
2. Ensure `default.yml` exists
3. If missing, seed `default.yml` from configured defaults:
   - `BRANDING`
   - `BRANDING_MESSAGE`
   - `BRANDING_RETRY`

Bootstrap is safe for concurrent workers (no overwrite if another worker creates the file first).

## Template Integration

Branding is injected through a shared template context processor and is available across templates as:

1. `branding`
2. `branding_message`
3. `branding_retry`

This avoids route-level duplication and keeps branding behavior consistent across pages.

## Deployment Guidance

Recommended container deployment:

1. Mount a persistent branding directory:
   - `./branding:/app/branding`
2. Add one file per domain as needed
3. Keep `default.yml` as global fallback

Recommended reverse-proxy behavior:

1. Preserve correct `Host` (and optionally `X-Forwarded-Host`)
2. Do not allow arbitrary host spoofing paths from untrusted networks

## Security Considerations

1. Host headers are normalized and validated to reduce unsafe filename resolution.
2. Branding is presentation-layer only and should not be treated as authorization input.
3. Domain-specific branding does not imply isolated storage or trust boundaries.
4. If strict domain control is required, enforce allowed hostnames at proxy/application boundary.

## Future Enhancements

1. Per-brand logo assets resolved directly from branding files
2. Per-brand CSS variable bundles/themes
3. Optional admin/CLI validation for branding files
4. Optional per-brand database routing (separate specification and tenant isolation model required)

## Implementation References

1. `app/branding.py`
2. `app/config.py` (`BRANDING_DIR`)
3. `app/main.py` (startup bootstrap)
4. `docker-compose.yaml` (branding volume mapping)
