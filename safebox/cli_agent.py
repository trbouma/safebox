import json
import os
import secrets
import asyncio
from typing import Any, Dict, Optional
from urllib.parse import urlparse, urlencode

import click
import requests
import yaml


DEFAULT_BASE_URL = "https://safebox.dev"
DEFAULT_PROFILE = "default"
COUPON_CHARSET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".safebox-agent")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.yml")


def _ensure_config() -> Dict[str, Any]:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if not os.path.exists(CONFIG_PATH):
        cfg = {
            "default_profile": DEFAULT_PROFILE,
            "profiles": {
                DEFAULT_PROFILE: {"base_url": DEFAULT_BASE_URL, "access_key": None, "timeout_seconds": 30}
            },
        }
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            yaml.safe_dump(cfg, f, default_flow_style=False)
        return cfg

    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        loaded = yaml.safe_load(f) or {}

    # Backward-compatible migration from single-profile schema.
    if "profiles" not in loaded:
        migrated = {
            "default_profile": DEFAULT_PROFILE,
            "profiles": {
                DEFAULT_PROFILE: {
                    "base_url": loaded.get("base_url", DEFAULT_BASE_URL),
                    "access_key": loaded.get("access_key"),
                    "timeout_seconds": int(loaded.get("timeout_seconds", 30)),
                }
            },
        }
        _write_config(migrated)
        return migrated

    normalized_profiles: Dict[str, Dict[str, Any]] = {}
    for name, profile in (loaded.get("profiles") or {}).items():
        profile = profile or {}
        normalized_profiles[name] = {
            "base_url": (profile.get("base_url") or DEFAULT_BASE_URL).rstrip("/"),
            "access_key": profile.get("access_key"),
            "timeout_seconds": int(profile.get("timeout_seconds", 30)),
        }

    if not normalized_profiles:
        normalized_profiles = {
            DEFAULT_PROFILE: {"base_url": DEFAULT_BASE_URL, "access_key": None, "timeout_seconds": 30}
        }

    default_profile = loaded.get("default_profile") or DEFAULT_PROFILE
    if default_profile not in normalized_profiles:
        default_profile = next(iter(normalized_profiles.keys()))

    normalized = {"default_profile": default_profile, "profiles": normalized_profiles}
    _write_config(normalized)
    return normalized


def _write_config(cfg: Dict[str, Any]) -> None:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, default_flow_style=False)


def _select_profile(cfg: Dict[str, Any], profile_name: Optional[str]) -> tuple[str, Dict[str, Any]]:
    selected = profile_name or os.environ.get("SAFEBOX_AGENT_PROFILE") or cfg.get("default_profile") or DEFAULT_PROFILE
    profiles = cfg.get("profiles", {})
    profile = profiles.get(selected)
    if profile is None:
        available = ", ".join(sorted(profiles.keys())) if profiles else "(none)"
        raise click.ClickException(f"Unknown profile '{selected}'. Available: {available}")
    return selected, profile


def _coalesce_access_key(cli_value: Optional[str], profile_cfg: Dict[str, Any]) -> Optional[str]:
    return cli_value or os.environ.get("SAFEBOX_AGENT_ACCESS_KEY") or profile_cfg.get("access_key")


def _coalesce_base_url(cli_value: Optional[str], profile_cfg: Dict[str, Any]) -> str:
    return (
        cli_value or os.environ.get("SAFEBOX_AGENT_BASE_URL") or profile_cfg.get("base_url") or DEFAULT_BASE_URL
    ).rstrip("/")


def _parse_csv(value: Optional[str]) -> Optional[list[str]]:
    if not value:
        return None
    return [v.strip() for v in value.split(",") if v.strip()]


def _request_json(
    base_url: str,
    path: str,
    method: str = "GET",
    access_key: Optional[str] = None,
    timeout_seconds: int = 30,
    params: Optional[Dict[str, Any]] = None,
    payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    headers = {"Content-Type": "application/json"}
    if access_key:
        headers["X-Access-Key"] = access_key

    url = f"{base_url}{path}"
    try:
        resp = requests.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            json=payload,
            timeout=timeout_seconds,
        )
    except requests.RequestException as exc:
        raise click.ClickException(f"HTTP request failed: {exc}") from exc

    if not resp.ok:
        detail = resp.text
        try:
            body = resp.json()
            detail = body.get("detail") or body
        except Exception:
            pass
        raise click.ClickException(f"{resp.status_code} {resp.reason}: {detail}")

    if not resp.text:
        return {"status": "OK"}

    try:
        return resp.json()
    except ValueError as exc:
        raise click.ClickException(f"Non-JSON response: {resp.text}") from exc


def _ws_base_url(http_base_url: str) -> str:
    parsed = urlparse(http_base_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    host = parsed.netloc or parsed.path
    if not host:
        raise click.ClickException(f"Invalid base URL for websocket conversion: {http_base_url}")
    return f"{scheme}://{host}"


async def _stream_ws_json(
    ws_url: str,
    access_key: Optional[str],
    timeout_seconds: int,
    max_messages: Optional[int],
) -> None:
    try:
        import websockets  # type: ignore
    except Exception as exc:
        raise click.ClickException(
            "websockets package is required for streaming. Install dependencies with `poetry install`."
        ) from exc

    headers = {}
    if access_key:
        headers["X-Access-Key"] = access_key

    msg_count = 0
    try:
        async with websockets.connect(
            ws_url,
            additional_headers=headers if headers else None,
            open_timeout=timeout_seconds,
            close_timeout=timeout_seconds,
        ) as ws:
            while True:
                raw = await ws.recv()
                try:
                    parsed = json.loads(raw)
                    click.echo(json.dumps(parsed, indent=2, ensure_ascii=True))
                except Exception:
                    click.echo(str(raw))

                msg_count += 1
                if max_messages is not None and msg_count >= max_messages:
                    break
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        raise click.ClickException(f"WebSocket stream failed: {exc}") from exc


@click.group()
@click.option("--profile", default=None, help="Config profile name (defaults to active profile).")
@click.option("--base-url", default=None, help="Safebox base URL (defaults to config/env).")
@click.option("--access-key", default=None, help="Wallet access key (defaults to config/env).")
@click.option("--timeout", "timeout_seconds", default=None, type=int, help="HTTP timeout seconds.")
@click.pass_context
def cli(
    ctx: click.Context,
    profile: Optional[str],
    base_url: Optional[str],
    access_key: Optional[str],
    timeout_seconds: Optional[int],
):
    """Standalone CLI for Safebox Agent API."""
    cfg = _ensure_config()
    profile_name, profile_cfg = _select_profile(cfg, profile)
    resolved_base_url = _coalesce_base_url(base_url, profile_cfg)
    resolved_access_key = _coalesce_access_key(access_key, profile_cfg)
    resolved_timeout = timeout_seconds if timeout_seconds is not None else int(profile_cfg.get("timeout_seconds", 30))

    ctx.obj = {
        "cfg": cfg,
        "profile_name": profile_name,
        "profile_cfg": profile_cfg,
        "base_url": resolved_base_url,
        "access_key": resolved_access_key,
        "timeout_seconds": resolved_timeout,
    }


def _print_json(data: Dict[str, Any]) -> None:
    click.echo(json.dumps(data, indent=2, ensure_ascii=True))


def _require_access_key(ctx: click.Context) -> str:
    key = ctx.obj.get("access_key")
    if not key:
        profile_name = ctx.obj.get("profile_name", DEFAULT_PROFILE)
        raise click.ClickException(
            f"Missing access key for profile '{profile_name}'. "
            "Set with `agent config set --profile <name> --access-key ...` or pass --access-key."
        )
    return key


def _generate_coupon_id() -> str:
    return "#COUP" + "".join(secrets.choice(COUPON_CHARSET) for _ in range(6))


@cli.group("config")
def config_group() -> None:
    """Read/write local CLI config."""


@config_group.command("show")
def config_show() -> None:
    cfg = _ensure_config()
    redacted = {"default_profile": cfg.get("default_profile"), "profiles": {}}
    for name, profile in (cfg.get("profiles") or {}).items():
        out = dict(profile)
        if out.get("access_key"):
            out["access_key"] = "***redacted***"
        redacted["profiles"][name] = out
    _print_json(redacted)


@config_group.command("list")
def config_list() -> None:
    cfg = _ensure_config()
    default_profile = cfg.get("default_profile")
    profiles = sorted((cfg.get("profiles") or {}).keys())
    _print_json({"default_profile": default_profile, "profiles": profiles})


@config_group.command("use")
@click.argument("profile")
def config_use(profile: str) -> None:
    cfg = _ensure_config()
    profiles = cfg.get("profiles") or {}
    if profile not in profiles:
        available = ", ".join(sorted(profiles.keys())) if profiles else "(none)"
        raise click.ClickException(f"Unknown profile '{profile}'. Available: {available}")
    cfg["default_profile"] = profile
    _write_config(cfg)
    click.echo(f"default profile set to '{profile}'")


@config_group.command("set")
@click.option("--profile", "profile_name", default=None, help="Profile name to write (default: active/default profile).")
@click.option("--base-url", default=None, help="Safebox base URL.")
@click.option("--access-key", default=None, help="Wallet access key.")
@click.option("--timeout", "timeout_seconds", default=None, type=int, help="HTTP timeout seconds.")
def config_set(
    profile_name: Optional[str], base_url: Optional[str], access_key: Optional[str], timeout_seconds: Optional[int]
) -> None:
    cfg = _ensure_config()
    profile_to_write = profile_name or cfg.get("default_profile") or DEFAULT_PROFILE

    profiles = cfg.setdefault("profiles", {})
    profile_cfg = profiles.get(profile_to_write) or {
        "base_url": DEFAULT_BASE_URL,
        "access_key": None,
        "timeout_seconds": 30,
    }

    if base_url is not None:
        profile_cfg["base_url"] = base_url.rstrip("/")
    if access_key is not None:
        profile_cfg["access_key"] = access_key
    if timeout_seconds is not None:
        profile_cfg["timeout_seconds"] = int(timeout_seconds)

    profiles[profile_to_write] = profile_cfg
    if "default_profile" not in cfg:
        cfg["default_profile"] = profile_to_write

    _write_config(cfg)
    click.echo(f"config updated for profile '{profile_to_write}'")


@cli.command("coupon-id")
@click.option("--count", default=1, type=int, show_default=True, help="Number of coupon IDs to generate.")
def coupon_id(count: int) -> None:
    if count < 1 or count > 100:
        raise click.ClickException("count must be between 1 and 100")
    ids = [_generate_coupon_id() for _ in range(count)]
    _print_json({"status": "OK", "count": len(ids), "coupon_ids": ids})


@cli.command("onboard")
@click.option("--invite-code", required=True, help="Safebox onboarding invite code.")
@click.option("--profile", "target_profile", default=None, help="Profile name to save (default: returned handle).")
@click.option("--custom-handle", default=None, help="Optional custom lightning handle to claim after onboarding.")
@click.option(
    "--publish-profile/--no-publish-profile",
    default=True,
    show_default=True,
    help="Publish kind-0 profile after onboarding.",
)
@click.option("--about", default="Safebox agent wallet", show_default=True, help="Kind-0 about field.")
@click.option("--picture", default=None, help="Kind-0 picture URL.")
@click.option(
    "--set-default/--no-set-default",
    default=True,
    show_default=True,
    help="Set saved profile as default profile.",
)
@click.option(
    "--show-secrets/--hide-secrets",
    default=False,
    show_default=True,
    help="Print sensitive onboarding fields (nsec/seed/access_key).",
)
@click.pass_context
def onboard(
    ctx: click.Context,
    invite_code: str,
    target_profile: Optional[str],
    custom_handle: Optional[str],
    publish_profile: bool,
    about: str,
    picture: Optional[str],
    set_default: bool,
    show_secrets: bool,
) -> None:
    base_url = ctx.obj["base_url"]
    timeout_seconds = ctx.obj["timeout_seconds"]

    onboard_resp = _request_json(
        base_url=base_url,
        path="/agent/onboard",
        method="POST",
        access_key=None,
        timeout_seconds=timeout_seconds,
        payload={"invite_code": invite_code},
    )

    wallet = onboard_resp.get("wallet") or {}
    handle = wallet.get("handle")
    access_key = wallet.get("access_key")
    if not handle or not access_key:
        raise click.ClickException("Onboard succeeded but response is missing wallet.handle or wallet.access_key.")

    profile_name = target_profile or handle
    effective_handle = handle
    custom_handle_resp: Optional[Dict[str, Any]] = None
    if custom_handle:
        custom_handle_resp = _request_json(
            base_url=base_url,
            path="/agent/set_custom_handle",
            method="POST",
            access_key=access_key,
            timeout_seconds=timeout_seconds,
            payload={"custom_handle": custom_handle},
        )
        effective_handle = custom_handle_resp.get("custom_handle") or custom_handle

    cfg = _ensure_config()
    profiles = cfg.setdefault("profiles", {})
    profiles[profile_name] = {
        "base_url": base_url.rstrip("/"),
        "access_key": access_key,
        "timeout_seconds": timeout_seconds,
    }
    if set_default:
        cfg["default_profile"] = profile_name
    _write_config(cfg)

    kind0_resp: Optional[Dict[str, Any]] = None
    if publish_profile:
        parsed = urlparse(base_url)
        host = parsed.hostname or ""
        nip05_lud16 = f"{effective_handle}@{host}" if host else effective_handle
        kind0_payload: Dict[str, Any] = {"name": effective_handle, "nip05": nip05_lud16, "lud16": nip05_lud16}
        if about:
            kind0_payload["about"] = about
        if picture:
            kind0_payload["picture"] = picture
        kind0_resp = _request_json(
            base_url=base_url,
            path="/agent/publish_kind0",
            method="POST",
            access_key=access_key,
            timeout_seconds=timeout_seconds,
            payload=kind0_payload,
        )

    output_wallet = dict(wallet)
    if not show_secrets:
        for sensitive_key in ("access_key", "nsec", "seed_phrase", "emergency_code"):
            if sensitive_key in output_wallet:
                output_wallet[sensitive_key] = "***redacted***"

    output: Dict[str, Any] = {
        "status": "OK",
        "saved_profile": profile_name,
        "default_profile": cfg.get("default_profile"),
        "effective_handle": effective_handle,
        "wallet": output_wallet,
    }
    if custom_handle_resp is not None:
        output["custom_handle"] = {
            "status": custom_handle_resp.get("status"),
            "custom_handle": custom_handle_resp.get("custom_handle"),
            "lightning_address": custom_handle_resp.get("lightning_address"),
            "detail": custom_handle_resp.get("detail"),
        }
    if kind0_resp is not None:
        output["publish_kind0"] = {
            "status": kind0_resp.get("status"),
            "event_id": kind0_resp.get("event_id"),
            "profile": kind0_resp.get("profile"),
        }
    _print_json(output)


@cli.command("info")
@click.pass_context
def info(ctx: click.Context) -> None:
    key = _require_access_key(ctx)
    data = _request_json(ctx.obj["base_url"], "/agent/info", "GET", key, ctx.obj["timeout_seconds"])
    _print_json(data)


@cli.command("balance")
@click.pass_context
def balance(ctx: click.Context) -> None:
    key = _require_access_key(ctx)
    data = _request_json(ctx.obj["base_url"], "/agent/balance", "GET", key, ctx.obj["timeout_seconds"])
    _print_json(data)


@cli.command("proof-safety-audit")
@click.option(
    "--check-relay/--no-check-relay",
    default=False,
    show_default=True,
    help="Also query relay proof state during audit (slower).",
)
@click.pass_context
def proof_safety_audit(ctx: click.Context, check_relay: bool) -> None:
    key = _require_access_key(ctx)
    data = _request_json(
        ctx.obj["base_url"],
        "/agent/proof_safety_audit",
        "GET",
        key,
        ctx.obj["timeout_seconds"],
        params={"check_relay": str(check_relay).lower()},
    )
    _print_json(data)


@cli.command("tx-history")
@click.option("--limit", default=50, type=int, show_default=True)
@click.pass_context
def tx_history(ctx: click.Context, limit: int) -> None:
    key = _require_access_key(ctx)
    data = _request_json(
        ctx.obj["base_url"],
        "/agent/tx_history",
        "GET",
        key,
        ctx.obj["timeout_seconds"],
        params={"limit": limit},
    )
    _print_json(data)


@cli.command("read-dms")
@click.option("--limit", default=20, type=int, show_default=True)
@click.option("--kind", default=1059, type=int, show_default=True)
@click.option("--relays", default=None, help="Comma-separated relay override.")
@click.pass_context
def read_dms(ctx: click.Context, limit: int, kind: int, relays: Optional[str]) -> None:
    key = _require_access_key(ctx)
    params: Dict[str, Any] = {"limit": limit, "kind": kind}
    if relays:
        params["relays"] = relays
    data = _request_json(
        ctx.obj["base_url"], "/agent/read_dms", "GET", key, ctx.obj["timeout_seconds"], params=params
    )
    _print_json(data)


@cli.command("stream-kind1")
@click.option(
    "--scope",
    required=True,
    type=click.Choice(["latest", "discovery", "my", "following"]),
    help="Streaming scope.",
)
@click.option("--nip05", default=None, help="Required for scope=latest|discovery.")
@click.option("--limit", default=10, type=int, show_default=True)
@click.option("--poll-seconds", default=5.0, type=float, show_default=True)
@click.option("--relays", default=None, help="Comma-separated relay override.")
@click.option(
    "--auth-query/--auth-header",
    default=False,
    show_default=True,
    help="Send access_key in query string instead of X-Access-Key header.",
)
@click.option(
    "--max-messages",
    default=None,
    type=int,
    help="Stop after N messages (default: stream until interrupted).",
)
@click.pass_context
def stream_kind1(
    ctx: click.Context,
    scope: str,
    nip05: Optional[str],
    limit: int,
    poll_seconds: float,
    relays: Optional[str],
    auth_query: bool,
    max_messages: Optional[int],
) -> None:
    key = _require_access_key(ctx)
    ws_base = _ws_base_url(ctx.obj["base_url"])

    path_map = {
        "latest": "/agent/ws/nostr/latest_kind1",
        "discovery": "/agent/ws/nostr/discovery/latest_kind1",
        "my": "/agent/ws/nostr/my_latest_kind1",
        "following": "/agent/ws/nostr/following/latest_kind1",
    }
    path = path_map[scope]

    if scope in {"latest", "discovery"} and not nip05:
        raise click.ClickException("--nip05 is required for scope=latest or scope=discovery.")
    if max_messages is not None and max_messages < 1:
        raise click.ClickException("--max-messages must be >= 1.")

    params: Dict[str, Any] = {"limit": limit, "poll_seconds": poll_seconds}
    if nip05:
        params["nip05"] = nip05
    if relays:
        params["relays"] = relays
    if auth_query:
        params["access_key"] = key

    ws_url = f"{ws_base}{path}?{urlencode(params)}"
    click.echo(json.dumps({"status": "CONNECTING", "url": ws_url, "scope": scope}, ensure_ascii=True))

    try:
        asyncio.run(
            _stream_ws_json(
                ws_url=ws_url,
                access_key=None if auth_query else key,
                timeout_seconds=int(ctx.obj["timeout_seconds"]),
                max_messages=max_messages,
            )
        )
    except KeyboardInterrupt:
        click.echo(json.dumps({"status": "STOPPED", "reason": "keyboard_interrupt"}, ensure_ascii=True))


@cli.command("stream-dms")
@click.option("--limit", default=20, type=int, show_default=True)
@click.option("--kind", default=1059, type=int, show_default=True)
@click.option("--poll-seconds", default=5.0, type=float, show_default=True)
@click.option("--relays", default=None, help="Comma-separated relay override.")
@click.option(
    "--auth-query/--auth-header",
    default=False,
    show_default=True,
    help="Send access_key in query string instead of X-Access-Key header.",
)
@click.option(
    "--max-messages",
    default=None,
    type=int,
    help="Stop after N messages (default: stream until interrupted).",
)
@click.pass_context
def stream_dms(
    ctx: click.Context,
    limit: int,
    kind: int,
    poll_seconds: float,
    relays: Optional[str],
    auth_query: bool,
    max_messages: Optional[int],
) -> None:
    key = _require_access_key(ctx)
    ws_base = _ws_base_url(ctx.obj["base_url"])

    if max_messages is not None and max_messages < 1:
        raise click.ClickException("--max-messages must be >= 1.")

    params: Dict[str, Any] = {"limit": limit, "kind": kind, "poll_seconds": poll_seconds}
    if relays:
        params["relays"] = relays
    if auth_query:
        params["access_key"] = key

    ws_url = f"{ws_base}/agent/ws/read_dms?{urlencode(params)}"
    click.echo(json.dumps({"status": "CONNECTING", "url": ws_url, "scope": "dms"}, ensure_ascii=True))

    try:
        asyncio.run(
            _stream_ws_json(
                ws_url=ws_url,
                access_key=None if auth_query else key,
                timeout_seconds=int(ctx.obj["timeout_seconds"]),
                max_messages=max_messages,
            )
        )
    except KeyboardInterrupt:
        click.echo(json.dumps({"status": "STOPPED", "reason": "keyboard_interrupt"}, ensure_ascii=True))


@cli.command("secure-dm")
@click.argument("recipient")
@click.argument("message")
@click.option("--relays", default=None, help="Comma-separated relay list override.")
@click.pass_context
def secure_dm(ctx: click.Context, recipient: str, message: str, relays: Optional[str]) -> None:
    key = _require_access_key(ctx)
    payload: Dict[str, Any] = {"recipient": recipient, "message": message}
    relay_list = _parse_csv(relays)
    if relay_list:
        payload["relays"] = relay_list
    data = _request_json(
        ctx.obj["base_url"], "/agent/secure_dm", "POST", key, ctx.obj["timeout_seconds"], payload=payload
    )
    _print_json(data)


@cli.command("market-order")
@click.option("--side", required=True, type=click.Choice(["buy", "sell", "bid", "ask"]))
@click.option("--asset", required=True, help="Asset label/id.")
@click.option("--price-sats", required=True, type=int, help="Price in sats.")
@click.option("--market", default="safebox-v1", show_default=True, help="Market namespace.")
@click.option("--quantity", default=None, type=float, help="Optional quantity.")
@click.option("--order-id", default=None, help="Optional client order id.")
@click.option("--flow", default=None, help="Optional flow descriptor.")
@click.option("--content", default=None, help="Optional custom content.")
@click.option("--relays", default=None, help="Comma-separated relay override.")
@click.pass_context
def market_order(
    ctx: click.Context,
    side: str,
    asset: str,
    price_sats: int,
    market: str,
    quantity: Optional[float],
    order_id: Optional[str],
    flow: Optional[str],
    content: Optional[str],
    relays: Optional[str],
) -> None:
    key = _require_access_key(ctx)
    payload: Dict[str, Any] = {"side": side, "asset": asset, "price_sats": price_sats, "market": market}
    if quantity is not None:
        payload["quantity"] = quantity
    if order_id:
        payload["order_id"] = order_id
    if flow:
        payload["flow"] = flow
    if content:
        payload["content"] = content
    relay_list = _parse_csv(relays)
    if relay_list:
        payload["relays"] = relay_list

    data = _request_json(
        ctx.obj["base_url"], "/agent/market/order", "POST", key, ctx.obj["timeout_seconds"], payload=payload
    )
    _print_json(data)


@cli.command("market-secret-hash-derive")
@click.option("--spec-id", default="MS01", show_default=True)
@click.option("--token-id", required=True, help="Token id (MS-01 coupon_id).")
@click.option("--redemption-secret", required=True, help="Redemption secret preimage.")
@click.option("--issuer-pubkey", default=None, help="Optional issuer pubkey/npub/nip05 override.")
@click.option("--hash-alg", default="sha256", show_default=True)
@click.pass_context
def market_secret_hash_derive(
    ctx: click.Context,
    spec_id: str,
    token_id: str,
    redemption_secret: str,
    issuer_pubkey: Optional[str],
    hash_alg: str,
) -> None:
    key = _require_access_key(ctx)
    payload: Dict[str, Any] = {
        "spec_id": spec_id,
        "token_id": token_id,
        "redemption_secret": redemption_secret,
        "hash_alg": hash_alg,
    }
    if issuer_pubkey:
        payload["issuer_pubkey"] = issuer_pubkey
    data = _request_json(
        ctx.obj["base_url"],
        "/agent/market/secret_hash/derive",
        "POST",
        key,
        ctx.obj["timeout_seconds"],
        payload=payload,
    )
    _print_json(data)


@cli.command("market-ms02-generate-entitlement")
@click.option("--entitlement-code", default=None, help="Optional entitlement code override.")
@click.option("--entitlement-secret", default=None, help="Optional entitlement secret override.")
@click.pass_context
def market_ms02_generate_entitlement(
    ctx: click.Context,
    entitlement_code: Optional[str],
    entitlement_secret: Optional[str],
) -> None:
    key = _require_access_key(ctx)
    payload: Dict[str, Any] = {}
    if entitlement_code is not None:
        payload["entitlement_code"] = entitlement_code
    if entitlement_secret is not None:
        payload["entitlement_secret"] = entitlement_secret
    data = _request_json(
        ctx.obj["base_url"],
        "/agent/market/ms02/generate_entitlement",
        "POST",
        key,
        ctx.obj["timeout_seconds"],
        payload=payload,
    )
    _print_json(data)


@cli.command("market-ms02-generate-wrapper")
@click.option("--nsec", default=None, help="Optional existing nsec; if omitted, a fresh wrapper is generated.")
@click.pass_context
def market_ms02_generate_wrapper(ctx: click.Context, nsec: Optional[str]) -> None:
    key = _require_access_key(ctx)
    payload: Dict[str, Any] = {}
    if nsec is not None:
        payload["nsec"] = nsec
    data = _request_json(
        ctx.obj["base_url"],
        "/agent/market/ms02/generate_wrapper",
        "POST",
        key,
        ctx.obj["timeout_seconds"],
        payload=payload,
    )
    _print_json(data)


@cli.command("market-ms02-derive-wrapper-commitment")
@click.option("--nsec", required=True, help="Wrapper secret delivery encoding.")
@click.option("--entitlement-code", required=True, help="Provider-native entitlement code.")
@click.option("--entitlement-secret", required=True, help="Provider-native entitlement secret.")
@click.option("--wrapper-scheme", default="nostr_keypair_v1", show_default=True)
@click.option("--hash-alg", default="sha256", show_default=True)
@click.pass_context
def market_ms02_derive_wrapper_commitment(
    ctx: click.Context,
    nsec: str,
    entitlement_code: str,
    entitlement_secret: str,
    wrapper_scheme: str,
    hash_alg: str,
) -> None:
    key = _require_access_key(ctx)
    payload: Dict[str, Any] = {
        "nsec": nsec,
        "entitlement_code": entitlement_code,
        "entitlement_secret": entitlement_secret,
        "wrapper_scheme": wrapper_scheme,
        "hash_alg": hash_alg,
    }
    data = _request_json(
        ctx.obj["base_url"],
        "/agent/market/ms02/derive_wrapper_commitment",
        "POST",
        key,
        ctx.obj["timeout_seconds"],
        payload=payload,
    )
    _print_json(data)


@cli.command("market-ms02-construct-ask")
@click.option("--wrapper-ref", default=None, help="Preferred MS-02 wrapper reference.")
@click.option("--wrapper-scheme", default="nostr_keypair_v1", show_default=True)
@click.option("--wrapper-commitment", default=None, help="Preferred MS-02 wrapper commitment.")
@click.option("--fulfillment-mode", default="provider_resolved_v1", show_default=True)
@click.option("--sealed-delivery-alg", default=None)
@click.option("--encrypted-entitlement", default=None)
@click.option("--price-sats", required=True, type=int)
@click.option("--expiry", required=True, help="ISO-8601 UTC timestamp.")
@click.option("--instrument", default="service_entitlement", show_default=True)
@click.option("--quantity", default=1, type=int, show_default=True)
@click.option("--redemption-provider", default=None)
@click.option("--provider-commitment", default=None)
@click.option("--settlement-method", default="nip57_zap_v1", show_default=True)
@click.option("--market", default="MS-02", show_default=True)
@click.option("--hash-alg", default="sha256", show_default=True)
@click.option("--content-format", default="yaml", show_default=True)
@click.pass_context
def market_ms02_construct_ask(
    ctx: click.Context,
    wrapper_ref: Optional[str],
    wrapper_scheme: str,
    wrapper_commitment: Optional[str],
    fulfillment_mode: str,
    sealed_delivery_alg: Optional[str],
    encrypted_entitlement: Optional[str],
    price_sats: int,
    expiry: str,
    instrument: str,
    quantity: int,
    redemption_provider: Optional[str],
    provider_commitment: Optional[str],
    settlement_method: str,
    market: str,
    hash_alg: str,
    content_format: str,
) -> None:
    key = _require_access_key(ctx)
    payload: Dict[str, Any] = {
        "wrapper_scheme": wrapper_scheme,
        "price_sats": price_sats,
        "expiry": expiry,
        "fulfillment_mode": fulfillment_mode,
        "instrument": instrument,
        "quantity": quantity,
        "settlement_method": settlement_method,
        "market": market,
        "hash_alg": hash_alg,
        "content_format": content_format,
    }
    if wrapper_ref is not None:
        payload["wrapper_ref"] = wrapper_ref
    if wrapper_commitment is not None:
        payload["wrapper_commitment"] = wrapper_commitment
    if sealed_delivery_alg is not None:
        payload["sealed_delivery_alg"] = sealed_delivery_alg
    if encrypted_entitlement is not None:
        payload["encrypted_entitlement"] = encrypted_entitlement
    if redemption_provider is not None:
        payload["redemption_provider"] = redemption_provider
    if provider_commitment is not None:
        payload["provider_commitment"] = provider_commitment
    data = _request_json(
        ctx.obj["base_url"],
        "/agent/market/ms02/construct_ask",
        "POST",
        key,
        ctx.obj["timeout_seconds"],
        payload=payload,
    )
    _print_json(data)


@cli.command("market-ms02-publish-ask")
@click.option("--content", required=True, help="Constructed ask content to publish.")
@click.option("--tags-json", required=True, help="JSON array of tag arrays from construct_ask output.")
@click.option("--kind", default=1, type=int, show_default=True, help="Nostr event kind for the ask publish.")
@click.option("--relays", default=None, help="Comma-separated relay override.")
@click.pass_context
def market_ms02_publish_ask(
    ctx: click.Context,
    content: str,
    tags_json: str,
    kind: int,
    relays: Optional[str],
) -> None:
    key = _require_access_key(ctx)
    try:
        parsed_tags = json.loads(tags_json)
    except Exception as exc:
        raise click.ClickException(f"--tags-json must be valid JSON: {exc}") from exc
    if not isinstance(parsed_tags, list):
        raise click.ClickException("--tags-json must be a JSON array of tag arrays")

    payload: Dict[str, Any] = {
        "content": content,
        "tags": parsed_tags,
        "kind": kind,
    }
    relay_list = _parse_csv(relays)
    if relay_list:
        payload["relays"] = relay_list

    data = _request_json(
        ctx.obj["base_url"],
        "/agent/market/ms02/publish_ask",
        "POST",
        key,
        ctx.obj["timeout_seconds"],
        payload=payload,
    )
    _print_json(data)


@cli.command("market-secret-hash-verify")
@click.option("--expected-hash", required=True, help="Expected full hash (hex).")
@click.option("--spec-id", default="MS01", show_default=True)
@click.option("--token-id", required=True, help="Token id (MS-01 coupon_id).")
@click.option("--redemption-secret", required=True, help="Redemption secret preimage.")
@click.option("--issuer-pubkey", default=None, help="Optional issuer pubkey/npub/nip05 override.")
@click.option("--hash-alg", default="sha256", show_default=True)
@click.pass_context
def market_secret_hash_verify(
    ctx: click.Context,
    expected_hash: str,
    spec_id: str,
    token_id: str,
    redemption_secret: str,
    issuer_pubkey: Optional[str],
    hash_alg: str,
) -> None:
    key = _require_access_key(ctx)
    payload: Dict[str, Any] = {
        "expected_hash": expected_hash,
        "spec_id": spec_id,
        "token_id": token_id,
        "redemption_secret": redemption_secret,
        "hash_alg": hash_alg,
    }
    if issuer_pubkey:
        payload["issuer_pubkey"] = issuer_pubkey
    data = _request_json(
        ctx.obj["base_url"],
        "/agent/market/secret_hash/verify",
        "POST",
        key,
        ctx.obj["timeout_seconds"],
        payload=payload,
    )
    _print_json(data)


@cli.command("market-orders")
@click.option("--limit", default=50, type=int, show_default=True)
@click.option("--kind", default=1, type=int, show_default=True)
@click.option("--market", default="safebox-v1", show_default=True)
@click.option("--side", default=None, type=click.Choice(["bid", "ask", "buy", "sell"]))
@click.option("--asset", default=None)
@click.option("--relays", default=None, help="Comma-separated relay override.")
@click.pass_context
def market_orders(
    ctx: click.Context,
    limit: int,
    kind: int,
    market: str,
    side: Optional[str],
    asset: Optional[str],
    relays: Optional[str],
) -> None:
    key = _require_access_key(ctx)
    params: Dict[str, Any] = {"limit": limit, "kind": kind, "market": market}
    if side:
        params["side"] = side
    if asset:
        params["asset"] = asset
    if relays:
        params["relays"] = relays
    data = _request_json(
        ctx.obj["base_url"], "/agent/market/orders", "GET", key, ctx.obj["timeout_seconds"], params=params
    )
    _print_json(data)


@cli.command("zap")
@click.option("--event-id", default=None, help="Target event id.")
@click.option("--event", default=None, help="Target event/npub/nip05 identifier.")
@click.option("--amount-sats", required=True, type=int)
@click.option("--comment", default=None)
@click.pass_context
def zap(
    ctx: click.Context, event_id: Optional[str], event: Optional[str], amount_sats: int, comment: Optional[str]
) -> None:
    key = _require_access_key(ctx)
    if not event_id and not event:
        raise click.ClickException("Provide either --event-id or --event.")
    payload: Dict[str, Any] = {"amount_sats": amount_sats}
    if event_id:
        payload["event_id"] = event_id
    if event:
        payload["event"] = event
    if comment:
        payload["comment"] = comment
    data = _request_json(ctx.obj["base_url"], "/agent/zap", "POST", key, ctx.obj["timeout_seconds"], payload=payload)
    _print_json(data)


@cli.command("reply")
@click.argument("event_id")
@click.argument("content")
@click.option("--target-pubkey", default=None)
@click.option("--target-kind", default=None, type=int)
@click.option("--relay-hint", default=None)
@click.pass_context
def reply(
    ctx: click.Context,
    event_id: str,
    content: str,
    target_pubkey: Optional[str],
    target_kind: Optional[int],
    relay_hint: Optional[str],
) -> None:
    key = _require_access_key(ctx)
    payload: Dict[str, Any] = {"event_id": event_id, "content": content}
    if target_pubkey:
        payload["target_pubkey"] = target_pubkey
    if target_kind is not None:
        payload["target_kind"] = target_kind
    if relay_hint:
        payload["relay_hint"] = relay_hint
    data = _request_json(
        ctx.obj["base_url"], "/agent/reply", "POST", key, ctx.obj["timeout_seconds"], payload=payload
    )
    _print_json(data)


@cli.command("react")
@click.option("--event-id", default=None, help="Target Nostr event id for kind-7 reaction.")
@click.option("--content", default="+", show_default=True, help="Reaction content: +, -, emoji, or :shortcode:.")
@click.option("--reacted-pubkey", default=None, help="Optional target event author pubkey/npub.")
@click.option("--reacted-kind", default=None, type=int, help="Optional target event kind.")
@click.option("--relay-hint", default=None, help="Optional relay hint for target event.")
@click.option("--a-tag", default=None, help="Optional addressable event coordinate (<kind>:<pubkey>:<d>).")
@click.option(
    "--external-tag",
    "external_tags",
    multiple=True,
    help="External reaction tag in comma form, e.g. 'k,web' or 'i,https://example.com'. Repeat as needed for kind-17.",
)
@click.option(
    "--extra-tag",
    "extra_tags",
    multiple=True,
    help="Additional tag in comma form. Repeat to include multiple tags.",
)
@click.option("--relays", default=None, help="Comma-separated relay override.")
@click.pass_context
def react(
    ctx: click.Context,
    event_id: Optional[str],
    content: str,
    reacted_pubkey: Optional[str],
    reacted_kind: Optional[int],
    relay_hint: Optional[str],
    a_tag: Optional[str],
    external_tags: tuple[str, ...],
    extra_tags: tuple[str, ...],
    relays: Optional[str],
) -> None:
    key = _require_access_key(ctx)
    payload: Dict[str, Any] = {"content": content}
    if event_id:
        payload["event_id"] = event_id
    if reacted_pubkey:
        payload["reacted_pubkey"] = reacted_pubkey
    if reacted_kind is not None:
        payload["reacted_kind"] = reacted_kind
    if relay_hint:
        payload["relay_hint"] = relay_hint
    if a_tag:
        payload["a_tag"] = a_tag
    if external_tags:
        payload["external_tags"] = [[part.strip() for part in raw.split(",") if part.strip()] for raw in external_tags]
    if extra_tags:
        payload["extra_tags"] = [[part.strip() for part in raw.split(",") if part.strip()] for raw in extra_tags]
    relay_list = _parse_csv(relays)
    if relay_list:
        payload["relays"] = relay_list
    data = _request_json(
        ctx.obj["base_url"], "/agent/react", "POST", key, ctx.obj["timeout_seconds"], payload=payload
    )
    _print_json(data)


@cli.command("follow")
@click.argument("identifier")
@click.option("--relay-hint", default=None, help="Optional relay hint to store in the kind-3 contact list.")
@click.option("--relays", default=None, help="Comma-separated relay override.")
@click.pass_context
def follow(ctx: click.Context, identifier: str, relay_hint: Optional[str], relays: Optional[str]) -> None:
    key = _require_access_key(ctx)
    payload: Dict[str, Any] = {"identifier": identifier}
    if relay_hint:
        payload["relay_hint"] = relay_hint
    relay_list = _parse_csv(relays)
    if relay_list:
        payload["relays"] = relay_list
    data = _request_json(
        ctx.obj["base_url"], "/agent/follow", "POST", key, ctx.obj["timeout_seconds"], payload=payload
    )
    _print_json(data)


@cli.command("unfollow")
@click.argument("identifier")
@click.option("--relays", default=None, help="Comma-separated relay override.")
@click.pass_context
def unfollow(ctx: click.Context, identifier: str, relays: Optional[str]) -> None:
    key = _require_access_key(ctx)
    payload: Dict[str, Any] = {"identifier": identifier}
    relay_list = _parse_csv(relays)
    if relay_list:
        payload["relays"] = relay_list
    data = _request_json(
        ctx.obj["base_url"], "/agent/unfollow", "POST", key, ctx.obj["timeout_seconds"], payload=payload
    )
    _print_json(data)


@cli.command("followers")
@click.option("--identifier", default=None, help="Optional nip05/npub/pubhex target. Defaults to active wallet.")
@click.option("--limit", default=100, type=int, show_default=True)
@click.option("--strict/--no-strict", default=True, show_default=True)
@click.option("--relays", default=None, help="Comma-separated relay override.")
@click.pass_context
def followers(
    ctx: click.Context,
    identifier: Optional[str],
    limit: int,
    strict: bool,
    relays: Optional[str],
) -> None:
    key = _require_access_key(ctx)
    params: Dict[str, Any] = {"limit": limit, "strict": str(strict).lower()}
    if identifier:
        params["identifier"] = identifier
    if relays:
        params["relays"] = relays
    data = _request_json(
        ctx.obj["base_url"], "/agent/nostr/followers", "GET", key, ctx.obj["timeout_seconds"], params=params
    )
    _print_json(data)


@cli.command("delete-request")
@click.option(
    "--event-id",
    "event_ids",
    multiple=True,
    help="Target event id (`note1...` or 64-char hex). Repeat for multiple references.",
)
@click.option(
    "--a-tag",
    "a_tags",
    multiple=True,
    help="Addressable target coordinate (<kind>:<pubkey>:<d>). Repeat for multiple references.",
)
@click.option(
    "--kind",
    "kinds",
    multiple=True,
    type=int,
    help="Optional kind tag to include. Repeat when referencing multiple kinds.",
)
@click.option("--reason", default=None, help="Optional deletion reason text.")
@click.option("--relays", default=None, help="Comma-separated relay override.")
@click.pass_context
def delete_request(
    ctx: click.Context,
    event_ids: tuple[str, ...],
    a_tags: tuple[str, ...],
    kinds: tuple[int, ...],
    reason: Optional[str],
    relays: Optional[str],
) -> None:
    key = _require_access_key(ctx)
    payload: Dict[str, Any] = {}
    if event_ids:
        payload["event_ids"] = list(event_ids)
    if a_tags:
        payload["a_tags"] = list(a_tags)
    if kinds:
        payload["kinds"] = list(kinds)
    if reason:
        payload["reason"] = reason
    relay_list = _parse_csv(relays)
    if relay_list:
        payload["relays"] = relay_list
    data = _request_json(
        ctx.obj["base_url"], "/agent/delete_request", "POST", key, ctx.obj["timeout_seconds"], payload=payload
    )
    _print_json(data)


@cli.command("my-posts")
@click.option("--limit", default=10, type=int, show_default=True)
@click.option("--relays", default=None, help="Comma-separated relay override.")
@click.pass_context
def my_posts(ctx: click.Context, limit: int, relays: Optional[str]) -> None:
    key = _require_access_key(ctx)
    params: Dict[str, Any] = {"limit": limit}
    if relays:
        params["relays"] = relays
    data = _request_json(
        ctx.obj["base_url"], "/agent/nostr/my_latest_kind1", "GET", key, ctx.obj["timeout_seconds"], params=params
    )
    _print_json(data)


@cli.command("zap-receipts")
@click.argument("event_id")
@click.option("--limit", default=50, type=int, show_default=True)
@click.pass_context
def zap_receipts(ctx: click.Context, event_id: str, limit: int) -> None:
    key = _require_access_key(ctx)
    params = {"event_id": event_id, "limit": limit}
    data = _request_json(
        ctx.obj["base_url"], "/agent/nostr/zap_receipts", "GET", key, ctx.obj["timeout_seconds"], params=params
    )
    _print_json(data)


@cli.command("replies")
@click.argument("event_id")
@click.option("--limit", default=50, type=int, show_default=True)
@click.option("--relays", default=None, help="Comma-separated relay override.")
@click.pass_context
def replies(ctx: click.Context, event_id: str, limit: int, relays: Optional[str]) -> None:
    key = _require_access_key(ctx)
    params: Dict[str, Any] = {"event_id": event_id, "limit": limit}
    if relays:
        params["relays"] = relays
    data = _request_json(
        ctx.obj["base_url"], "/agent/nostr/replies", "GET", key, ctx.obj["timeout_seconds"], params=params
    )
    _print_json(data)


if __name__ == "__main__":
    cli()
