from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml
from fastapi import Request
from fastapi.templating import Jinja2Templates

from app.config import Settings

settings = Settings()

_SAFE_HOST_RE = re.compile(r"^[a-z0-9.-]+$")
_EXTS = (".yml", ".yaml", ".json")
_CACHE: dict[str, tuple[str, float, dict[str, Any]]] = {}


def _normalize_host(host: str | None) -> str:
    if not host:
        return "default"
    host = host.split(",")[0].strip().lower()
    if ":" in host:
        host = host.split(":", 1)[0]
    if not _SAFE_HOST_RE.match(host):
        return "default"
    return host or "default"


def _fallback_branding() -> dict[str, Any]:
    return {
        "branding": settings.BRANDING,
        "branding_message": settings.BRANDING_MESSAGE,
        "branding_retry": settings.BRANDING_RETRY,
    }


def ensure_branding_bootstrap() -> None:
    """
    Ensure branding directory and baseline default branding file exist.
    Safe to call on every startup.
    """
    branding_dir = Path(settings.BRANDING_DIR)
    branding_dir.mkdir(parents=True, exist_ok=True)

    default_path = branding_dir / "default.yml"
    if default_path.exists():
        return

    seed_data = {
        "brand_name": settings.BRANDING,
        "brand_message": settings.BRANDING_MESSAGE,
        "branding_retry_message": settings.BRANDING_RETRY,
    }
    try:
        # 'x' avoids clobbering if another worker created it first.
        with default_path.open("x", encoding="utf-8") as f:
            yaml.safe_dump(seed_data, f, sort_keys=False, allow_unicode=False)
    except FileExistsError:
        return


def _load_file(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    if path.suffix in {".yml", ".yaml"}:
        loaded = yaml.safe_load(raw) or {}
    else:
        loaded = json.loads(raw)
    if not isinstance(loaded, dict):
        return {}
    return loaded


def _resolve_file_for_host(host: str) -> Path | None:
    branding_dir = Path(settings.BRANDING_DIR)
    candidates: list[str] = [host]
    if host.startswith("www."):
        candidates.append(host[4:])
    candidates.append("default")

    for name in candidates:
        for ext in _EXTS:
            path = branding_dir / f"{name}{ext}"
            if path.exists() and path.is_file():
                return path
    return None


def get_branding_for_host(host: str | None) -> dict[str, Any]:
    normalized = _normalize_host(host)
    path = _resolve_file_for_host(normalized)
    fallback = _fallback_branding()

    if path is None:
        return fallback

    cache_key = str(path.resolve())
    mtime = path.stat().st_mtime
    cached = _CACHE.get(cache_key)
    if cached and cached[1] == mtime:
        return cached[2]

    loaded = _load_file(path)
    branding = {
        "branding": loaded.get("branding", loaded.get("brand_name", fallback["branding"])),
        "branding_message": loaded.get(
            "branding_message",
            loaded.get("brand_message", fallback["branding_message"]),
        ),
        "branding_retry": loaded.get(
            "branding_retry",
            loaded.get("branding_retry_message", fallback["branding_retry"]),
        ),
    }
    for key in ("logo_url", "logo_path", "theme", "brand_url"):
        if key in loaded:
            branding[key] = loaded[key]

    _CACHE[cache_key] = (cache_key, mtime, branding)
    return branding


def get_branding_for_request(request: Request) -> dict[str, Any]:
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.hostname
    return get_branding_for_host(host)


def branding_context_processor(request: Request) -> dict[str, Any]:
    return get_branding_for_request(request)


def build_templates(directory: str = "app/templates") -> Jinja2Templates:
    return Jinja2Templates(directory=directory, context_processors=[branding_context_processor])
