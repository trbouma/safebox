from fastapi import FastAPI, WebSocket, HTTPException, Depends, Request, APIRouter, Response, Form, Header, Cookie
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, StreamingResponse
from fastapi import UploadFile, File, Form

from pydantic import BaseModel
from typing import Optional, List
from fastapi.templating import Jinja2Templates
import asyncio,qrcode, io, urllib
from starlette.websockets import WebSocketDisconnect

from datetime import datetime, timedelta, timezone
from safebox.acorn import Acorn
from safebox.models import GrantRecord, OfferRecord
from time import sleep
import json
from monstr.util import util_funcs
from monstr.encrypt import Keys
from monstr.event.event import Event
import ipinfo
import requests
import httpx
from safebox.func_utils import get_profile_for_pub_hex, get_attestation
from safebox.monstrmore import ExtendedNIP44Encrypt
from safebox.models import SafeboxRecord, OriginalRecordTransfer
from monstr.encrypt import NIP44Encrypt
import oqs


from app.utils import create_jwt_token, fetch_safebox,extract_leading_numbers, fetch_balance, db_state_change, create_nprofile_from_hex, npub_to_hex, validate_local_part, parse_nostr_bech32, hex_to_npub, get_acorn,create_naddr_from_npub,create_nprofile_from_npub, generate_nonce, create_nauth_from_npub, create_nauth, parse_nauth, listen_for_request, create_nembed_compressed, parse_nembed_compressed, parse_nembed, get_label_by_id, get_id_by_label, sign_payload, get_tag_value, fetch_safebox_by_npub, create_record_request_bind_payload

from sqlmodel import Field, Session, SQLModel, select
from app.appmodels import RegisteredSafebox, CurrencyRate, lnPayAddress, lnPayInvoice, lnInvoice, ecashRequest, ecashAccept, ownerData, customHandle, addCard, deleteCard, updateCard, transmitConsultation, incomingRecord, sendRecordParms, nauthRequest, proofByToken, OfferToken, BlobRequest
from app.config import Settings, ConfigWithFallback
from app.db import engine
from app.branding import build_templates
from app.tasks import service_poll_for_payment, invoice_poll_for_payment
from app.rates import refresh_currency_rates, get_currency_rates

import logging, jwt
import mimetypes
from tempfile import NamedTemporaryFile

logger = logging.getLogger(__name__)

settings = Settings()
config = ConfigWithFallback()

templates = build_templates()


router = APIRouter()


class PresenterCallbackRequest(BaseModel):
    presenter_nauth: str
    verifier_nauth: str


class PresenterAnnounceRequest(BaseModel):
    verifier_nauth: str

def _redirect_if_missing_acorn(acorn_obj: Acorn):
    if acorn_obj is None:
        logger.warning("records route called without an active acorn session")
        return RedirectResponse(url="/", status_code=302)
    return None

def _raise_if_missing_acorn(acorn_obj: Acorn):
    if acorn_obj is None:
        logger.warning("records API called without an active acorn session")
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")


def _normalize_nonce(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if normalized in {"", "none", "null", "0"}:
        return None
    return str(value).strip()


def _nonce_matches(expected_nonce: str | None, candidate_nauth: str | None) -> bool:
    expected = _normalize_nonce(expected_nonce)
    if expected is None:
        return True
    if not candidate_nauth:
        return False
    try:
        parsed = parse_nauth(candidate_nauth)
        candidate_nonce = _normalize_nonce(parsed["values"].get("nonce"))
    except Exception:
        return False
    return candidate_nonce == expected


def _parse_event_payload(payload) -> Optional[Event]:
    candidate = None
    if isinstance(payload, dict):
        candidate = json.dumps(payload)
    elif isinstance(payload, str):
        stripped = payload.strip()
        if not stripped.startswith("{"):
            return None
        candidate = payload
    else:
        return None

    try:
        event_to_validate: Event = Event().load(candidate)
    except Exception:
        return None

    if (
        event_to_validate.kind is None
        or event_to_validate.pub_key is None
        or event_to_validate.sig is None
    ):
        return None
    return event_to_validate


def _extract_payload_content(payload):
    if isinstance(payload, str):
        try:
            parsed = json.loads(payload)
        except Exception:
            return payload
        return _extract_payload_content(parsed)

    if isinstance(payload, dict):
        content = payload.get("content")
        if isinstance(content, str):
            return content
        return json.dumps(payload)

    if isinstance(payload, list):
        return json.dumps(payload)

    return str(payload)


def _extract_kind_from_scope(scope: str | None, expected_prefix: str = "verifier") -> Optional[int]:
    """Return kind from '<prefix>:<kind>' scope or None if missing/invalid."""
    if not isinstance(scope, str):
        return None
    parts = scope.split(":", 2)
    if len(parts) < 2 or parts[0] != expected_prefix:
        return None
    kind_raw = str(parts[1]).strip()
    if not kind_raw:
        return None
    try:
        return int(kind_raw)
    except (TypeError, ValueError):
        return None


def _extract_target_from_scope(scope: str | None, expected_prefix: str = "verifier") -> Optional[str]:
    """Return optional scope target from '<prefix>:<kind>:target=<value>' preserving ':' in value."""
    if not isinstance(scope, str):
        return None
    parts = scope.split(":", 2)
    if len(parts) < 3 or parts[0] != expected_prefix:
        return None
    suffix = str(parts[2]).strip()
    if not suffix.startswith("target="):
        return None
    target_value = suffix[len("target="):].strip()
    return target_value or None


def _parse_offer_request_scope(scope: str | None) -> tuple[Optional[int], Optional[int], Optional[str]]:
    """
    Parse 'offer_request:<grant_kind>:<offer_kind>[:<recipient_host...>]'
    using bounded split so recipient_host may include ':' (e.g. host:port).
    """
    if not isinstance(scope, str) or not scope.startswith("offer_request:"):
        return None, None, None
    parts = scope.split(":", 3)
    if len(parts) < 3:
        return None, None, None
    try:
        grant_kind = int(str(parts[1]).strip())
    except Exception:
        grant_kind = None
    try:
        offer_kind = int(str(parts[2]).strip())
    except Exception:
        offer_kind = None
    recipient_host = str(parts[3]).strip() if len(parts) >= 4 else None
    return grant_kind, offer_kind, recipient_host

async def _preflight_card_status(host_or_origin: str, token: str, pubkey: str, sig: str) -> tuple[bool, str, bool]:
    """Fail fast for rotated/revoked NFC cards before starting record vault flows."""
    origin = _origin_from_host(host_or_origin)
    if not origin:
        return False, "Invalid card host.", True
    status_url = f"{origin}/.well-known/card-status"
    headers = {"Content-Type": "application/json"}
    payload = {"token": token, "pubkey": pubkey, "sig": sig}
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            response = await client.post(status_url, json=payload, headers=headers)
    except httpx.TimeoutException:
        logger.warning("Card status preflight timeout for origin=%s", origin)
        return False, "Card validation timed out.", False
    except httpx.RequestError as exc:
        logger.warning("Card status preflight network error for origin=%s: %s", origin, exc)
        return False, "Card validation network error.", False

    if response.status_code == 200:
        return True, "Card is active", True
    if response.status_code in (401, 404):
        return False, "Card is invalid or rotated. Re-issue the NFC card.", True

    logger.warning("Card status preflight failed origin=%s code=%s body=%s", origin, response.status_code, response.text)
    return False, f"Card validation failed with HTTP {response.status_code}.", True


def _relay_to_http_origin(relay_url: str) -> str | None:
    try:
        parsed = urllib.parse.urlparse((relay_url or "").strip())
    except Exception:
        return None
    if not parsed.hostname:
        return None
    scheme = "https" if parsed.scheme in {"https", "wss"} else "http"
    default_port = 443 if scheme == "https" else 80
    if parsed.port and parsed.port != default_port:
        return f"{scheme}://{parsed.hostname}:{parsed.port}"
    return f"{scheme}://{parsed.hostname}"


async def _resolve_kem_from_service_hosts(host_origins: list[str]) -> tuple[str | None, str | None]:
    for origin in host_origins:
        kem_url = f"{origin.rstrip('/')}/.well-known/kem"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(kem_url)
                response.raise_for_status()
                payload = response.json()
            kem_public_key = payload.get("kem_public_key")
            kemalg = payload.get("kemalg")
            if kem_public_key and kemalg:
                logger.info("Resolved recipient KEM from %s", kem_url)
                return kem_public_key, kemalg
        except Exception as exc:
            logger.warning("KEM lookup failed at %s: %s", kem_url, exc)
            continue
    return None, None


def _origin_from_host(host: str) -> str | None:
    host = (host or "").strip()
    if not host:
        return None
    if host.startswith("http://") or host.startswith("https://"):
        return host.rstrip("/")
    # Local/dev safety; production defaults to HTTPS.
    if host.startswith("localhost") or host.startswith("127.0.0.1"):
        return f"http://{host}"
    return f"https://{host}"


def _normalize_relay_list(relays, fallback: list[str] | None = None) -> list[str]:
    raw_values: list[str] = []
    if isinstance(relays, (list, tuple, set)):
        for each in relays:
            if each is None:
                continue
            raw_values.append(str(each).strip())
    elif isinstance(relays, str):
        raw_values.extend([part.strip() for part in relays.split(",") if part.strip()])

    if not raw_values and fallback:
        return _normalize_relay_list(fallback, fallback=None)

    normalized: list[str] = []
    for each in raw_values:
        if not each:
            continue
        if not each.startswith("wss://") and not each.startswith("ws://"):
            each = f"wss://{each}"
        if each not in normalized:
            normalized.append(each)
    return normalized


def _build_record_request_auth(
    *,
    service_keys: Keys,
    flow: str,
    token: str,
    nauth: str,
    label: str | None = None,
    kind: int | None = None,
    pin: str | None = None,
    kem_public_key: str | None = None,
    kemalg: str | None = None,
    requester_pubkey: str | None = None,
    requester_sig: str | None = None,
    requester_nonce: str | None = None,
    requester_ts: int | None = None,
) -> dict:
    caller_has_any_requester_fields = any(
        [
            requester_pubkey,
            requester_sig,
            requester_nonce,
            requester_ts is not None,
        ]
    )
    caller_has_all_requester_fields = all(
        [
            bool(str(requester_pubkey or "").strip()),
            bool(str(requester_sig or "").strip()),
            bool(str(requester_nonce or "").strip()),
            requester_ts is not None,
        ]
    )

    if caller_has_any_requester_fields and not caller_has_all_requester_fields:
        raise HTTPException(
            status_code=400,
            detail="Requester signature fields must include pubkey, sig, nonce, and ts together.",
        )

    nonce_to_use = str(requester_nonce or generate_nonce())
    ts_to_use = int(requester_ts) if requester_ts is not None else int(datetime.now(timezone.utc).timestamp())

    bind_payload = create_record_request_bind_payload(
        token=token,
        nauth=nauth,
        label=label,
        kind=kind,
        pin=pin,
        kem_public_key=kem_public_key,
        kemalg=kemalg,
        requester_nonce=nonce_to_use,
        requester_ts=ts_to_use,
        flow=flow,
    )

    service_pubkey = service_keys.public_key_hex()
    service_sig = sign_payload(bind_payload, service_keys.private_key_hex())

    return {
        "requester_pubkey": requester_pubkey if caller_has_all_requester_fields else None,
        "requester_sig": requester_sig if caller_has_all_requester_fields else None,
        "requester_nonce": nonce_to_use,
        "requester_ts": ts_to_use,
        "requester_service_pubkey": service_pubkey,
        "requester_service_sig": service_sig,
    }


def _extract_kem_from_nembed(payload: str | None) -> tuple[str | None, str | None]:
    if not payload:
        return None, None
    parsed_obj = None
    try:
        parsed_obj = parse_nembed_compressed(payload)
    except Exception:
        parsed_obj = None
    if parsed_obj is None:
        try:
            parsed_obj = parse_nembed(payload)
        except Exception:
            parsed_obj = None
    if not isinstance(parsed_obj, dict):
        return None, None
    kem_public_key = parsed_obj.get("kem_public_key")
    kemalg = parsed_obj.get("kemalg")
    if (not kem_public_key or not kemalg) and isinstance(parsed_obj.get("kem"), dict):
        kem_public_key = kem_public_key or parsed_obj["kem"].get("kem_public_key")
        kemalg = kemalg or parsed_obj["kem"].get("kemalg")
    if (not kem_public_key or not kemalg) and isinstance(parsed_obj.get("data"), dict):
        kem_public_key = kem_public_key or parsed_obj["data"].get("kem_public_key")
        kemalg = kemalg or parsed_obj["data"].get("kemalg")
    return kem_public_key, kemalg



@router.get("/issue", tags=["records"]) 
async def issue_credentials (   request: Request, 
                                acorn_obj = Depends(get_acorn)                  
                    
                       
                            ):
    redirect = _redirect_if_missing_acorn(acorn_obj)
    if redirect:
        return redirect
    
    profile = acorn_obj.get_profile()
    
    
        
   

    
    return templates.TemplateResponse("credentials/issuecredentials.html", {"request": request, "profile": profile})

@router.get("/offerlist", tags=["records", "protected"])
async def offer_list(      request: Request,
                                    private_mode:str = "offer", 
                                    kind:int = None,   
                                    nprofile:str = None, 
                                    nauth: str = None,
                                    card: str = None,
                                    recipient_initiated: int = 0,
                                    recipient_mode: str = None,
                                    acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to offer records in home relay."""
    redirect = _redirect_if_missing_acorn(acorn_obj)
    if redirect:
        return redirect
    nprofile_parse = None
    auth_msg = None

    offer_kinds = settings.OFFER_KINDS
    
    if nprofile:
        nprofile_parse = parse_nostr_bech32(nprofile)
        pass

    if nauth:
        logger.info("offer_list received nauth for recipient-initiated offer flow")


        parsed_result = parse_nauth(nauth)
        npub_initiator = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values'].get('nonce', '0')
        auth_kind = parsed_result['values'].get("auth_kind", settings.AUTH_KIND)
        auth_relays = parsed_result['values'].get("auth_relays", settings.AUTH_RELAYS)
        transmittal_pubhex = parsed_result['values'].get("transmittal_pubhex")
        transmittal_kind = parsed_result['values'].get("transmittal_kind", settings.RECORD_TRANSMITTAL_KIND)
        transmittal_relays = parsed_result['values'].get("transmittal_relays",settings.RECORD_TRANSMITTAL_RELAYS)
        scope = parsed_result['values'].get("scope")
        if isinstance(scope, str) and scope.startswith("offer_request"):
            recipient_initiated = 1

        if not kind and isinstance(scope, str) and scope.startswith("offer_request:"):
            _, scope_offer_kind, _ = _parse_offer_request_scope(scope)
            if scope_offer_kind is not None and any(entry[0] == scope_offer_kind for entry in offer_kinds):
                kind = scope_offer_kind

        transmittal_npub = hex_to_npub(transmittal_pubhex)
    
        #TODO  transmittal npub from nauth

        auth_msg = create_nauth(    npub=acorn_obj.pubkey_bech32,
                                    nonce=nonce,
                                    auth_kind= auth_kind,
                                    auth_relays=auth_relays,
                                    transmittal_npub=transmittal_npub,
                                    transmittal_kind=transmittal_kind,
                                    transmittal_relays=transmittal_relays,
                                    name=acorn_obj.handle,
                                    scope=scope,
                                    grant=scope
        )

        print(f"do  offer initiator npub: {npub_initiator} and nonce: {nonce} auth relays: {auth_kind} auth kind: {auth_kind} transmittal relays: {transmittal_relays} transmittal kind: {transmittal_kind}")

        
        # send the recipient nauth message
        msg_out = await acorn_obj.secure_transmittal(nrecipient=npub_initiator,message=auth_msg,dm_relays=auth_relays,kind=auth_kind)

    else:
       pass
    
    if not kind:
        kind = offer_kinds[0][0]

    normalized_mode = (recipient_mode or "").strip().lower()
    if normalized_mode not in {"auto_send", "review"}:
        normalized_mode = "auto_send"
    if recipient_initiated:
        # Offer-request handshake depends on immediate send semantics.
        normalized_mode = "auto_send"

    user_records = await acorn_obj.get_user_records(record_kind=kind)


    grant_kinds = settings.GRANT_KINDS
    offer_kind_label = get_label_by_id(offer_kinds, kind)
    host = request.url.hostname
    scheme = "ws" if host in ("localhost", "127.0.0.1") else "wss"
    port = f":{request.url.port}" if request.url.port not in (None, 80) else ""
    ws_url = f"{scheme}://{host}{port}/records/ws/listenfornauth/"

    # Get correspond grant kind
    grant_kind = get_id_by_label(grant_kinds,offer_kind_label)

    return templates.TemplateResponse(  "records/offerlist.html", 
                                        {   "request": request,
                                           
                                            "user_records": user_records,
                                            "record_kind": kind,
                                            "offer_kind": kind,
                                            "offer_kind_label": offer_kind_label,
                                            "grant_kind": grant_kind,
                                            "private_mode": private_mode,
                                            "client_nprofile": nprofile,
                                            "client_nprofile_parse": nprofile_parse,
                                            "client_nauth": auth_msg,
                                            "offer_kinds": offer_kinds,
                                            "ws_url": ws_url,
                                            "recipient_initiated": bool(recipient_initiated),
                                            "recipient_mode": normalized_mode,
                                            "preselected_card": card or ""

                                        })

@router.post("/offerlist", tags=["records", "protected"])
async def offer_list_post(
    request: Request,
    private_mode: str = Form("offer"),
    kind: int = Form(None),
    nprofile: str = Form(None),
    nauth: str = Form(None),
    card: str = Form(None),
    recipient_initiated: int = Form(0),
    recipient_mode: str = Form(None),
    acorn_obj: Acorn = Depends(get_acorn),
):
    """
    Compatibility POST entrypoint for scanner/form-based redirects.
    Delegates to canonical offer_list logic to avoid method-mismatch 405s.
    """
    return await offer_list(
        request=request,
        private_mode=private_mode,
        kind=kind,
        nprofile=nprofile,
        nauth=nauth,
        card=card,
        recipient_initiated=recipient_initiated,
        recipient_mode=recipient_mode,
        acorn_obj=acorn_obj,
    )


@router.post("/offerlist-scan", tags=["records", "protected"])
async def offer_list_scan_post(
    request: Request,
    nauth: str = Form(None),
    kind: int = Form(None),
    card: str = Form(None),
    recipient_initiated: int = Form(1),
    recipient_mode: str = Form("auto_send"),
    acorn_obj: Acorn = Depends(get_acorn),
):
    """Scanner-only POST handoff to avoid exposing offer flow params in URL."""
    return await offer_list(
        request=request,
        kind=kind,
        nauth=nauth,
        card=card,
        recipient_initiated=recipient_initiated,
        recipient_mode=recipient_mode,
        acorn_obj=acorn_obj,
    )

@router.get("/offerlist-scan", tags=["records", "protected"])
async def offer_list_scan_get(
    request: Request,
    nauth: str = None,
    kind: int = None,
    card: str = None,
    recipient_initiated: int = 1,
    recipient_mode: str = "auto_send",
    acorn_obj: Acorn = Depends(get_acorn),
):
    """
    GET fallback for scanner handoff.
    Some clients/redirect paths may hit offerlist-scan with GET, so
    normalize to the same offer_list entrypoint instead of returning 405.
    """
    return await offer_list(
        request=request,
        kind=kind,
        nauth=nauth,
        card=card,
        recipient_initiated=recipient_initiated,
        recipient_mode=recipient_mode,
        acorn_obj=acorn_obj,
    )

@router.get("/request", tags=["records", "protected"])
async def record_request(      request: Request,                                    
                                kind:int = 34003,                          
                                grant_kind:int = None,
                                mode:str = None,
                                presenter_nauth: str = None,
                                target: str = None,
                                acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """This function display the verification page"""
    """The page sets up a websocket to listen for the incoming credential"""
    redirect = _redirect_if_missing_acorn(acorn_obj)
    if redirect:
        return redirect
    



    # user_records = await acorn_obj.get_user_records(record_kind=kind)

    # this is the replacement for records/request.html
    # const ws = new WebSocket(`wss://{{request.url.hostname}}/records/ws/request/${nauth}`); 
    
    host = request.url.hostname
    scheme = "ws" if host in ("localhost", "127.0.0.1") else "wss"
    port = f":{request.url.port}" if request.url.port not in (None, 80) else ""
    ws_url = f"{scheme}://{host}{port}/records/ws/request/"
    

    request_mode = (mode or "request").strip().lower()
    request_scope_prefix = "offer_request" if request_mode == "receive_offer" else "verifier"

    grant_kinds = settings.GRANT_KINDS or []
    valid_grant_kinds = {entry[0] for entry in grant_kinds if isinstance(entry, list) and len(entry) >= 2}
    default_grant_kind = grant_kinds[0][0] if grant_kinds else kind

    resolved_kind = grant_kind if grant_kind is not None else kind
    if resolved_kind not in valid_grant_kinds:
        resolved_kind = default_grant_kind

    return templates.TemplateResponse(  "records/request.html", 
                                        {   "request": request,
                                            "record_kind": resolved_kind,
                                            "grant_kinds": grant_kinds,
                                            "ws_url": ws_url,
                                            "request_mode": request_mode,
                                            "request_scope_prefix": request_scope_prefix,
                                            "presenter_nauth": presenter_nauth or "",
                                            "presenter_target": target or ""


                                        })


@router.get("/request-offer", tags=["records", "protected"])
async def record_request_offer(
                                request: Request,
                                grant_kind:int = 34004,
                                acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Explicit route for recipient-initiated offer intake flow."""
    return await record_request(
        request=request,
        kind=grant_kind,
        grant_kind=grant_kind,
        mode="receive_offer",
        acorn_obj=acorn_obj,
    )


@router.post("/presenter-callback", tags=["records", "protected"])
async def presenter_callback(
    request: Request,
    payload: PresenterCallbackRequest,
    acorn_obj: Acorn = Depends(get_acorn),
):
    """Send verifier nauth back to presenter-auth channel in presenter-initiated QR flow."""
    _raise_if_missing_acorn(acorn_obj)

    presenter_nauth = (payload.presenter_nauth or "").strip()
    verifier_nauth = (payload.verifier_nauth or "").strip()
    if not presenter_nauth or not verifier_nauth:
        raise HTTPException(status_code=400, detail="Missing presenter_nauth or verifier_nauth")

    try:
        parsed = parse_nauth(presenter_nauth)
        presenter_pubhex = parsed["values"].get("pubhex")
        presenter_nonce = parsed["values"].get("nonce")
        if not presenter_pubhex:
            raise ValueError("presenter_nauth missing pubhex")
        presenter_npub = hex_to_npub(presenter_pubhex)
        presenter_auth_kind = parsed["values"].get("auth_kind", settings.AUTH_KIND)
        presenter_auth_relays = parsed["values"].get("auth_relays", settings.AUTH_RELAYS)
    except Exception as exc:
        logger.warning("presenter-callback invalid presenter_nauth: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid presenter_nauth") from exc

    try:
        verifier_to_send = verifier_nauth
        try:
            parsed_verifier = parse_nauth(verifier_nauth)
            verifier_values = parsed_verifier.get("values", {})
            verifier_nonce = verifier_values.get("nonce")
            if _normalize_nonce(verifier_nonce) != _normalize_nonce(presenter_nonce):
                verifier_pubhex = verifier_values.get("pubhex")
                verifier_npub = hex_to_npub(verifier_pubhex) if verifier_pubhex else acorn_obj.pubkey_bech32
                verifier_auth_kind = verifier_values.get("auth_kind", settings.AUTH_KIND)
                verifier_auth_relays = verifier_values.get("auth_relays", settings.AUTH_RELAYS)
                transmittal_pubhex = verifier_values.get("transmittal_pubhex")
                verifier_transmittal_npub = (
                    hex_to_npub(transmittal_pubhex)
                    if transmittal_pubhex
                    else acorn_obj.pubkey_bech32
                )
                verifier_transmittal_kind = verifier_values.get("transmittal_kind", settings.RECORD_TRANSMITTAL_KIND)
                verifier_transmittal_relays = verifier_values.get("transmittal_relays", settings.RECORD_TRANSMITTAL_RELAYS)
                verifier_scope = verifier_values.get("scope")
                verifier_grant = verifier_values.get("grant")

                verifier_to_send = create_nauth(
                    npub=verifier_npub,
                    nonce=presenter_nonce,
                    auth_kind=verifier_auth_kind,
                    auth_relays=verifier_auth_relays,
                    transmittal_npub=verifier_transmittal_npub,
                    transmittal_kind=verifier_transmittal_kind,
                    transmittal_relays=verifier_transmittal_relays,
                    name=acorn_obj.handle,
                    scope=verifier_scope,
                    grant=verifier_grant,
                )
        except Exception as exc:
            logger.warning("presenter-callback could not normalize verifier nonce: %s", exc)
            verifier_to_send = verifier_nauth

        kem_material = {
            "kem_public_key": config.PQC_KEM_PUBLIC_KEY,
            "kemalg": settings.PQC_KEMALG,
        }
        kem_nembed = create_nembed_compressed(kem_material)
        callback_message = f"{verifier_to_send}:{kem_nembed}"

        msg_out = await acorn_obj.secure_transmittal(
            nrecipient=presenter_npub,
            message=callback_message,
            kind=presenter_auth_kind,
            dm_relays=presenter_auth_relays,
        )
    except Exception as exc:
        logger.exception("presenter-callback secure transmittal failed: %s", exc)
        raise HTTPException(status_code=502, detail="Could not notify presenter") from exc

    return {"status": "OK", "detail": "Presenter notified.", "result": msg_out}


@router.post("/presenter-announce", tags=["records", "protected"])
async def presenter_announce(
    request: Request,
    payload: PresenterAnnounceRequest,
    acorn_obj: Acorn = Depends(get_acorn),
):
    """
    Emit presenter nauth back to verifier auth channel so /ws/request can
    complete its stage-1 handshake before waiting for transmittal records.
    """
    _raise_if_missing_acorn(acorn_obj)
    verifier_nauth = (payload.verifier_nauth or "").strip()
    if not verifier_nauth:
        raise HTTPException(status_code=400, detail="Missing verifier_nauth")

    try:
        parsed_result = parse_nauth(verifier_nauth)
        npub_initiator = hex_to_npub(parsed_result["values"]["pubhex"])
        nonce = parsed_result["values"].get("nonce", "0")
        auth_kind = parsed_result["values"].get("auth_kind", settings.AUTH_KIND)
        auth_relays = parsed_result["values"].get("auth_relays", settings.AUTH_RELAYS)
        transmittal_npub = hex_to_npub(parsed_result["values"].get("transmittal_pubhex"))
        transmittal_kind = parsed_result["values"].get("transmittal_kind", settings.RECORD_TRANSMITTAL_KIND)
        transmittal_relays = parsed_result["values"].get("transmittal_relays", settings.RECORD_TRANSMITTAL_RELAYS)
        scope = parsed_result["values"].get("scope")
    except Exception as exc:
        logger.warning("presenter-announce invalid verifier_nauth: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid verifier_nauth") from exc

    presenter_nauth = create_nauth(
        npub=acorn_obj.pubkey_bech32,
        nonce=nonce,
        auth_kind=auth_kind,
        auth_relays=auth_relays,
        transmittal_npub=transmittal_npub,
        transmittal_kind=transmittal_kind,
        transmittal_relays=transmittal_relays,
        name=acorn_obj.handle,
        scope=scope,
        grant=scope,
    )

    try:
        msg_out = await acorn_obj.secure_transmittal(
            nrecipient=npub_initiator,
            message=presenter_nauth,
            dm_relays=auth_relays,
            kind=auth_kind,
        )
    except Exception as exc:
        logger.exception("presenter-announce secure transmittal failed: %s", exc)
        raise HTTPException(status_code=502, detail="Could not announce presenter readiness") from exc

    return {"status": "OK", "detail": "Presenter announced.", "nauth": presenter_nauth, "result": msg_out}
@router.get("/verificationrequest", tags=["records", "protected"])
async def records_verfication_request(      request: Request,
                          
                                    acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """This function display the verification page"""
    """The page sets up a websocket to listen for the incoming credential"""
    redirect = _redirect_if_missing_acorn(acorn_obj)
    if redirect:
        return redirect

    
    credential_types = ["id_card","passport","drivers_license"]

    return templates.TemplateResponse(  "credentials/verificationrequest.html", 
                                        {   "request": request,   
                                            "credential_types": credential_types

                                        })




@router.post("/transmit", tags=["records", "protected"])
async def transmit_records(        request: Request, 
                                        transmit_consultation: transmitConsultation,
                                        acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """ transmit consultation retreve 32227 records from issuing wallet and send as as 32225 records to nprofile recipient recieving wallet """
    _raise_if_missing_acorn(acorn_obj)

    status = "OK"
    detail = "Nothing yet"
   
    
    # Need to generalize the parameters below
    # transmit_consultation.originating_kind = 34001
    # transmit_consultation.final_kind = 34002
    

    
    logger.info(
        "Transmit requested (record_name=%s, originating_kind=%s, final_kind=%s)",
        transmit_consultation.record_name,
        transmit_consultation.originating_kind,
        transmit_consultation.final_kind,
    )
    logger.info(
        "Transmit context (nauth_present=%s kem_present=%s kemalg=%s)",
        bool((transmit_consultation.nauth or "").strip()),
        bool((transmit_consultation.kem_public_key or "").strip()),
        transmit_consultation.kemalg,
    )

    try:
        parsed_nauth = parse_nauth(transmit_consultation.nauth)
        pubhex = parsed_nauth['values']['pubhex']
        npub_recipient = hex_to_npub(pubhex)
        scope = parsed_nauth['values']['scope']
        nonce = parsed_nauth['values'].get('nonce', generate_nonce(1))
        auth_kind = parsed_nauth['values'].get('auth_kind') or settings.AUTH_KIND
        auth_relays = parsed_nauth['values'].get('auth_relays') or settings.AUTH_RELAYS


        
        transmittal_pubhex = parsed_nauth['values']['transmittal_pubhex']
        transmittal_npub = hex_to_npub(transmittal_pubhex)
        
        
        transmittal_kind = parsed_nauth['values'].get('transmittal_kind') or settings.RECORD_TRANSMITTAL_KIND
        transmittal_relays = parsed_nauth['values'].get('transmittal_relays') or settings.RECORD_TRANSMITTAL_RELAYS

        kem_public_key = transmit_consultation.kem_public_key
        kemalg = transmit_consultation.kemalg
        if (
            not kem_public_key or kem_public_key == "None" or
            not kemalg or kemalg == "None"
        ):
            # Browser-side KEM state may be unavailable (e.g. review mode/navigation).
            # Resolve recipient KEM from service hosts inferred from nauth context.
            candidate_origins: list[str] = []
            seen_origins: set[str] = set()

            def add_origin_from_relay(relay: str | None):
                origin = _relay_to_http_origin(relay or "")
                if origin and origin not in seen_origins:
                    seen_origins.add(origin)
                    candidate_origins.append(origin)

            # Preferred: recipient service host embedded by request-offer scope.
            # Format: offer_request:<grant_kind>:<offer_kind>:<recipient_host>
            if isinstance(scope, str) and scope.startswith("offer_request:"):
                _, _, scope_host = _parse_offer_request_scope(scope)
                if scope_host:
                    scope_origin = _origin_from_host(scope_host)
                    if scope_origin and scope_origin not in seen_origins:
                        seen_origins.add(scope_origin)
                        candidate_origins.append(scope_origin)

            # Same-instance fallback: try current request host after recipient scope host.
            # Recipient host must be preferred for cross-instance offer_request flows;
            # otherwise we can encrypt to the sender instance key and the receiver
            # cannot decrypt (resulting in placeholder payload text).
            request_host = request.url.hostname or ""
            request_port = request.url.port
            if request_host:
                if request_port and request_port not in (80, 443):
                    request_host = f"{request_host}:{request_port}"
                request_origin = _origin_from_host(request_host)
                if request_origin and request_origin not in seen_origins:
                    seen_origins.add(request_origin)
                    candidate_origins.append(request_origin)

            for relay in (transmittal_relays or []):
                add_origin_from_relay(relay)
            for relay in (auth_relays or []):
                add_origin_from_relay(relay)

            # Same-instance fallback: if recipient npub exists locally, use its home relay too.
            try:
                recipient_local = await fetch_safebox_by_npub(transmittal_npub)
                if recipient_local and recipient_local.home_relay:
                    add_origin_from_relay(recipient_local.home_relay)
            except Exception as exc:
                logger.debug("Local recipient lookup for KEM host failed: %s", exc)

            logger.info("KEM host resolution order: %s", candidate_origins)

            resolved_kem_public_key, resolved_kemalg = await _resolve_kem_from_service_hosts(candidate_origins)
            if resolved_kem_public_key and resolved_kemalg:
                kem_public_key = resolved_kem_public_key
                kemalg = resolved_kemalg
            else:
                raise HTTPException(
                    status_code=400,
                    detail="Recipient channel is not quantum-safe yet. Please re-authenticate and retry.",
                )

        # PQC Step 2a
        logger.info("PQC encapsulation start (kemalg=%s)", kemalg)
        pqc = oqs.KeyEncapsulation(kemalg,bytes.fromhex(config.PQC_KEM_SECRET_KEY))
        kem_ciphertext, kem_shared_secret = pqc.encap_secret(bytes.fromhex(kem_public_key))
        kem_shared_secret_hex = kem_shared_secret.hex()
        kem_ciphertext_hex = kem_ciphertext.hex()

        k_nip44 = Keys(priv_k=kem_shared_secret_hex)
        my_enc = ExtendedNIP44Encrypt(k_nip44)

        #TODO Replace with create_grant

        issued_record: Event
        original_record: OriginalRecordTransfer
        try:
            issued_record, original_record = await acorn_obj.create_grant_from_offer(
                offer_kind=transmit_consultation.originating_kind,
                offer_name=transmit_consultation.record_name,
                grant_kind=transmit_consultation.final_kind,
                holder=transmittal_npub,
                shared_secret_hex=kem_shared_secret_hex,
                blossom_xfer_server=settings.BLOSSOM_XFER_SERVER,
            )
        except requests.exceptions.ConnectionError as exc:
            fallback_server = settings.BLOSSOM_HOME_SERVER
            if not fallback_server or fallback_server == settings.BLOSSOM_XFER_SERVER:
                raise
            logger.warning(
                "Primary blossom transfer server unreachable (%s); retrying on fallback (%s): %s",
                settings.BLOSSOM_XFER_SERVER,
                fallback_server,
                exc,
            )
            issued_record, original_record = await acorn_obj.create_grant_from_offer(
                offer_kind=transmit_consultation.originating_kind,
                offer_name=transmit_consultation.record_name,
                grant_kind=transmit_consultation.final_kind,
                holder=transmittal_npub,
                shared_secret_hex=kem_shared_secret_hex,
                blossom_xfer_server=fallback_server,
            )

        issued_record_str = json.dumps(issued_record.data())
        pqc_encrypted_payload = my_enc.encrypt(to_pub_k=k_nip44.public_key_hex(),plain_text=issued_record_str)

        if original_record:           
            original_record_str = original_record.model_dump_json(exclude_none=True)
            pqc_encrypted_original = my_enc.encrypt(to_pub_k=k_nip44.public_key_hex(),plain_text=original_record_str)
            


        else:
            pqc_encrypted_original = None


        transmittal_obj = { "tag"   : [transmit_consultation.record_name],
                        "type"  : str(transmit_consultation.final_kind),
                        "payload": "This record is quantum-safe",
                        "timestamp": int(datetime.now(timezone.utc).timestamp()),
                        "endorsement": acorn_obj.pubkey_bech32,
                        "ciphertext": kem_ciphertext_hex,
                        "kemalg": kemalg,
                        "pqc_encrypted_payload": pqc_encrypted_payload,
                        "pqc_encrypted_original": pqc_encrypted_original
                            }

        msg_out = await acorn_obj.secure_transmittal(transmittal_npub,json.dumps(transmittal_obj), dm_relays=transmittal_relays,kind=transmittal_kind)

        detail = f"Successfully transmitted kind {transmit_consultation.final_kind} to {transmittal_npub} via {transmittal_relays}"
        logger.info("Transmit success: %s", detail)

        return {"status": status, "detail": detail}
    except HTTPException:
        raise
    except (KeyError, ValueError, TypeError) as e:
        logger.warning("Invalid transmit request payload: %s", e)
        status = "ERROR"
        detail = f"Error: invalid transmit request ({e})"
    except Exception as e:
        logger.exception("Unexpected transmit failure")
        status = "ERROR"
        detail = f"Error: {e}"
    
    logger.info("Transmit result status=%s detail=%s", status, detail)

    return {"status": status, "detail": detail} 

@router.get("/present", tags=["records", "protected"])
async def my_present_records(       request: Request, 
                                nauth: str = None,
                                nonce: str = None,
                                record_kind: int = None,
                                acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to private data stored in home relay"""
    nauth_response = None
    record_select = False
    
    if not acorn_obj:
        return RedirectResponse("/safebox/access")
    
    grant_kinds = settings.GRANT_KINDS
    if not record_kind:
        record_kind = grant_kinds[0][0]


    if nauth:
        
        print("nauth")

        

        parsed_result = parse_nauth(nauth)
        npub_initiator = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values'].get('nonce', '0')
        auth_kind = parsed_result['values'].get("auth_kind", settings.AUTH_KIND)
        auth_relays = parsed_result['values'].get("auth_relays", settings.AUTH_RELAYS)
        transmittal_npub = parsed_result['values'].get("transmittal_npub")
        transmittal_kind = parsed_result['values'].get("transmittal_kind", settings.RECORD_TRANSMITTAL_KIND)
        transmittal_relays = parsed_result['values'].get("transmittal_relays", settings.RECORD_TRANSMITTAL_RELAYS)
        scope = parsed_result['values'].get("scope")
    
        if isinstance(scope, str) and "verifier" in scope:
            record_select = True
            scope_kind = _extract_kind_from_scope(scope, "verifier")
            if scope_kind is not None:
                record_kind = scope_kind
            else:
                logger.warning(
                    "present route received malformed verifier scope='%s'; using record_kind=%s",
                    scope,
                    record_kind,
                )
            nauth_response = nauth
        
        else:
            pass

        
            # also need to set transmittal npub 

            
        nauth_presenter = create_nauth(  npub=acorn_obj.pubkey_bech32,
                                        nonce=nonce,
                                        auth_kind= auth_kind,
                                        auth_relays=auth_relays,
                                        transmittal_npub=transmittal_npub,
                                        transmittal_kind=transmittal_kind,
                                        transmittal_relays=transmittal_relays,
                                        name=acorn_obj.handle,
                                        scope=scope,
                                        grant=scope
            )



        
        # send the recipient nauth message
        # need to add in the PQC Step 1

        

        msg_out = await acorn_obj.secure_transmittal(nrecipient=npub_initiator,message=nauth_presenter,dm_relays=auth_relays,kind=auth_kind)

    else:
       pass

    try:
        user_records = await acorn_obj.get_user_records(record_kind=record_kind )
    except Exception as exc:
        user_records = None
    
    #FIXME don't need the grant kinds
    
    grant_kinds = settings.GRANT_KINDS

    # Need to determine what to present
    out_records = []
    is_valid = "Cannot Validate"
    for each in user_records:        

        event_to_validate = _parse_event_payload(each.get("payload"))
        if event_to_validate:

            
                        
            print(f"event to validate tags: {event_to_validate.tags}")
            tag_owner = get_tag_value(event_to_validate.tags, "safebox_owner")
            tag_safebox = get_tag_value(event_to_validate.tags, "safebox_issuer")
            type_name = get_label_by_id(settings.GRANT_KINDS,event_to_validate.kind)
            # owner_name = tag_owner
            owner_info, picture = await get_profile_for_pub_hex(tag_owner,settings.RELAYS)
            print(f"safebox owner: {tag_owner} {owner_info}")
            # Need to check signature too
            print("let's check signature")  
            print(f"event to validate: {event_to_validate.data()}")
    
            if event_to_validate.is_valid():
                is_valid = "True"

            is_trusted = "TBD"
            content = f"{event_to_validate.content}"
            each["content"] = content
            print(f"line 418 {content}")
            each["verification"] = f"\n\n{'_'*40}\n\nIssued From: {tag_safebox[:6]}:{tag_safebox[-6:]} \nOwner: {owner_info} [{tag_owner[:6]}:{tag_owner[-6:]}] \nValid: {is_valid} | Trusted: {is_trusted} \nType:{type_name} Kind: {event_to_validate.kind} \nCreated at: {event_to_validate.created_at}"
            each["picture"]=picture
        else:
            each["content"] = _extract_payload_content(each.get("payload"))
            each["verification"] = f"\n\n{'_'*40}\n\nPlain Text {is_valid}"
            each["picture"]=None
        
        
        out_records.append(each)

    print("present records")
    record_label = get_label_by_id(grant_kinds, record_kind)

    # FIXME this is what is being replaced in present.html
    # const ws_present = new WebSocket(`wss://{{request.url.hostname}}/records/ws/present/{{nauth}}`);

    host = request.url.hostname
    scheme = "ws" if host in ("localhost", "127.0.0.1") else "wss"
    port = f":{request.url.port}" if request.url.port not in (None, 80) else ""
    ws_url = f"{scheme}://{host}{port}/records/ws/present/{nauth}"
    
    return templates.TemplateResponse(  "records/present.html", 
                                        {   "request": request,
                                            
                                            
                                            "user_records": out_records ,
                                            "nauth": nauth_response,
                                            "record_select": record_select,
                                            "record_kind": record_kind,
                                            "record_label": record_label,
                                            "select_kinds": grant_kinds,
                                            "kem_public_key": config.PQC_KEM_PUBLIC_KEY,
                                            "kemalg": settings.PQC_KEMALG,
                                            "ws_url": ws_url

                                        })

@router.post("/present", tags=["records", "protected"])
async def my_present_records_post(
    request: Request,
    nauth: str = Form(None),
    nonce: str = Form(None),
    record_kind: int = Form(None),
    acorn_obj: Acorn = Depends(get_acorn),
):
    """Compatibility POST entrypoint for scanner/form handoffs."""
    return await my_present_records(
        request=request,
        nauth=nauth,
        nonce=nonce,
        record_kind=record_kind,
        acorn_obj=acorn_obj,
    )

@router.get("/retrieve", tags=["records", "protected"])
async def my_retrieve_records(       request: Request, 
                                nauth: str = None,
                                nonce: str = None,
                                record_kind: int = 34002,
                                acorn_obj = Depends(get_acorn)
                    ):
    # Legacy retrieval route retained for compatibility with older record views.
    # New request/presentation flow is centered on /records/request and /ws/request.
    """Protected access to private data stored in home relay"""
    redirect = _redirect_if_missing_acorn(acorn_obj)
    if redirect:
        return redirect
    nauth_response = None
    record_select = False
    



    if nauth:
        
        print("nauth")

        

        parsed_result = parse_nauth(nauth)
        npub_initiator = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values'].get('nonce', '0')
        auth_kind = parsed_result['values'].get("auth_kind", settings.AUTH_KIND)
        auth_relays = parsed_result['values'].get("auth_relays",settings.AUTH_RELAYS)
        transmittal_npub = parsed_result['values'].get("transmittal_npub")
        transmittal_kind = parsed_result['values'].get("transmittal_kind", settings.RECORD_TRANSMITTAL_KIND)
        transmittal_relays = parsed_result['values'].get("transmittal_relays",settings.RECORD_TRANSMITTAL_RELAYS)
        scope = parsed_result['values'].get("scope")
    
        if isinstance(scope, str) and "verifier" in scope:
            record_select = True
            scope_kind = _extract_kind_from_scope(scope, "verifier")
            if scope_kind is not None:
                record_kind = scope_kind
            else:
                logger.warning(
                    "retrieve route received malformed verifier scope='%s'; using record_kind=%s",
                    scope,
                    record_kind,
                )
            nauth_response = nauth
        
        else:

        
            # also need to set transmittal npub 


            nauth_response = create_nauth(    npub=acorn_obj.pubkey_bech32,
                                        nonce=nonce,
                                        auth_kind= auth_kind,
                                        auth_relays=auth_relays,
                                        transmittal_npub=transmittal_npub,
                                        transmittal_kind=transmittal_kind,
                                        transmittal_relays=transmittal_relays,
                                        name=acorn_obj.handle,
                                        scope=scope,
                                        grant=scope
            )



        
        # send the recipient nauth message
        msg_out = await acorn_obj.secure_transmittal(nrecipient=npub_initiator,message=nauth_response,dm_relays=auth_relays,kind=auth_kind)

    else:
       pass

    try:
        user_records = await acorn_obj.get_user_records(record_kind=record_kind )
    except Exception as exc:
        user_records = None
    
    print(f"present records: {user_records}")
    present_records = []
    for record in user_records: 

        try:
            
            content = record["payload"]
            private_record = record["payload"]
            event_to_validate = _parse_event_payload(private_record)
            if not event_to_validate:
                raise ValueError("payload is not a signed event")
            
            
            # tag_owner = get_tag_value(private_record["tags"], "safebox_owner")
            # tag_safebox = get_tag_value(private_record["tags"], "safebox")
            tag_owner = get_tag_value(event_to_validate.tags, "safebox_owner")
            tag_safebox = get_tag_value(event_to_validate.tags, "safebox")
            type_name = get_label_by_id(settings.GRANT_KINDS,event_to_validate.kind)
            # Need to check signature too
            print("let's check signature")
           
            
            print(f"event to validate: {event_to_validate.data()}")
            
            event_is_valid = event_to_validate.is_valid()
            is_trusted = "TBD"

            content = f"{event_to_validate.content}\n\n{'_'*40}\n\nIssued From: {tag_safebox[:6]}:{tag_safebox[-6:]} \nOwner: {tag_owner[:6]}:{tag_owner[-6:]} \nValid: {event_is_valid} | Trusted: {is_trusted} \nType:{type_name} Kind: {event_to_validate.kind} \nCreated at: {event_to_validate.created_at}"
            record["content"] = content
        except Exception as exc:
            record["content"] = _extract_payload_content(record.get("payload"))
        present_records = record
    
    #FIXME don't need the grant kinds
    
    grant_kinds = settings.GRANT_KINDS
  
    record_label = get_label_by_id(grant_kinds, record_kind)
    
    return templates.TemplateResponse(  "records/retrieve.html", 
                                        {   "request": request,
                                            
                                            
                                            "user_records": present_records ,
                                            "nauth": nauth_response,
                                            "record_select": record_select,
                                            "record_kind": record_kind,
                                            "record_label": record_label,
                                            "select_kinds": grant_kinds

                                        })

@router.get("/grantlist", tags=["records", "protected"])
async def retrieve_grant_list(       request: Request, 
                                nauth: str = None,
                                nonce: str = None,
                                record_kind: int = None,
                                acorn_obj = Depends(get_acorn)
                    ):
    """Protected access to private data stored in home relay"""
    redirect = _redirect_if_missing_acorn(acorn_obj)
    if redirect:
        return redirect
    nauth_response = None
    record_select = False
    
    if not record_kind:
        record_kind = settings.GRANT_KINDS[0][0]


    if nauth:
        
        print("nauth")

        

        parsed_result = parse_nauth(nauth)
        npub_initiator = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values'].get('nonce', '0')
        auth_kind = parsed_result['values'].get("auth_kind", settings.AUTH_KIND)
        auth_relays = parsed_result['values'].get("auth_relays", settings.AUTH_RELAYS)
        transmittal_npub = parsed_result['values'].get("transmittal_npub")
        transmittal_kind = parsed_result['values'].get("transmittal_kind", settings.RECORD_TRANSMITTAL_KIND)
        transmittal_relays = parsed_result['values'].get("transmittal_relays", settings.RECORD_TRANSMITTAL_RELAYS)
        scope = parsed_result['values'].get("scope")
    
        if isinstance(scope, str) and "verifier" in scope:
            record_select = True
            scope_kind = _extract_kind_from_scope(scope, "verifier")
            if scope_kind is not None:
                record_kind = scope_kind
            else:
                logger.warning(
                    "grantlist route received malformed verifier scope='%s'; using record_kind=%s",
                    scope,
                    record_kind,
                )
            nauth_response = nauth
        
        else:

        
            # also need to set transmittal npub 


            nauth_response = create_nauth(    npub=acorn_obj.pubkey_bech32,
                                        nonce=nonce,
                                        auth_kind= auth_kind,
                                        auth_relays=auth_relays,
                                        transmittal_npub=transmittal_npub,
                                        transmittal_kind=transmittal_kind,
                                        transmittal_relays=transmittal_relays,
                                        name=acorn_obj.handle,
                                        scope=scope,
                                        grant=scope
            )



        
        # send the recipient nauth message
        msg_out = await acorn_obj.secure_transmittal(nrecipient=npub_initiator,message=nauth_response,dm_relays=auth_relays,kind=auth_kind)

    else:
       pass

    try:
        user_records = await acorn_obj.get_user_records(record_kind=record_kind )
    except Exception as exc:
        user_records = None
    
    #FIXME don't need the grant kinds
   
    
    grant_kinds = settings.GRANT_KINDS

    # Inspect the user records and see what we can do with them
    

  
    record_label = get_label_by_id(grant_kinds, record_kind)

    host = request.url.hostname
    scheme = "ws" if host in ("localhost", "127.0.0.1") else "wss"
    port = f":{request.url.port}" if request.url.port not in (None, 80) else ""
    ws_url = f"{scheme}://{host}{port}/records/ws/offer/{nauth}"

    # this is the hardcoded one from grantlist.html
    # ws_url = "wss://{{request.url.hostname}}/records/ws/offer/${global_nauth}"
    
    return templates.TemplateResponse(  "records/grantlist.html", 
                                        {   "request": request,
                                            
                                            
                                            "user_records": user_records ,
                                            "nauth": nauth_response,
                                            "record_select": record_select,
                                            "record_kind": record_kind,
                                            "record_label": record_label,
                                            "select_kinds": grant_kinds,
                                            "ws_url": ws_url

                                        })

@router.get("/accept", tags=["records", "protected"])
async def accept_records(            request: Request,
                                nauth: str = None,                         
                                acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to inbox in home relay"""
    redirect = _redirect_if_missing_acorn(acorn_obj)
    if redirect:
        return redirect
    nprofile_parse = None
    scope = ""
    grant = ""
 

    
    # acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    # await acorn_obj.load_data()
    # since = None
    since = util_funcs.date_as_ticks(datetime.now())
   
    if acorn_obj == None:
        return



    user_records_with_label = []
    offer_kind = 0
    offer_kind_label=""
    grant_kind = 0
    grant_kind_label = ""
    transmittal_kind = 0

    host = request.url.hostname
    scheme = "ws" if host in ("localhost", "127.0.0.1") else "wss"
    port = f":{request.url.port}" if request.url.port not in (None, 80) else ""
    nauth_clean = None if str(nauth).strip().lower() in {"none", "null", ""} else nauth
    if nauth_clean:
        ws_url = f"{scheme}://{host}{port}/records/ws/accept?nauth={nauth_clean}"
    else:
        ws_url = f"{scheme}://{host}{port}/records/ws/accept"

    

    return templates.TemplateResponse(  "records/acceptrecord.html", 
                                        {   "request": request,
                                            
                                            "user_records": user_records_with_label,
                                            "offer_kind": offer_kind,
                                            "offer_kind_label": offer_kind_label,
                                            "grant_kind": grant_kind,
                                            "grant_kind_label": grant_kind_label,
                                            "transmittal_kind": transmittal_kind,
                                            "nauth": nauth,
                                            "ws_url": ws_url

                                        })

@router.post("/accept", tags=["records", "protected"])
async def accept_records_post(
    request: Request,
    nauth: str = Form(None),
    acorn_obj: Acorn = Depends(get_acorn),
):
    """Compatibility POST entrypoint for scanner/form handoffs."""
    return await accept_records(
        request=request,
        nauth=nauth,
        acorn_obj=acorn_obj,
    )


@router.websocket("/ws/accept")
async def websocket_accept(websocket: WebSocket,  nauth: str = None, acorn_obj: Acorn = Depends(get_acorn)):

 
    global global_websocket
    user_records = []
    await websocket.accept()
    await acorn_obj.load_data()
    
    
    global_websocket = websocket

    # Look back slightly to avoid missing same-second events.
    since_now = int((datetime.now(timezone.utc) - timedelta(seconds=5)).timestamp())

    kem_public_key = config.PQC_KEM_PUBLIC_KEY

    print("This is the records websocket")
    
    print("This is the records websocket after sleep")
    print("nauth")
    nauth_clean = None if str(nauth).strip().lower() in {"none", "null", ""} else nauth
    npub_initiator = None
    nonce = generate_nonce(1)
    auth_kind = settings.AUTH_KIND
    auth_relays = settings.AUTH_RELAYS
    transmittal_kind = settings.RECORD_TRANSMITTAL_KIND
    transmittal_relays = settings.RECORD_TRANSMITTAL_RELAYS
    scope = None
    grant = None
    if nauth_clean:
        parsed_result = parse_nauth(nauth_clean)
        npub_initiator = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values'].get('nonce', '0')
        auth_kind = parsed_result['values'].get("auth_kind",settings.AUTH_KIND)
        auth_relays = _normalize_relay_list(
            parsed_result['values'].get("auth_relays"),
            settings.AUTH_RELAYS,
        )
        transmittal_kind = parsed_result['values'].get("transmittal_kind",settings.RECORD_TRANSMITTAL_KIND)
        transmittal_relays = _normalize_relay_list(
            parsed_result['values'].get("transmittal_relays"),
            settings.RECORD_TRANSMITTAL_RELAYS,
        )
        scope = parsed_result['values'].get("scope",None)
        grant = parsed_result['values'].get("grant",None)
    
    
    
    print(f"scope: {scope} grant: {grant}")
    # create the response nauth
    response_nauth = create_nauth(    npub=acorn_obj.pubkey_bech32,
                                nonce=nonce,
                                auth_kind= auth_kind,
                                auth_relays=auth_relays,
                                transmittal_npub=acorn_obj.pubkey_bech32,
                                transmittal_kind=transmittal_kind,
                                transmittal_relays=transmittal_relays,
                                name=acorn_obj.handle,
                                scope=scope,
                                grant=grant
    )

    # send the recipient nauth message
    # this is PQC Step 1 for KEM key agreement - need to send public key only
    kemalg = settings.PQC_KEMALG
    
    print(f"this is where we add in the ML_KEM key agreement using: {kemalg} {settings.PQC_KEMALG}")
   
    # pqc = oqs.KeyEncapsulation(settings.PQC_KEMALG,bytes.fromhex(config.PQC_KEM_SECRET_KEY))
    
    # pqc_public_key_from_nauth = bytes.fromhex(config.PQC_KEM_PUBLIC_KEY)
    # ciphertext, shared_secret = pqc.encap_secret(pqc_public_key_from_nauth)
    # shared_secret_hex = shared_secret.hex()
    # print(f"pqc shared secret: {shared_secret_hex} ciphertext: {ciphertext.hex()}")

    pqc_to_send = { "kem_public_key": config.PQC_KEM_PUBLIC_KEY,
                    "kemalg": settings.PQC_KEMALG
    }
    nembedpqc = create_nembed_compressed(pqc_to_send)
    response_nauth_with_kem= f"{response_nauth}:{nembedpqc}"
    print(f"response nauth with kem {response_nauth_with_kem}")

    if npub_initiator:
        msg_out = await acorn_obj.secure_transmittal(nrecipient=npub_initiator,message=response_nauth_with_kem,dm_relays=auth_relays,kind=auth_kind)
    else:
        logger.info("websocket_accept started without nauth; skipping presenter announce and waiting for incoming records")
    print("accepting.... let's poll for the records")
    # await asyncio.sleep(10)
    #FIXME - add in an ack here using auth relays

    # This is the same acceptance code that has to go into NWC relay offer_record

    wait_start = datetime.now(timezone.utc)
    wait_timeout = timedelta(seconds=max(10, settings.LISTEN_TIMEOUT))
    while user_records == []:
        user_records = await acorn_obj.get_user_records(record_kind=transmittal_kind, relays=transmittal_relays,since=since_now)
        if user_records:
            break
        if datetime.now(timezone.utc) - wait_start > wait_timeout:
            await websocket.send_json({"status": "TIMEOUT", "detail": "Record offer timed out before transmittal arrived."})
            return
        await asyncio.sleep(1)

    if user_records == []:
        first_type = 34002        
    else:
        first_type = int(user_records[0].get('type',34002))
        

    records_missing_original_blob: List[str] = []

    for each_record in user_records:
        type = int(each_record['type'])
        print(f"incoming record: {each_record} type: {type}")
        # await acorn_obj.secure_dm(npub,json.dumps(record_obj), dm_relays=relay)
        # 32227 are transmitted as kind 1060
        # await acorn_obj.secure_transmittal(npub,json.dumps(record_obj), dm_relays=relay,transmittal_kind=1060)
        
        print(each_record)
        print(each_record['tag'][0][0],each_record['payload'] )
            # acorn_obj.put_record(record_name=each_record['tag'][0][0],record_value=each_record['payload'],record_type='health',record_kind=37375)
            # record_name = f"{each_record['tag'][0][0]} {each_record['created_at']}" 
        record_name = f"{each_record['tag'][0]}" 
        record_value = each_record['payload']
        record_timestamp = each_record.get("timestamp",0)
        record_endorsement = each_record.get("endorsement","")
        endorse_trunc = record_endorsement[:8] + "..." + record_endorsement[-8:]
        final_record = f"{record_value} \n\n[{datetime.fromtimestamp(record_timestamp)} offered by: {endorse_trunc}]" 
        print(f"record_name: {record_name} record value: {final_record} type: {type}")
        # PQC Step 3 Accept
        
        record_ciphertext = each_record.get("ciphertext", None)
        record_kemalg = each_record.get("kemalg", None)
        my_enc = None
        pqc_pub_hex = None
        if record_ciphertext and record_kemalg:
            try:
                pqc = oqs.KeyEncapsulation(record_kemalg,bytes.fromhex(config.PQC_KEM_SECRET_KEY))
                shared_secret = pqc.decap_secret(bytes.fromhex(record_ciphertext))
                print(f"PQC Step 3: shared secret {shared_secret.hex()} cipertext: {record_ciphertext} kemalg: {record_kemalg}")
                k_pqc = Keys(shared_secret.hex())
                my_enc = ExtendedNIP44Encrypt(k_pqc)
                pqc_pub_hex = k_pqc.public_key_hex()
            except Exception as exc:
                logger.warning(
                    "acceptincomingrecord PQC decrypt skipped tag=%s kind=%s: %s",
                    each_record.get("tag"),
                    type,
                    exc,
                )
        elif record_ciphertext and not record_kemalg:
            logger.warning(
                "acceptincomingrecord PQC decrypt skipped tag=%s kind=%s: missing kemalg",
                each_record.get("tag"),
                type,
            )
        payload_to_decrypt = each_record.get("pqc_encrypted_payload", None)
        if payload_to_decrypt and my_enc:
            try:
                decrypted_payload = my_enc.decrypt(payload=payload_to_decrypt, for_pub_k=pqc_pub_hex)
                print(f"decrypted payload: {decrypted_payload}")
                record_value = decrypted_payload
            except Exception as exc:
                logger.warning(
                    "acceptincomingrecord payload decrypt skipped tag=%s kind=%s: %s",
                    each_record.get("tag"),
                    type,
                    exc,
                )

        original_record_to_decrpyt = each_record.get("pqc_encrypted_original", None)
        decrypted_original = None
        if original_record_to_decrpyt and my_enc:
            try:
                decrypted_original = my_enc.decrypt(payload=original_record_to_decrpyt, for_pub_k=pqc_pub_hex)
                print(f"decrypted original: {decrypted_original}")
            except Exception as exc:
                logger.warning(
                    "acceptincomingrecord original decrypt skipped tag=%s kind=%s: %s",
                    each_record.get("tag"),
                    type,
                    exc,
                )  

        # Just add in record_value instead of final value
        
        await acorn_obj.put_record(record_name=record_name, record_value=record_value, record_kind=type, record_origin=npub_initiator)
        # Ingest original recored if there is one

        if original_record_to_decrpyt and decrypted_original:
            blob_result = await acorn_obj.transfer_blob(
                record_name=record_name,
                record_kind=type,
                record_origin=npub_initiator,
                blobxfer=decrypted_original,
                blossom_xfer_server=settings.BLOSSOM_XFER_SERVER,
                blossom_home_server=settings.BLOSSOM_HOME_SERVER,
            )
            if blob_result.get("status") != "OK":
                logger.warning(
                    "Original blob transfer non-fatal status record=%s kind=%s status=%s reason=%s",
                    record_name,
                    type,
                    blob_result.get("status"),
                    blob_result.get("reason"),
                )
                if blob_result.get("reason") == "original_record_not_available":
                    records_missing_original_blob.append(record_name)




    try:
        response_payload = {
            "status": "OK",
            "detail": f"all good {acorn_obj.handle} {scope} {grant} {user_records}",
            "grant_kind": first_type,
            "record_kind": first_type,
        }
        if records_missing_original_blob:
            response_payload["warning"] = (
                "Original record blob unavailable for: "
                + ", ".join(records_missing_original_blob)
            )
        await websocket.send_json(response_payload)
    except WebSocketDisconnect:
        logger.info("websocket_accept client disconnected before final send")
   

@router.post("/acceptincomingrecord", tags=["records", "protected"])
async def accept_incoming_record(       request: Request, 
                                        incoming_record: incomingRecord,
                                        acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """ accept incoming NPI-17 1060 health record and store as a 32225 record"""
    _raise_if_missing_acorn(acorn_obj)

    status = "OK"
    detail = "Nothing yet"



    try:
        parsed_result = parse_nauth(incoming_record.nauth)
        npub_initiator = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values'].get('nonce', '0')
        auth_kind = parsed_result['values'].get("auth_kind", settings.AUTH_KIND)
        auth_relays = parsed_result['values'].get("auth_relays", settings.AUTH_RELAYS)
        transmittal_kind = parsed_result['values'].get("transmittal_kind", settings.RECORD_TRANSMITTAL_KIND)
        transmittal_relays = parsed_result['values'].get("transmittal_relays",settings.RECORD_TRANSMITTAL_RELAYS)

        # acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
        # await acorn_obj.load_data()
        scope = parsed_result['values'].get("scope", None)
        grant = parsed_result['values'].get("grant", None)
        grant_kind = int(grant.replace("record:",""))

        print(f"incoming record scope: {scope} grant: {grant}")
        
        records_to_accept = await acorn_obj.get_user_records(record_kind=transmittal_kind, relays=transmittal_relays)
        
        detail = f"Could not find incoming record"
        for each_record in records_to_accept:
            print(f"incoming record id: {each_record['id']}")
            # await acorn_obj.secure_dm(npub,json.dumps(record_obj), dm_relays=relay)
            # 32227 are transmitted as kind 1060
            # await acorn_obj.secure_transmittal(npub,json.dumps(record_obj), dm_relays=relay,transmittal_kind=1060)
            if each_record['id'] == incoming_record.id:
                print(each_record)
                print(each_record['tag'][0][0],each_record['payload'] )
                # acorn_obj.put_record(record_name=each_record['tag'][0][0],record_value=each_record['payload'],record_type='health',record_kind=37375)
                # record_name = f"{each_record['tag'][0][0]} {each_record['created_at']}" 
                record_name = f"{each_record['tag'][0][0]}" 
                record_value = each_record['payload']
                grant_record = GrantRecord(tag=[record_name], type="generic",payload=record_value)
                print(f"grant record: {grant_record}")
                await acorn_obj.put_record(record_name=record_name, record_value=record_value, record_kind=grant_kind)
                
                detail = f"Matched record {incoming_record.id} accepted!"

        
        
    except Exception as e:
        status = "ERROR"
        detail = f"Error: {e}"
    

    return {"status": status, "detail": detail}  

@router.get("/displayrecord", tags=["records", "protected"])
async def display_record(     request: Request, 
                            card: str = None,
                            kind: int = 34002,
                            action_mode: str = None,
                            acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to updating the card"""
    redirect = _redirect_if_missing_acorn(acorn_obj)
    if redirect:
        return redirect

    label_hash = None
    template_to_use = "records/record.html"
    content = ""
    
    if action_mode == 'edit':

        record = await acorn_obj.get_record(record_name=card, record_kind=kind)
        print(f"display record: {record}")
        label_hash = await acorn_obj.get_label_hash(label=card)

        try:
            content = record["payload"]
        except Exception as exc:
            content = record
        
    elif action_mode == 'offer':
        #FIXME I don't this is used anymore
        record = await acorn_obj.get_record(record_name=card, record_kind=kind)
        label_hash = await acorn_obj.get_label_hash(label=card)
        template_to_use = "records/recordoffer.html"

        try:
            content = record["payload"]
        except Exception as exc:
            content = record    
    
    elif action_mode =='add':
        card = ""
        content =""
    
    credential_record = {"card":card, "content": content}

    select_kinds = settings.OFFER_KINDS
    select_kind = get_label_by_id(select_kinds, kind)

    offer_kinds = settings.OFFER_KINDS
    offer_label = get_label_by_id(offer_kinds, kind)
    referer = f"{urllib.parse.urlparse(request.headers.get('referer')).path}?record_kind={kind}"
   

    return templates.TemplateResponse(  template_to_use, 
                                        {   "request": request,
                                            
                                            "card": card,
                                            "record_kind": kind,
                                            "offer_kind": kind,
                                            "grant_kind": kind+1,
                                            "offer_label": offer_label,
                                            "select_kind": select_kind,
                                            "referer": referer,
                                            "label_hash": label_hash,
                                            "action_mode":action_mode,
                                            "content": content,
                                            "credential_record": credential_record
                                            
                                        })

@router.get("/displaygrant", tags=["records", "protected"])
async def display_grant(     request: Request, 
                            card: str = None,
                            kind: int = None,
                            action_mode: str = None,
                            acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to updating the card"""
    redirect = _redirect_if_missing_acorn(acorn_obj)
    if redirect:
        return redirect

    label_hash = None
    template_to_use = "records/grant.html"
    content = ""
    
    

    if not kind:
        kind = settings.GRANT_KINDS[0][0]
    
    if action_mode == 'edit':

        record = await acorn_obj.get_record(record_name=card, record_kind=kind)
        label_hash = await acorn_obj.get_label_hash(label=card)
        grant_record = GrantRecord(**record)
        print(f"safebox record: {record} {grant_record}")

        try:
            grant_record = GrantRecord(**record)
            # content = record["payload"]
            # content=grant_record.payload
            private_record = record["payload"]
            event_to_validate = _parse_event_payload(private_record)
            if not event_to_validate:
                raise ValueError("payload is not a signed event")
            
            
            # tag_owner = get_tag_value(private_record["tags"], "safebox_owner")
            # tag_safebox = get_tag_value(private_record["tags"], "safebox")
            tag_owner = get_tag_value(event_to_validate.tags, "safebox_owner")
            tag_safebox = get_tag_value(event_to_validate.tags, "safebox")
            type_name = get_label_by_id(settings.GRANT_KINDS,event_to_validate.kind)
            # Need to check signature too
            print("let's check signature")
           
            
            print(f"event to validate: {event_to_validate.data()}")
            
            event_is_valid = event_to_validate.is_valid()
            is_trusted = "TBD"

            content = f"{event_to_validate.content}\n\n{'_'*40}\n\nIssued From: {tag_safebox[:6]}:{tag_safebox[-6:]} \nOwner: {tag_owner[:6]}:{tag_owner[-6:]} \nValid: {event_is_valid} | Trusted: {is_trusted} \nType:{type_name} Kind: {event_to_validate.kind} \nCreated at: {event_to_validate.created_at}"
        except Exception as exc:
            content = _extract_payload_content(record.get("payload"))
        
    elif action_mode == 'offer':

        record = await acorn_obj.get_record(record_name=card, record_kind=kind)
        label_hash = await acorn_obj.get_label_hash(label=card)
        template_to_use = "records/recordoffer.html"

        try:
            #content = record["payload"]
            content = record["payload"]["content"]
        except Exception as exc:
            content = record    
    
    elif action_mode =='add':
        card = ""
        content =""
    
   



    grant_kinds = settings.GRANT_KINDS
    grant_label = get_label_by_id(grant_kinds, kind)
    referer = f"{urllib.parse.urlparse(request.headers.get('referer')).path}?record_kind={kind}"
   

    return templates.TemplateResponse(  template_to_use, 
                                        {   "request": request,
                                            
                                            "card": card,
                                            "record_kind": kind,
                                            "grant_label": grant_label,
                                            "referer": referer,
                                            "label_hash": label_hash,
                                            "content": content
                                            
                                            
                                        })



@router.get("/displayoffer", tags=["records", "protected"])
async def display_offer(     request: Request, 
                            card: str = None,
                            kind: int = 34002,
                            nauth: str = None,
                            recipient_initiated: int = 0,
                            recipient_mode: str = None,
                            action_mode: str = None,
                            acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to updating the card"""
    #FIXME remove action mode because this path is now for offer only
    redirect = _redirect_if_missing_acorn(acorn_obj)
    if redirect:
        return redirect

    label_hash = None
   
    content = ""
    

    record: SafeboxRecord = await acorn_obj.get_record_safebox(record_name=card, record_kind=kind)
    # record = await acorn_obj.get_record(record_name=card, record_kind=kind)
    label_hash = await acorn_obj.get_label_hash(label=card)
    template_to_use = "records/offer.html"

    print(f"display record: {record}")
  
    content = record.payload
   

    
    credential_record = {"card":card, "content": content}

    select_kinds = settings.OFFER_KINDS
    select_kind = get_label_by_id(select_kinds, kind)

    offer_kinds = settings.OFFER_KINDS
    offer_label = get_label_by_id(offer_kinds, kind)
    referer = f"{urllib.parse.urlparse(request.headers.get('referer')).path}?record_kind={kind}"

    #FIXME hard-coded to replace in offer.html
    # `wss://{{request.url.hostname}}/records/ws/listenfornauth/${global_nauth}`
    host = request.url.hostname
    scheme = "ws" if host in ("localhost", "127.0.0.1") else "wss"
    port = f":{request.url.port}" if request.url.port not in (None, 80) else ""
    ws_url = f"{scheme}://{host}{port}/records/ws/listenfornauth/"
    # need to add in global_nauth in the page
    normalized_mode = (recipient_mode or "").strip().lower()
    if normalized_mode not in {"auto_send", "review"}:
        normalized_mode = "auto_send"
    if recipient_initiated:
        normalized_mode = "auto_send"

    return templates.TemplateResponse(  template_to_use, 
                                        {   "request": request,
                                            
                                            "card": card,
                                            "record_kind": kind,
                                            "offer_kind": kind,
                                            "grant_kind": kind+1,
                                            "offer_label": offer_label,
                                            "select_kind": select_kind,
                                            "referer": referer,
                                            "label_hash": label_hash,
                                            "action_mode":action_mode,
                                            "content": content,
                                            "credential_record": credential_record,
                                            "ws_url": ws_url,
                                            "nauth": nauth,
                                            "recipient_initiated": bool(recipient_initiated),
                                            "recipient_mode": normalized_mode
                                            
                                        })


@router.post("/upload")
async def upload_record(
                        file: UploadFile = File(...),                        
                        record_kind: int = Form(...),
                        card: str = Form(...),
                        content: str = Form(...),
                        acorn_obj: Acorn = Depends(get_acorn)
                        ):
    _raise_if_missing_acorn(acorn_obj)
    
    contents: bytes = await file.read()
    print(f"finished uploading {len(contents)} record_kind: {record_kind}")

    record_name = "test_upload"
    record_value = "test booga"
    await acorn_obj.put_record(record_name=card,record_kind=record_kind,record_value=content, blob_data=contents)

    return {"status": "OK", "detail": "OK"}
    

@router.get("/manageoffer", tags=["records", "protected"])
async def manage_offer(     request: Request, 
                            card: str = None,
                            kind: int = 34002,
                            label: str = "default",
                            action_mode: str = None,
                            acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to updating the card"""
    redirect = _redirect_if_missing_acorn(acorn_obj)
    if redirect:
        return redirect

    label_hash = None
    template_to_use = "records/manageoffer.html"
    content = ""
    
    if action_mode == 'edit':

        record = await acorn_obj.get_record(record_name=card, record_kind=kind)
        label_hash = await acorn_obj.get_label_hash(label=card)

        try:
            content = record["payload"]
        except Exception as exc:
            content = record
        
    elif action_mode == 'offer':

        record = await acorn_obj.get_record(record_name=card, record_kind=kind)
        label_hash = await acorn_obj.get_label_hash(label=card)
        template_to_use = "records/recordoffer.html"

        try:
            content = record["payload"]
        except Exception as exc:
            content = record    
    
    elif action_mode =='add':
        card = label
        content =""
    
    credential_record = {"card":card, "content": content}

    select_kinds = settings.OFFER_KINDS
    select_kind = get_label_by_id(select_kinds, kind)

    offer_kinds = settings.OFFER_KINDS
    offer_label = get_label_by_id(offer_kinds, kind)
    referer = f"{urllib.parse.urlparse(request.headers.get('referer')).path}?record_kind={kind}"
   

    return templates.TemplateResponse(  template_to_use, 
                                        {   "request": request,
                                            
                                            "card": card,
                                            "record_kind": kind,
                                            "offer_kind": kind,
                                            "grant_kind": kind+1,
                                            "offer_label": offer_label,
                                            "select_kind": select_kind,
                                            "referer": referer,
                                            "label_hash": label_hash,
                                            "action_mode":action_mode,
                                            "content": content,
                                            "credential_record": credential_record
                                            
                                        })

@router.post("/updaterecord", tags=["records", "protected"])
async def update_record(    request: Request, 
                            update_card: updateCard,
                            acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Update card in safebox"""
    _raise_if_missing_acorn(acorn_obj)
    status = "OK"
    detail = "Nothing yet"


    
    
    # This is where we can do specialized handling for records that need to be transmittee

    try:

        await acorn_obj.put_record(record_name=update_card.title,record_value=update_card.content, record_kind=update_card.final_kind)
        detail = "Update successful!"
    except Exception as e:
        status = "ERROR"
        detail = f"Error: {e}"
    

    return {"status": status, "detail": detail} 

@router.post("/deleterecord", tags=["safebox", "protected"])
async def delete_card(         request: Request, 
                            delete_card: deleteCard,
                            acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Delete card from safebox"""
    _raise_if_missing_acorn(acorn_obj)
    status = "OK"
    detail = "Nothing yet"

    
    try:

        msg_out = await acorn_obj.delete_record(label=delete_card.title, record_kind=delete_card.kind)
        detail = f"Success! {msg_out}"
    except Exception as e:
        status = "ERROR"
        detail = f"Error: {e}"
    

    return {"status": status, "detail": detail} 

@router.post("/nauth", tags=["records", "protected"])
async def generate_nauth(    request: Request, 
                        nauth_request: nauthRequest,
                        acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to private data stored in home relay"""
    _raise_if_missing_acorn(acorn_obj)
    status = "OK"
    detail = "None"
    print(f"nauth request: {nauth_request}")
    nonce = None

    
    # acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    # await acorn_obj.load_data()
    # figure out to use the owner key or the wallet key
    # just use the wallet
    print("this is the records/nauth")

    # pub_hex_to_use = acorn_obj.pubkey_hex
    npub_to_use = acorn_obj.pubkey_bech32
    
    print(f"scope: {nauth_request.scope} nonce: {nonce}")

    try:

        
        transmittal_npub = acorn_obj.pubkey_bech32

        if nauth_request.transmittal_kind:
            transmittal_kind = nauth_request.transmittal_kind
        else:
            transmittal_kind = settings.RECORD_TRANSMITTAL_KIND
       
        if nauth_request.compact:
            auth_relays = None
            transmittal_relays = None
            default_nonce = generate_nonce(length=1)
        else:
            auth_relays = settings.AUTH_RELAYS
            transmittal_relays = settings.RECORD_TRANSMITTAL_RELAYS
            default_nonce = generate_nonce(length=16)

        nonce = default_nonce
        if nauth_request.nonce:
            nonce = str(nauth_request.nonce).strip() or default_nonce
        elif nauth_request.source_nauth:
            try:
                parsed_source_nauth = parse_nauth(nauth_request.source_nauth)
                source_nonce = parsed_source_nauth.get("values", {}).get("nonce")
                source_nonce = str(source_nonce).strip() if source_nonce is not None else ""
                if source_nonce:
                    nonce = source_nonce
            except Exception as exc:
                logger.warning("generate_nauth could not parse source_nauth nonce: %s", exc)

        detail = create_nauth(  npub=npub_to_use,
                                nonce=nonce,
                                auth_kind=settings.AUTH_KIND,
                                auth_relays=auth_relays,
                                transmittal_npub=transmittal_npub,
                                transmittal_kind = transmittal_kind,
                                transmittal_relays=transmittal_relays,
                                name=acorn_obj.handle,
                                scope=nauth_request.scope, 
                                grant=nauth_request.grant

                               
                            )
        

        print(f"scope: {nauth_request.scope} grant: {nauth_request.grant}")
        print(f"generated nauth: {detail} {len(detail)}")
      
    except Exception as exc:
        detail = "Not created"

    return {"status": status, "detail": detail}

@router.post("/sendrecord", tags=["records", "protected"])
async def post_send_record(      request: Request, 
                                record_parms: sendRecordParms,                                
                                acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Select record for verification"""
    _raise_if_missing_acorn(acorn_obj)
    nauth_response = None
    print(f"send record {record_parms}")

    if record_parms.nauth:
        parsed_nauth = parse_nauth(record_parms.nauth)

        scope = parsed_nauth['values']['scope']
        grant = parsed_nauth['values'].get("grant")
        

        
        pubhex = parsed_nauth['values']['pubhex']
        npub_recipient = hex_to_npub(pubhex)
        nonce = parsed_nauth['values'].get('nonce', '0')
        auth_kind = parsed_nauth['values'].get('auth_kind') or settings.AUTH_KIND
        auth_relays = parsed_nauth['values'].get('auth_relays') or settings.AUTH_RELAYS
        transmittal_pubhex = parsed_nauth['values'].get('transmittal_pubhex') or acorn_obj.pubkey_hex
        transmittal_kind = parsed_nauth['values'].get('transmittal_kind') or settings.RECORD_TRANSMITTAL_KIND
        transmittal_relays = parsed_nauth['values'].get('transmittal_relays') or settings.RECORD_TRANSMITTAL_RELAYS

        print(f"send record to transmittal_pubhex: {transmittal_pubhex} scope: {scope} grant:{grant}")

        # Need to inspect scope to determine what to do
        verifier_kind = None
        try:
            if "verifier" in scope:
                verifier_kind = _extract_kind_from_scope(scope, "verifier")
            elif "prover" in scope:
                verifier_kind = _extract_kind_from_scope(scope, "prover")
        except Exception:
            verifier_kind = None
        if verifier_kind is None and record_parms.grant_kind is not None:
            verifier_kind = int(record_parms.grant_kind)
        if verifier_kind is None:
            raise HTTPException(status_code=400, detail=f"Could not resolve grant kind from scope={scope}")

        #TODO refactor this code
        if "prover" in scope:
            # this means the presentation has the corresponding record hash
            transmittal_npub = hex_to_npub(transmittal_pubhex)
            print(f"grant: {record_parms.grant}")
            # record_hash = scope.replace("prover:","")
            # print(f"need to select credential with record hash {record_hash}")
            # record_out = await acorn_obj.get_record(record_kind=34002, record_by_hash=record_hash)
            record_out = await acorn_obj.get_record(record_name=record_parms.grant_name, record_kind=verifier_kind)
            
        elif "verifier" in scope:
            transmittal_npub = hex_to_npub(transmittal_pubhex)
            #need to figure how to pass in the label to look up
            print(f"grant: {record_parms.grant_name}")
            record_out = await acorn_obj.get_record(record_name=record_parms.grant_name, record_kind=verifier_kind)
            # record_out = {"tag": "TBD", "payload" : "This will be a real credential soon!"}
        else:
            record_out = {"tag": "TBD", "payload" : "This will be a real credential soon!"}

        


        # Add in PQC stuff
        print(f"PQC Step 2a {record_parms.kem_public_key} {record_parms.kemalg}")
        pqc = oqs.KeyEncapsulation(record_parms.kemalg,bytes.fromhex(config.PQC_KEM_SECRET_KEY))
        kem_ciphertext, kem_shared_secret = pqc.encap_secret(bytes.fromhex(record_parms.kem_public_key))
        kem_shared_secret_hex = kem_shared_secret.hex()
        kem_ciphertext_hex = kem_ciphertext.hex()

        k_nip44 = Keys(priv_k=kem_shared_secret_hex)
        print(f"kem shared secret: {kem_shared_secret_hex} ciphertext: {kem_ciphertext_hex}")
        try:
            pass
            my_enc = ExtendedNIP44Encrypt(k_nip44)
            print(f"my NIP44 enc: {my_enc}")
        except Exception as exc:
            logger.exception("Failed to initialize PQC NIP44 encryptor")
            raise HTTPException(status_code=500, detail="Encryption initialization failed")
        # Now add to record
        record_out['ciphertext']    = kem_ciphertext_hex
        record_out['kemalg']        = record_parms.kemalg

        payload = record_out['payload']
        record_out['pqc_encrypted_payload'] =  my_enc.encrypt(payload, to_pub_k=k_nip44.public_key_hex())
        record_out['payload'] = "This record is quantum-safe"
        print(f"This is the record to be sent for verification:{record_out}")
        print(f"Let's add in the original record if it exists do the same as /transmit")
        print("let's get the original record" )
        issued_record: Event
        original_record: OriginalRecordTransfer
        try:
            issued_grant, original_record = await acorn_obj.create_request_from_grant(
                grant_name=record_parms.grant_name,
                grant_kind=verifier_kind,
                shared_secret_hex=kem_shared_secret_hex,
            )
            print(f"grant to present is {issued_grant}")
        except Exception as exc:
            logger.warning(
                "sendrecord original_record lookup non-fatal grant=%s kind=%s error=%s",
                record_parms.grant_name,
                verifier_kind,
                exc,
            )
            original_record = None
       
        if original_record:           
            original_record_str = original_record.model_dump_json(exclude_none=True)
            print(f"now we need to include the original record: ")
            pqc_encrypted_original = my_enc.encrypt(to_pub_k=k_nip44.public_key_hex(),plain_text=original_record_str)

        else:
            print(f"no original record")
            pqc_encrypted_original = None

        record_out["pqc_encrypted_original"]= pqc_encrypted_original
        
        try:
            nembed = create_nembed_compressed(record_out)
        except Exception as exc:
            nembed = create_nembed_compressed({"test": "test"})
        # print(nembed)

        #TODO Need to select the right credential and send over the to verifier
        # just send scope for now

        # Need to get the PQC public key of the requestor

        print(f"we are sending a record to verify: {record_out}")
        msg_out = await acorn_obj.secure_transmittal(transmittal_npub,nembed, dm_relays=transmittal_relays,kind=transmittal_kind)

    return {"status": "OK", "result": True, "detail": f"Successfully sent to {transmittal_npub}for verification!"}

@router.websocket("/ws/recorddata")
async def ws_record_data( websocket: WebSocket,                                          
                                        acorn_obj = Depends(get_acorn)
                                        ):
    await websocket.accept()
    return

@router.websocket("/ws/present/{nauth}")
async def ws_record_present( websocket: WebSocket, 
                                        nauth:str=None, 
                                        acorn_obj: Acorn = Depends(get_acorn)
                                        ):
    print(f"websocket opened for /ws/present {nauth}")
    since_now = int(datetime.now(timezone.utc).timestamp())
    requester_nauth = None
    requester_nembed = None
    
    if nauth:
        parsed_nauth = parse_nauth(nauth) 
        pubhex_initiator =   parsed_nauth['values'] ['pubhex'] 
        auth_kind = parsed_nauth['values'].get('auth_kind', settings.AUTH_KIND)  
        auth_relays = parsed_nauth['values'].get('auth_relays', settings.AUTH_RELAYS)
        print(f"npub initiator: {hex_to_npub(pubhex_initiator)}")
    
    await websocket.accept()
    
    print("start listening for requester data")
    try:
        requester_nauth, requester_nembed = await acorn_obj.listen_for_record_sub(
            record_kind=auth_kind,
            since=None,
            relays=auth_relays,
            timeout=settings.LISTEN_TIMEOUT,
        )
        print(f"requester nauth: {requester_nauth} requester nembed: {requester_nembed}")
    except TimeoutError:
        try:
            await websocket.send_json({"status": "TIMEOUT", "detail": "Requester handshake timed out."})
        except WebSocketDisconnect:
            logger.info("ws_record_present client disconnected before TIMEOUT send")
        return
    except Exception as exc:
        logger.exception("ws_record_present handshake failure: %s", exc)
        try:
            await websocket.send_json({"status": "ERROR", "detail": "Handshake failed."})
        except WebSocketDisconnect:
            logger.info("ws_record_present client disconnected before ERROR send")
        return

    if not requester_nembed:
        try:
            await websocket.send_json({"status": "ERROR", "detail": "Missing requester key material."})
        except WebSocketDisconnect:
            logger.info("ws_record_present client disconnected before missing-material send")
        return

    try:
        parsed_nembed = parse_nembed_compressed(requester_nembed)
        kem_public_key = parsed_nembed['kem_public_key']
        kemalg = parsed_nembed['kemalg']
        print(f"From the requester provided to the presenter: kem public key: {kem_public_key} kemalg {kemalg}")
        kem_material = {'status': 'OK', 'kem_public_key': kem_public_key, 'kemalg': kemalg}
        await websocket.send_json(kem_material)
    except Exception as exc:
        logger.exception("ws_record_present invalid requester key material: %s", exc)
        try:
            await websocket.send_json({"status": "ERROR", "detail": "Invalid requester key material."})
        except WebSocketDisconnect:
            logger.info("ws_record_present client disconnected before invalid-material send")

    

@router.websocket("/ws/offer/{nauth}")
async def ws_record_offer( websocket: WebSocket, 
                                        nauth:str=None, 
                                        acorn_obj = Depends(get_acorn)
                                        ):
    # Legacy path retained for backward compatibility with retrieve/grantlist views.
    # Prefer /ws/listenfornauth for newer offer flows.

    print(f"ws nauth: {nauth}")
    auth_relays = None
    expected_nonce = None

    await websocket.accept()

    if nauth:
        parsed_nauth = parse_nauth(nauth) 
        pubhex_initiator = parsed_nauth['values'].get('pubhex')
        if not pubhex_initiator:
            await websocket.send_json({"status": "ERROR", "detail": "Invalid authentication payload."})
            return
        npub_initiator = hex_to_npub(pubhex_initiator)
        auth_kind = parsed_nauth['values'] ['auth_kind']   
        auth_relays = parsed_nauth['values']['auth_relays']
        expected_nonce = parsed_nauth['values'].get("nonce")
        print(f"npub initiator: {npub_initiator}")



        msg_out = await acorn_obj.secure_transmittal(nrecipient=npub_initiator,message=nauth,dm_relays=auth_relays,kind=auth_kind)

    naddr = acorn_obj.pubkey_bech32
    nauth_old = None
    # since_now = None
    since_now = int(datetime.now(timezone.utc).timestamp())
    start_time = datetime.now()

    while True:
        if datetime.now() - start_time > timedelta(minutes=1):
            print("1 minute has passed. Exiting loop.")
            await websocket.send_json({"status": "TIMEOUT", "detail": "Authentication timed out."})
            break
        try:
            # await acorn_obj.load_data()
            try:
                client_nauth, presenter,kem_public_key = await listen_for_request(
                    acorn_obj=acorn_obj,
                    kind=auth_kind,
                    since_now=since_now,
                    relays=auth_relays,
                    expected_nonce=expected_nonce,
                    expected_transmittal_pubhex=acorn_obj.pubkey_hex,
                )
            except Exception as exc:
                client_nauth=None
            

            
            # parsed_nauth = parse_nauth(client_nauth)
            # name = parsed_nauth['name']
            # print(f"client nauth {client_nauth}")
            

            if client_nauth != nauth_old: 
                if not _nonce_matches(expected_nonce, client_nauth):
                    logger.warning("ws_record_offer ignoring nonce mismatch for candidate response")
                    await asyncio.sleep(1)
                    continue
                parsed_nauth = parse_nauth(client_nauth)
                transmittal_kind = parsed_nauth['values'].get('transmittal_kind')
                transmittal_relays = parsed_nauth['values'].get('transmittal_relays')
                nprofile = {'nauth': client_nauth, 'name': 'safebox user', 'transmittal_kind': transmittal_kind, "transmittal_relays": transmittal_relays}
                print(f"send {client_nauth}") 
                await websocket.send_json(nprofile)
                nauth_old = client_nauth
                print("authentication successful!")
                break
           
        
        except Exception as e:
            print(f"Websocket message: {e}")
            break
        
        await asyncio.sleep(1)
        
        
        
    print("websocket connection closed")

@router.websocket("/ws/listenforrequestor/{nauth}")
async def ws_listen_for_requestor( websocket: WebSocket, 
                                        nauth:str=None, 
                                        acorn_obj = Depends(get_acorn)
                                        ):
    # Legacy path retained for backward compatibility with older requestor flows.
    # Prefer /ws/request for current request-record UX.
    """After presenting a QR code, listen for verifier reponse using nauth parameters"""
    print(f"ws nauth: {nauth}")
    auth_relays = None
    expected_nonce = None

    await websocket.accept()

    if nauth:
        parsed_nauth = parse_nauth(nauth)   
        auth_kind = parsed_nauth['values'] ['auth_kind']   
        auth_relays = parsed_nauth['values']['auth_relays']
        expected_nonce = parsed_nauth['values'].get("nonce")
        print(f"ws auth relays: {auth_relays}")



    # acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    # await acorn_obj.load_data()

    naddr = acorn_obj.pubkey_bech32
    nauth_old = None
    # since_now = None
    # Look back slightly to avoid missing same-second events.
    since_now = int((datetime.now(timezone.utc) - timedelta(seconds=5)).timestamp())
    start_time = datetime.now()

    while True:
        if datetime.now() - start_time > timedelta(seconds=settings.LISTEN_TIMEOUT):
            print("1 minute has passed. Exiting loop.")
            await websocket.send_json({"status":"TIMEOUT"})
            break
        try:
            # Error handling
            
            try:
                client_nauth, presenter, ken_public_key = await listen_for_request(
                    acorn_obj=acorn_obj,
                    kind=auth_kind,
                    since_now=since_now,
                    relays=auth_relays,
                    expected_nonce=expected_nonce,
                    expected_transmittal_pubhex=acorn_obj.pubkey_hex,
                )
            except Exception as exc:
                client_nauth=None
            


            if client_nauth != nauth_old: 
                if not _nonce_matches(expected_nonce, client_nauth):
                    logger.warning("ws_listen_for_requestor ignoring nonce mismatch for candidate response")
                    await asyncio.sleep(1)
                    continue
                parsed_nauth = parse_nauth(client_nauth)
                transmittal_kind = parsed_nauth['values'].get('transmittal_kind')
                transmittal_relays = parsed_nauth['values'].get('transmittal_relays')
                msg_out =   {   "status": "PRESENTACK",
                                'nauth': client_nauth, 
                                'name': 'safebox user', 
                                'transmittal_kind': transmittal_kind, 
                                'transmittal_relays': transmittal_relays}
                print(f"send {client_nauth}") 
                await websocket.send_json(msg_out)
                nauth_old = client_nauth
                print("credential presentation successful!")
                break
           
        
        except Exception as e:
            print(f"Websocket message: {e}")
            break
        
        await asyncio.sleep(1)
     
        
    print("websocket connection closed")

@router.websocket("/ws/request/{nauth}")
async def ws_request_record( websocket: WebSocket, 
                                        nauth:str=None, 
                                        acorn_obj: Acorn = Depends(get_acorn)
                                        ):

    print(f"listen with: {nauth}")
    auth_relays = None
    expected_nonce = None

    await websocket.accept()


    request_scope = None
    receive_offer_mode = False
    if nauth:
        parsed_nauth = parse_nauth(nauth)   
        auth_kind = parsed_nauth['values'].get('auth_kind', settings.AUTH_KIND)  
        auth_relays = parsed_nauth['values'].get('auth_relays', settings.AUTH_RELAYS)
        transmittal_kind = parsed_nauth['values'].get('transmittal_kind', settings.RECORD_TRANSMITTAL_KIND)  
        transmittal_relays = parsed_nauth['values'].get('transmittal_relays', settings.RECORD_TRANSMITTAL_RELAYS)
        expected_nonce = parsed_nauth['values'].get('nonce')
        request_scope = parsed_nauth['values'].get('scope')
        receive_offer_mode = isinstance(request_scope, str) and request_scope.startswith("offer_request")
        print(f"ws transmittal relays: {transmittal_relays}")


    # since_now = None
    # Look back slightly to avoid missing same-second events.
    since_now = int((datetime.now(timezone.utc) - timedelta(seconds=5)).timestamp())
    start_time = datetime.now()
    


    

    naddr = acorn_obj.pubkey_bech32
    incoming_record_old = None

    # Need to:
    # 1. listen for nauth of presenting safebox
    # 2. send kem public key and kemalg
    # 3. listen for incoming records

    
    print(f"#1 listen for nauth ")
    presenter_nauth = None
    presenter_nembed = None
    handshake_deadline = datetime.now(timezone.utc) + timedelta(seconds=max(5, settings.LISTEN_TIMEOUT))
    while datetime.now(timezone.utc) < handshake_deadline:
        remaining = int((handshake_deadline - datetime.now(timezone.utc)).total_seconds())
        poll_timeout = max(3, min(10, remaining))
        try:
            candidate_nauth, candidate_nembed = await acorn_obj.listen_for_record_sub(
                record_kind=auth_kind,
                since=since_now,
                relays=auth_relays,
                timeout=poll_timeout,
            )
        except Exception as exc:
            logger.exception("ws_request_record presenter handshake failed: %s", exc)
            candidate_nauth, candidate_nembed = None, None

        if not candidate_nauth:
            since_now = int((datetime.now(timezone.utc) - timedelta(seconds=1)).timestamp())
            await asyncio.sleep(0.2)
            continue

        if not _nonce_matches(expected_nonce, candidate_nauth):
            logger.warning("ws_request_record ignoring nonce mismatch for candidate response")
            since_now = int((datetime.now(timezone.utc) - timedelta(seconds=1)).timestamp())
            await asyncio.sleep(0.2)
            continue

        presenter_nauth, presenter_nembed = candidate_nauth, candidate_nembed
        break

    if not presenter_nauth:
        try:
            await websocket.send_json({"status": "TIMEOUT", "detail": "Presenter did not acknowledge in time."})
        except WebSocketDisconnect:
            logger.info("ws_request_record client disconnected before presenter TIMEOUT send")
        return
    parsed_nauth = parse_nauth(presenter_nauth)

    
    print(f"we've got presenter nauth {presenter_nauth}")
    presenter_nauth_parsed = parse_nauth(presenter_nauth)
    presenter_npub = hex_to_npub(presenter_nauth_parsed['values']['pubhex'])
    presenter_auth_kind = presenter_nauth_parsed['values'].get('auth_kind', settings.AUTH_KIND)
    presenter_auth_relays = presenter_nauth_parsed['values'].get('auth_relays', settings.AUTH_RELAYS)
    
    print("we can now send the kem public key and kemalg")
    #TODO Need to add in additional info for blossom blob transfer

    kem_material = {    'kem_public_key': config.PQC_KEM_PUBLIC_KEY,
                        'kemalg': settings.PQC_KEMALG
                        }
    nembed_to_send = create_nembed_compressed(kem_material)
    message = f"{nauth}:{nembed_to_send}"
    print(f"send to presenter npub: {presenter_npub}")

    msg_out = await acorn_obj.secure_transmittal(nrecipient=presenter_npub,message=message,kind=presenter_auth_kind,dm_relays=presenter_auth_relays)
    print(f"msg out {msg_out}")
    


    print(f"now let's wait for the presenting records...")
    while True:
        if datetime.now() - start_time > timedelta(minutes=1):
            print("1 minute has passed. Exiting loop.")
            try:
                await websocket.send_json({"status":"TIMEOUT"})
            except WebSocketDisconnect:
                logger.info("ws_request_record client disconnected before TIMEOUT send")
            break
        try:
            # await acorn_obj.load_data()
            try:
                incoming_record,presenter,kem_public_key = await listen_for_request(
                    acorn_obj=acorn_obj,
                    kind=transmittal_kind,
                    since_now=since_now,
                    relays=transmittal_relays,
                    allow_since_fallback=False,
                )
            except Exception as e:
                incoming_record=None
            


            if incoming_record != incoming_record_old: 
                if not incoming_record:
                    await asyncio.sleep(1)
                    continue
                # parsed_nauth = parse_nauth(client_nauth)
                # transmittal_kind = parsed_nauth['values'].get('transmittal_kind')
                # transmittal_relays = parsed_nauth['values'].get('transmittal_relays')
                if isinstance(incoming_record, (dict, list)):
                    # Some flows deliver already-decoded record payloads via get_user_records.
                    record_json = incoming_record
                else:
                    try:
                        record_json = parse_nembed_compressed(incoming_record)
                    except Exception as exc:
                        logger.warning("ws_request_record could not parse incoming nembed: %s", exc)
                        incoming_record_old = incoming_record
                        await asyncio.sleep(1)
                        continue
                print(f"parse record json: {record_json}")
                #### Do the verification here... ####
                verify_result = "Done"
                #### Finish verification ####
                

                #FIXME Record coming via QR code is single from NFC is a List
                if not isinstance(record_json, list):
                    record_json = [record_json]

                # Check each record payload and decide how to validate
                # Payload is either plain text or dict.
                # If payload is dict, then it is a signed nostr event embedded in the payload
                # determine content to display and verification result

                out_records =[]
                persisted_records: List[str] = []
                records_missing_original_blob: List[str] = []
                is_valid = "Cannot Validate"
                is_presenter = False
                #TODO This needs to be refactored into a verification function
                for each in record_json:
                    decrypted_original = None
                    original_record_to_present_json = None
                    incoming_original_record = each.get("original_record")
                    if isinstance(incoming_original_record, dict):
                        original_record_to_present_json = incoming_original_record
                    elif isinstance(incoming_original_record, str):
                        try:
                            original_record_to_present_json = json.loads(incoming_original_record)
                        except Exception:
                            original_record_to_present_json = None
                    # Add in PQC stuff here
                    record_ciphertext = each.get("ciphertext", None)
                    record_kemalg = each.get("kemalg", None) 
                    if record_ciphertext and record_kemalg:
                        try:
                            pqc = oqs.KeyEncapsulation(record_kemalg,bytes.fromhex(config.PQC_KEM_SECRET_KEY))
                            kem_shared_secret = pqc.decap_secret(bytes.fromhex(record_ciphertext))
                            kem_shared_secret_hex = kem_shared_secret.hex()
                            print(f"This is the shared secret: {kem_shared_secret_hex}")
                            k_pqc = Keys(priv_k=kem_shared_secret_hex)
                            my_enc = ExtendedNIP44Encrypt(k_pqc)
                            payload_to_decrypt = each.get("pqc_encrypted_payload", None)
                            original_record_to_decrpyt = each.get("pqc_encrypted_original", None)
                            if payload_to_decrypt:
                                decrypted_payload = my_enc.decrypt(payload=payload_to_decrypt, for_pub_k=k_pqc.public_key_hex())
                                print(f"decrypted payload to put in content: {decrypted_payload} compare to content: {each['payload']}")
                                each['payload'] = decrypted_payload
                            if original_record_to_decrpyt:
                                print("there is an original record in the presentation!")
                                decrypted_original = my_enc.decrypt(payload=original_record_to_decrpyt, for_pub_k=k_pqc.public_key_hex())
                                print(f"decrypted original for presentation: {decrypted_original}") 
                                orignal_record_transfer: OriginalRecordTransfer
                                try:
                                    original_record_to_present_json = json.loads(decrypted_original)
                                    original_record_transfer = OriginalRecordTransfer(**json.loads(decrypted_original))
                                    print(f"original record transfer {original_record_transfer}")
                                except Exception as e:
                                    logger.warning("ws_request_record original record parse failed: %s", e)
                                    original_record_to_present_json = None
                        except Exception as exc:
                            logger.warning(
                                "ws_request_record payload decrypt skipped tag=%s kind=%s: %s",
                                each.get("tag"),
                                each.get("type"),
                                exc,
                            )
                    elif record_ciphertext and not record_kemalg:
                        logger.warning(
                            "ws_request_record payload decrypt skipped tag=%s kind=%s: missing kemalg",
                            each.get("tag"),
                            each.get("type"),
                        )

                        
                    

                    print(f"each to present: {each} {presenter}")
                    payload_to_use = each.get('payload')

                    print(f"each ciphertext {each.get('ciphertext','None')}")
                    is_valid = "Cannot Validate"
                    event_to_validate = _parse_event_payload(payload_to_use)
                    if event_to_validate:
                        print(f"event to validate tags: {event_to_validate.tags}")
                        tag_owner = get_tag_value(event_to_validate.tags, "safebox_owner")
                        tag_issuer = get_tag_value(event_to_validate.tags, "safebox_issuer")
                        tag_holder = get_tag_value(event_to_validate.tags, "safebox_holder")
                        
                        type_name = get_label_by_id(settings.GRANT_KINDS,event_to_validate.kind)
                        # owner_name = tag_owner
                        owner_info, picture = await get_profile_for_pub_hex(tag_owner,settings.RELAYS)
                        print(f"safebox issuer: {tag_owner} {owner_info}")
                        # Need to check signature too
                        print("let's check signature")  
                        print(f"event to validate: {event_to_validate.data()}")
                
                        if event_to_validate.is_valid():
                            is_valid = "True"

                        
                        is_attested = await get_attestation(owner_npub=tag_owner,safebox_npub=acorn_obj.pubkey_bech32, relays=settings.RELAYS)
                        
                        # authorities = await acorn_obj.get_authorities(kind=event_to_validate.kind)
                        # trust_list = "npub1vqddl2xav68jyyg669r8eqnv5akx6n5fgky698tfr3d4vy30enpse34f7m # npub1q6mcr8tlr3l4gus3sfnw6772s7zae6hqncmw5wj27ejud5wcxf7q0nx7d5"
                        # await acorn_obj.set_trusted_entities(pub_list_str=trust_list)
                        trusted_entities = await acorn_obj.get_trusted_entities(relays=settings.RELAYS)
                        # trusted_entities = ['06b7819d7f1c7f5472118266ed7bca8785dceae09e36ea3a4af665c6d1d8327c', '601adfa8dd668f22111ad1467c826ca76c6d4e894589a29d691c5b56122fccc3']

                        print(f"trusted_entities: {trusted_entities} tag owner {tag_owner}")
                        if tag_owner in trusted_entities:
                            is_trusted = True
                        else:
                            is_trusted = False

                        print(f"test for presenter: {presenter} tag holder: {tag_holder}")
                        if presenter == tag_holder:
                            is_presenter = True

                        print(f"is attested: {is_attested}")
                        rating = "TBD"
                        wot_scores = await acorn_obj.get_wot_scores(pub_key_to_score=tag_owner, relays=settings.WOT_RELAYS)
                        # print(f"rating of owner is: {rating}")
                        wot_scores_to_show = "\n".join(f"⭐️ {label}: {value}" for label, value in wot_scores)
                        # wot_scores_to_show = "⭐️"
                        content = f"{event_to_validate.content}"
                        each["content"] = content
                        each["verification"] = f"\nIssuer: {owner_info}\n[{tag_owner[:6]}:{tag_owner[-6:]}]  \nKind: {event_to_validate.kind} \nCreated at: {event_to_validate.created_at} \n\n|{'✅' if is_valid else '❌'} Valid|{'✅' if is_presenter else '❌'} Self-Presented|\n{'✅' if is_attested else '❌'} Attested By Issuer|{'✅' if is_trusted else '❌'} Recognized|\nIssuer WoT Scores\n ------\n{wot_scores_to_show}\n-----"
                        each["picture"] = picture
                        each["is_attested"] = is_attested
                        each["original_record"] = original_record_to_present_json

                        # PQC Stuff here

            
                       


                    else:
                        each["content"] = _extract_payload_content(payload_to_use)
                        each["verification"] = f"\n\n{'_'*40}\n\nPlain Text {is_valid}"
                        each["picture"] = None
                        each["is_attested"] = False

                    if receive_offer_mode:
                        try:
                            raw_tag = each.get("tag")
                            if isinstance(raw_tag, list) and raw_tag:
                                record_name = str(raw_tag[0])
                            else:
                                record_name = str(each.get("content") or "received-offer")

                            record_kind = int(each.get("type") or each.get("kind") or transmittal_kind)
                            record_value = each.get("payload")
                            if not isinstance(record_value, str):
                                record_value = json.dumps(record_value)

                            record_origin = presenter
                            try:
                                if isinstance(presenter, str) and len(presenter) == 64:
                                    record_origin = hex_to_npub(presenter)
                            except Exception:
                                pass

                            await acorn_obj.put_record(
                                record_name=record_name,
                                record_value=record_value,
                                record_kind=record_kind,
                                record_origin=record_origin,
                            )
                            persisted_records.append(f"{record_name}:{record_kind}")

                            if decrypted_original:
                                blob_result = await acorn_obj.transfer_blob(
                                    record_name=record_name,
                                    record_kind=record_kind,
                                    record_origin=record_origin,
                                    blobxfer=decrypted_original,
                                    blossom_xfer_server=settings.BLOSSOM_XFER_SERVER,
                                    blossom_home_server=settings.BLOSSOM_HOME_SERVER,
                                )
                                if blob_result.get("status") != "OK":
                                    logger.warning(
                                        "ws_request_record transfer_blob non-fatal status record=%s kind=%s status=%s reason=%s",
                                        record_name,
                                        record_kind,
                                        blob_result.get("status"),
                                        blob_result.get("reason"),
                                    )
                                    if blob_result.get("reason") == "original_record_not_available":
                                        records_missing_original_blob.append(record_name)
                        except Exception as exc:
                            logger.warning("ws_request_record failed to persist received offer record: %s", exc)

                    out_records.append(each)
                    print(f"out records: {out_records}")


                msg_out =   {   "status": "VERIFIED",
                                "detail": None, 
                                "records": out_records,
                                "result": is_valid
                               
                               }
                if receive_offer_mode and persisted_records:
                    msg_out["detail"] = f"Stored {len(persisted_records)} incoming grant record(s)."
                if receive_offer_mode and records_missing_original_blob:
                    msg_out["warning"] = (
                        "Original record blob unavailable for: "
                        + ", ".join(records_missing_original_blob)
                    )
                # print(f"send {incoming_record} {record_json}") 
                # print(f"msg out: {msg_out}") 
                try:
                    await websocket.send_json(msg_out)
                except WebSocketDisconnect:
                    logger.info("ws_request_record client disconnected before VERIFIED send")
                    break
                incoming_record_old = incoming_record
                print("incoming record  successful!")
                break
           
        
        except WebSocketDisconnect:
            logger.info("ws_request_record client disconnected")
            break
        except Exception as e:
            logger.exception("ws_request_record processing error: %s", e)
            try:
                await websocket.send_json({"status": "ERROR", "detail": "Record processing error. Please retry."})
            except WebSocketDisconnect:
                logger.info("ws_request_record client disconnected while sending ERROR status")
                break
            await asyncio.sleep(1)
            continue
        
        await asyncio.sleep(1)
     
        
    print("websocket connection closed")

@router.websocket("/ws/listenfornauth/{nauth}")
async def ws_listen_for_nauth( websocket: WebSocket, 
                                        nauth:str=None, 
                                        acorn_obj = Depends(get_acorn)
                                        ):

    print(f"ws nauth: {nauth}")
    auth_kind = settings.AUTH_KIND
    auth_relays = None
    expected_nonce = None

    await websocket.accept()

    if nauth:
        parsed_nauth = parse_nauth(nauth)   
        auth_kind = parsed_nauth['values'].get('auth_kind',   settings.AUTH_KIND)
        auth_relays = _normalize_relay_list(
            parsed_nauth['values'].get("auth_relays"),
            settings.AUTH_RELAYS,
        )
        expected_nonce = parsed_nauth['values'].get("nonce")
        print(
            "ws_listen_for_nauth resolved auth params "
            f"kind={auth_kind} relays={auth_relays} nonce={expected_nonce}"
        )



    # acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    # await acorn_obj.load_data()

    naddr = acorn_obj.pubkey_bech32
    nauth_old = None
    # since_now = None
    # Look back slightly to avoid missing same-second events.
    since_now = int((datetime.now(timezone.utc) - timedelta(seconds=5)).timestamp())
    start_time = datetime.now()

    # This is PQC Step 2 in the KEM iteraction 
    while True:
        if datetime.now() - start_time > timedelta(seconds=settings.LISTEN_TIMEOUT):
            print("listenfornauth timeout reached. Exiting loop.")
            try:
                await websocket.send_json({"status": "TIMEOUT", "detail": "Authentication timed out."})
            except WebSocketDisconnect:
                logger.info("ws_listen_for_nauth client disconnected before TIMEOUT send")
            break
        try:
            # await acorn_obj.load_data()
            try:
                client_nauth,presenter,kem_public_key_nauth = await listen_for_request(
                    acorn_obj=acorn_obj,
                    kind=auth_kind,
                    since_now=since_now,
                    relays=auth_relays,
                    expected_nonce=expected_nonce,
                )
                kem_public_key = None
                kemalg = None
                if kem_public_key_nauth:
                    kem_public_key, kemalg = _extract_kem_from_nembed(kem_public_key_nauth)
                    if not kem_public_key or not kemalg:
                        logger.warning("ws_listen_for_nauth invalid or incomplete KEM payload")

                if client_nauth and (not kem_public_key or not kemalg):
                    try:
                        parsed_candidate = parse_nauth(client_nauth)
                        candidate_scope = parsed_candidate["values"].get("scope")
                        candidate_auth_relays = parsed_candidate["values"].get("auth_relays") or auth_relays or []
                        candidate_tx_relays = parsed_candidate["values"].get("transmittal_relays") or []

                        candidate_origins: list[str] = []
                        seen_origins: set[str] = set()

                        def add_origin(origin: str | None):
                            if origin and origin not in seen_origins:
                                seen_origins.add(origin)
                                candidate_origins.append(origin)

                        def add_origin_from_relay(relay: str | None):
                            add_origin(_relay_to_http_origin(relay or ""))

                        if isinstance(candidate_scope, str) and candidate_scope.startswith("offer_request:"):
                            _, _, scope_host = _parse_offer_request_scope(candidate_scope)
                            add_origin(_origin_from_host(scope_host))

                        for relay in (candidate_tx_relays or []):
                            add_origin_from_relay(relay)
                        for relay in (candidate_auth_relays or []):
                            add_origin_from_relay(relay)

                        resolved_kem_public_key, resolved_kemalg = await _resolve_kem_from_service_hosts(candidate_origins)
                        if resolved_kem_public_key and resolved_kemalg:
                            kem_public_key = resolved_kem_public_key
                            kemalg = resolved_kemalg
                            logger.info("ws_listen_for_nauth resolved KEM via host hints")
                    except Exception as exc:
                        logger.debug("ws_listen_for_nauth legacy KEM discovery skipped: %s", exc)

                print(f"this is the kem public key: {kem_public_key} kemalg: {kemalg}")
                # These parameters get passed along to Step 2a via the browser.
            except Exception as exc:
                client_nauth=None
            

            
            # parsed_nauth = parse_nauth(client_nauth)
            # name = parsed_nauth['name']
            # print(f"client nauth {client_nauth}")
            

            if client_nauth != nauth_old: 
                if not _nonce_matches(expected_nonce, client_nauth):
                    logger.warning("ws_listen_for_nauth ignoring nonce mismatch for candidate response")
                    await asyncio.sleep(1)
                    continue
                parsed_nauth = parse_nauth(client_nauth)
                pubhex = parsed_nauth['values'].get('pubhex')
                transmittal_pubhex = parsed_nauth['values'].get('transmittal_pubhex')
                transmittal_kind = parsed_nauth['values'].get('transmittal_kind') or settings.RECORD_TRANSMITTAL_KIND
                transmittal_relays = _normalize_relay_list(
                    parsed_nauth['values'].get('transmittal_relays'),
                    settings.RECORD_TRANSMITTAL_RELAYS,
                )
                
                # Need to create a new nauth where the transmittal npub points back to the initiator
                new_nauth = create_nauth (  npub= hex_to_npub(pubhex),
                                            nonce = parsed_nauth['values'].get('nonce'),
                                            auth_kind = parsed_nauth['values'].get('auth_kind') or settings.AUTH_KIND,
                                            auth_relays = _normalize_relay_list(
                                                parsed_nauth['values'].get('auth_relays'),
                                                settings.AUTH_RELAYS,
                                            ),
                                            transmittal_npub = hex_to_npub(pubhex),
                                            transmittal_kind=  transmittal_kind,
                                            transmittal_relays= transmittal_relays,
                                            scope= parsed_nauth['values'].get('scope'),
                                            grant = parsed_nauth['values'].get('grant')

                ) 

                if not kem_public_key or not kemalg:
                    logger.info("ws_listen_for_nauth proceeding without embedded KEM; transmit path will resolve fallback")
                #FIXME use a better variable name than nprofile. Also some extra parameters not needed.
                nprofile = {'nauth': new_nauth, 'name': acorn_obj.handle, 'transmittal_kind': transmittal_kind, 'transmittal_relays': transmittal_relays, "kem_public_key": kem_public_key, 'kemalg': kemalg}
                print(f"send {client_nauth}") 
                await websocket.send_json(nprofile)
                nauth_old = client_nauth
                break
           
        
        except WebSocketDisconnect:
            logger.info("ws_listen_for_nauth client disconnected")
            break
        except Exception as e:
            print(f"Websocket message: {e}")
            break
        
        await asyncio.sleep(1)
        
        
    print("websocket connection closed")    

@router.post("/acceptprooftoken", tags=["records", "protected"])
async def accept_proof_token( request: Request, 
                                proof_token: proofByToken,
                                acorn_obj: Acorn = Depends(get_acorn)
                    ):
    _raise_if_missing_acorn(acorn_obj)
   

    k = Keys(config.SERVICE_NSEC)

    status = "OK"
    detail = "done"
  
    
    token_to_use = proof_token.proof_token
    label_to_use = proof_token.label
    record_kind_to_use = proof_token.kind

    if not token_to_use:
        return {"status": "ERROR", "detail": "Missing proof token."}

    host = request.url.hostname or ""
    proof_token_to_use = token_to_use
    nfc_default = ["Holder", "default"]
    try:
        parsed_nembed = parse_nembed_compressed(token_to_use)
        host = parsed_nembed.get("h") or host
        proof_token_to_use = parsed_nembed.get("k") or proof_token_to_use
        nfc_default = parsed_nembed.get("n", nfc_default)
    except (KeyError, TypeError, ValueError) as exc:
        # Backward compatibility: allow legacy cards that store raw token material.
        logger.info("acceptprooftoken using legacy raw token fallback: %s", exc)

    origin = _origin_from_host(host)
    if not origin:
        return {"status": "ERROR", "detail": "Invalid NFC proof token host."}
    vault_url = f"{origin}/.well-known/proof"

    print(f"proof token: {token_to_use} acquired pin: {proof_token.pin} record kind {record_kind_to_use} label to use: {label_to_use} nfc default: {nfc_default}")

    # If Holder is specified using kind 9999 then look up default
    if record_kind_to_use == 99999:
        record_kind_to_use = get_id_by_label(settings.GRANT_KINDS, nfc_default[0])
        label_to_use = nfc_default[1]
        
    print(f"record kind to use: {record_kind_to_use} {type(record_kind_to_use)} {label_to_use} {type(label_to_use)}")
    
    sig = sign_payload(proof_token_to_use, k.private_key_hex())
    pubkey = k.public_key_hex()
    card_ok, card_detail, preflight_definitive = await _preflight_card_status(origin, proof_token_to_use, pubkey, sig)
    if not card_ok:
        if preflight_definitive:
            logger.warning("Proof preflight rejected host=%s detail=%s", host, card_detail)
            return {"status": "ERROR", "detail": card_detail}
        # On transport-level uncertainty, continue and rely on authoritative vault validation.
        logger.warning("Proof preflight advisory host=%s detail=%s", host, card_detail)

    # need to send off to the vault for processing
    request_auth = _build_record_request_auth(
        service_keys=k,
        flow="record_proof",
        token=proof_token_to_use,
        nauth=proof_token.nauth,
        label=label_to_use,
        kind=record_kind_to_use,
        pin=proof_token.pin,
        requester_pubkey=proof_token.requester_pubkey,
        requester_sig=proof_token.requester_sig,
        requester_nonce=proof_token.requester_nonce,
        requester_ts=proof_token.requester_ts,
    )
    submit_data = {
        "nauth": proof_token.nauth,
        "token": proof_token_to_use,
        "label": label_to_use,
        "kind": record_kind_to_use,
        "pin": proof_token.pin,
        "pubkey": pubkey,
        "sig": sig,
        **request_auth,
    }
    
    headers = { "Content-Type": "application/json"}
    print(f"vault url: {vault_url} submit data: {submit_data}")

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url=vault_url, json=submit_data, headers=headers)
            response.raise_for_status()
            vault_response = response.json()
    except httpx.TimeoutException:
            logger.warning("Proof vault timeout for origin=%s", origin)
            return {"status": "ERROR", "detail": "Proof vault request timed out."}
    except httpx.HTTPStatusError as exc:
        response_text = ""
        try:
            response_text = exc.response.json().get("detail", "")
        except ValueError:
            response_text = exc.response.text
        logger.warning(
            "Proof vault HTTP error %s for origin=%s body=%s",
            exc.response.status_code,
            origin,
            response_text,
        )
        detail_text = response_text or f"Proof vault returned HTTP {exc.response.status_code}."
        return {"status": "ERROR", "detail": detail_text}
    except httpx.RequestError as exc:
        logger.warning("Proof vault network error for origin=%s: %s", origin, exc)
        return {"status": "ERROR", "detail": "Proof vault network error."}
    except ValueError:
        logger.warning("Proof vault returned non-JSON response for origin=%s", origin)
        return {"status": "ERROR", "detail": "Proof vault returned an invalid response."}
    
    print(vault_response)

    # add in the polling task here
   
    # task = asyncio.create_task(handle_payment(acorn_obj=acorn_obj,cli_quote=cli_quote, amount=final_amount, tendered_amount=payment_token.amount, tendered_currency=payment_token.currency, mint=HOME_MINT, comment=payment_token.comment))

    return {
        "status": vault_response.get("status", "ERROR"),
        "detail": vault_response.get("detail", "Proof vault request completed."),
    }

@router.post("/acceptoffertoken", tags=["records", "protected"])
async def accept_offer_token( request: Request, 
                                offer_token: OfferToken,
                                acorn_obj: Acorn = Depends(get_acorn)
                    ):
    _raise_if_missing_acorn(acorn_obj)
   

    k = Keys(config.SERVICE_NSEC)

    status = "OK"
    detail = "done"
  
    
    token_to_use = offer_token.offer_token
    if not token_to_use:
        return {"status": "ERROR", "detail": "Missing offer token."}

    host = request.url.hostname or ""
    offer_token_to_use = token_to_use
    try:
        parsed_nembed = parse_nembed_compressed(token_to_use)
        host = parsed_nembed.get("h") or host
        offer_token_to_use = parsed_nembed.get("k") or offer_token_to_use
    except (KeyError, TypeError, ValueError) as exc:
        # Backward compatibility: allow legacy cards that store raw token material.
        logger.info("acceptoffertoken using legacy raw token fallback: %s", exc)

    origin = _origin_from_host(host)
    if not origin:
        return {"status": "ERROR", "detail": "Invalid NFC offer token host."}
    offer_url = f"{origin}/.well-known/offer"

    print(f"proof token: {token_to_use}")


    
    sig = sign_payload(offer_token_to_use, k.private_key_hex())
    pubkey = k.public_key_hex()
    card_ok, card_detail, preflight_definitive = await _preflight_card_status(origin, offer_token_to_use, pubkey, sig)
    if not card_ok:
        if preflight_definitive:
            logger.warning("Offer preflight rejected host=%s detail=%s", host, card_detail)
            return {"status": "ERROR", "detail": card_detail}
        # On transport-level uncertainty, continue and rely on authoritative vault validation.
        logger.warning("Offer preflight advisory host=%s detail=%s", host, card_detail)

    # need to send off to the vault for processing with negotiated recipient KEM
    kem_public_key = offer_token.kem_public_key
    kemalg = offer_token.kemalg
    if (
        not kem_public_key or kem_public_key == "None" or
        not kemalg or kemalg == "None"
    ):
        # NFC flows may not always have browser-captured KEM state yet.
        # Resolve recipient KEM directly from the target host as fallback.
        kem_url = f"{origin}/.well-known/kem"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                kem_response = await client.get(kem_url)
                kem_response.raise_for_status()
                kem_payload = kem_response.json()
            kem_public_key = kem_payload.get("kem_public_key")
            kemalg = kem_payload.get("kemalg")
            logger.info("acceptoffertoken resolved KEM from origin=%s", origin)
        except Exception as exc:
            logger.warning("acceptoffertoken unable to resolve KEM from origin=%s: %s", origin, exc)
            return {"status": "ERROR", "detail": "Recipient channel is not quantum-safe yet. Please re-authenticate and retry."}

    if (
        not kem_public_key or kem_public_key == "None" or
        not kemalg or kemalg == "None"
    ):
        logger.warning("acceptoffertoken missing KEM material after host lookup; rejecting request")
        return {"status": "ERROR", "detail": "Recipient channel is not quantum-safe yet. Please re-authenticate and retry."}

    request_auth = _build_record_request_auth(
        service_keys=k,
        flow="record_offer",
        token=offer_token_to_use,
        nauth=offer_token.nauth,
        kem_public_key=kem_public_key,
        kemalg=kemalg,
        requester_pubkey=offer_token.requester_pubkey,
        requester_sig=offer_token.requester_sig,
        requester_nonce=offer_token.requester_nonce,
        requester_ts=offer_token.requester_ts,
    )
    submit_data = {
        "nauth": offer_token.nauth,
        "token": offer_token_to_use,
        "pubkey": pubkey,
        "sig": sig,
        "kem_public_key": kem_public_key,
        "kemalg": kemalg,
        **request_auth,
    }
    print(f"data: {submit_data}")
    headers = { "Content-Type": "application/json"}
    print(f"offer url: {offer_url} submit data: {submit_data}")

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url=offer_url, json=submit_data, headers=headers)
            response.raise_for_status()
            response_json = response.json()
    except httpx.TimeoutException:
            logger.warning("Offer vault timeout for origin=%s", origin)
            return {"status": "ERROR", "detail": "Offer vault request timed out."}
    except httpx.HTTPStatusError as exc:
        response_text = ""
        try:
            response_text = exc.response.json().get("detail", "")
        except ValueError:
            response_text = exc.response.text
        logger.warning(
            "Offer vault HTTP error %s for origin=%s body=%s",
            exc.response.status_code,
            origin,
            response_text,
        )
        detail_text = response_text or f"Offer vault returned HTTP {exc.response.status_code}."
        return {"status": "ERROR", "detail": detail_text}
    except httpx.RequestError as exc:
        logger.warning("Offer vault network error for origin=%s: %s", origin, exc)
        return {"status": "ERROR", "detail": "Offer vault network error."}
    except ValueError:
        logger.warning("Offer vault returned non-JSON response for origin=%s", origin)
        return {"status": "ERROR", "detail": "Offer vault returned an invalid response."}
    
    print(f"response from vault: {response_json}")

    print("Now need to issue the private records")


    # add in the polling task here
   
    # task = asyncio.create_task(handle_payment(acorn_obj=acorn_obj,cli_quote=cli_quote, amount=final_amount, tendered_amount=payment_token.amount, tendered_currency=payment_token.currency, mint=HOME_MINT, comment=payment_token.comment))

    return {
        "status": response_json.get("status", status),
        "detail": response_json.get("detail", detail),
    }  

@router.get("/blob")
async def get_blob(
    record_name: str,
    record_kind: int,
    acorn_obj: Acorn = Depends(get_acorn)
):
    _raise_if_missing_acorn(acorn_obj)
    blob_type, blob_data = await acorn_obj.get_record_blobdata(
        record_name=record_name,
        record_kind=record_kind
    )
    
    if not blob_data or not blob_type:
        raise HTTPException(status_code=404, detail="Blob not available")

    blob_type = blob_type.split(";")[0].strip().lower()
    print(f"getblob: {record_name} {record_kind} {blob_type}")

    return Response(
        content=blob_data,
        media_type=blob_type,
        headers={"Cache-Control": "no-store"}
    )


@router.post("/blob")
async def post_blob(
    req: BlobRequest,
    acorn_obj: Acorn = Depends(get_acorn)  # your protected session
):
    _raise_if_missing_acorn(acorn_obj)
    blob_type, blob_data = await acorn_obj.get_record_blobdata(record_name=req.record_name, record_kind=req.record_kind)

    if blob_data is None:
        raise HTTPException(status_code=404, detail="Blob data not found")

    if not blob_data or not blob_type:
        raise HTTPException(status_code=404, detail="Blob not available")
    
       
    

    blob_type = blob_type.split(";")[0].strip()

    print (f"returned blob type: {blob_type} blob data: {type(blob_data)}")
    return Response(
        content= blob_data,        # raw bytes
        media_type=blob_type,      # image/png, application/pdf, etc.
        headers={
            "Content-Disposition": "inline",
            "Cache-Control": "no-store"  # recommended for protected content
        }
    )


@router.post("/originalblob")
async def retrieve_blob(
    original_record: OriginalRecordTransfer,
    acorn_obj: Acorn = Depends(get_acorn)  # your protected session
):
    """
    Accepts OriginalRecordTransfer
    Returns decrypted blob with correct mimetype
    """
    _raise_if_missing_acorn(acorn_obj)
    print(f"fetch original blob {original_record}")

    blob_bytes: bytes = None
    mime_type = "image/jpeq"

    blob_bytes, mime_type = await acorn_obj.get_original_blob(
        original_record,
        blossom_xfer_server=settings.BLOSSOM_XFER_SERVER,
        blossom_home_server=settings.BLOSSOM_HOME_SERVER,
    )

    if not blob_bytes:
        raise HTTPException(status_code=404, detail="Original record is not available")

    # raise HTTPException(status_code=404, detail="Blob not available")

    # 4️⃣ Return raw bytes
    return Response(
        content=blob_bytes,
        media_type=mime_type
    )
