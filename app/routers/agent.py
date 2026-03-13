import asyncio
import base64
import hashlib
import hmac
import io
import json
import logging
import secrets
import time
import urllib.parse
from collections import defaultdict, deque
from decimal import Decimal
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
import qrcode
from sqlmodel import Session, select
from sqlalchemy.exc import IntegrityError

from app.appmodels import PaymentQuote, RegisteredSafebox, sendRecordParms
from app.config import ConfigWithFallback, Settings
from app.db import engine
from app.rates import get_currency_rate, get_currency_rates
from app.routers import records as records_router
from app.tasks import handle_payment
from app.utils import (
    create_nembed_compressed,
    create_jwt_token,
    create_nauth,
    extract_leading_numbers,
    generate_nonce,
    generate_pnr,
    hex_to_npub,
    listen_for_request,
    parse_nauth,
    validate_local_part,
)
from monstr.encrypt import Keys
from safebox.monstrmore import ExtendedNIP44Encrypt
import oqs
from safebox.acorn import Acorn

router = APIRouter()
logger = logging.getLogger(__name__)
settings = Settings()
config = ConfigWithFallback()
_RATE_LIMIT_WINDOWS: dict[str, deque[float]] = defaultdict(deque)
_AGENT_OFFERS: dict[str, dict] = {}
_AGENT_OFFER_RECEIVE_INTENTS: dict[str, dict] = {}


class AgentInvoiceRequest(BaseModel):
    amount: int
    comment: str = "Please Pay!"


class AgentPayInvoiceRequest(BaseModel):
    invoice: str
    comment: str = "Paid by agent"
    tendered_amount: float | None = None
    tendered_currency: str = "SAT"


class AgentPayLightningAddressRequest(BaseModel):
    lightning_address: str
    amount_sats: int | None = None
    amount: float | None = None
    currency: str = "SAT"
    comment: str = "Paid by agent"
    tendered_amount: float | None = None
    tendered_currency: str | None = None


class AgentZapRequest(BaseModel):
    event: str | None = None
    event_id: str | None = None
    amount_sats: int | None = None
    amount: float | None = None
    currency: str = "SAT"
    comment: str = "⚡️"


class AgentPublishKind0Request(BaseModel):
    name: str | None = None
    about: str | None = None
    picture: str | None = None
    display_name: str | None = None
    nip05: str | None = None
    banner: str | None = None
    website: str | None = None
    lud16: str | None = None
    extra_fields: dict | None = None
    relays: list[str] | None = None


class AgentPublishKind1Request(BaseModel):
    content: str
    relays: list[str] | None = None


class AgentDeleteRequest(BaseModel):
    event_ids: list[str] | None = None
    a_tags: list[str] | None = None
    kinds: list[int] | None = None
    reason: str | None = None
    relays: list[str] | None = None


class AgentMarketOrderRequest(BaseModel):
    side: str
    asset: str
    price_sats: int
    quantity: str | int | float = "1"
    market: str = "safebox-v1"
    order_id: str | None = None
    content: str | None = None
    relays: list[str] | None = None
    flow: str | None = None


class AgentMS02ConstructAskRequest(BaseModel):
    wrapper_scheme: str = "nostr_keypair_v1"
    wrapper_ref: str
    price_sats: int
    expiry: str
    wrapper_commitment: str
    fulfillment_mode: str = "provider_resolved_v1"
    sealed_delivery_alg: str | None = None
    encrypted_entitlement: str | None = None
    instrument: str = "service_entitlement"
    quantity: int = 1
    redemption_provider: str | None = None
    provider_commitment: str | None = None
    settlement_method: str = "nip57_zap_v1"
    market: str = "MS-02"
    hash_alg: str = "sha256"
    content_format: str = "yaml"


class AgentMS02PublishAskRequest(BaseModel):
    content: str
    tags: list[list[str]] = []
    kind: int = 1
    relays: list[str] | None = None


class AgentMS02GenerateEntitlementRequest(BaseModel):
    entitlement_code: str | None = None
    entitlement_secret: str | None = None


class AgentMS02GenerateWrapperRequest(BaseModel):
    nsec: str | None = None


class AgentMS02DeriveWrapperCommitmentRequest(BaseModel):
    wrapper_scheme: str = "nostr_keypair_v1"
    nsec: str
    entitlement_code: str
    entitlement_secret: str
    hash_alg: str = "sha256"


class AgentDeriveTokenSecretHashRequest(BaseModel):
    spec_id: str = "MS01"
    token_id: str
    redemption_secret: str
    issuer_pubkey: str | None = None
    hash_alg: str = "sha256"


class AgentVerifyTokenSecretHashRequest(BaseModel):
    expected_hash: str
    spec_id: str = "MS01"
    token_id: str
    redemption_secret: str
    issuer_pubkey: str | None = None
    hash_alg: str = "sha256"


class AgentSetCustomHandleRequest(BaseModel):
    custom_handle: str


class AgentSecureDmRequest(BaseModel):
    recipient: str
    message: str
    relays: list[str] | None = None


class AgentReactRequest(BaseModel):
    event_id: str | None = None
    content: str = "❤️"
    reacted_pubkey: str | None = None
    reacted_kind: int | None = None
    relay_hint: str | None = None
    a_tag: str | None = None
    external_tags: list[list[str]] | None = None
    extra_tags: list[list[str]] | None = None
    relays: list[str] | None = None


class AgentReplyRequest(BaseModel):
    event_id: str
    content: str
    target_pubkey: str | None = None
    target_kind: int | None = None
    relay_hint: str | None = None
    extra_tags: list[list[str]] | None = None
    relays: list[str] | None = None


class AgentFollowRequest(BaseModel):
    identifier: str
    relay_hint: str | None = None
    relays: list[str] | None = None


class AgentUnfollowRequest(BaseModel):
    identifier: str
    relays: list[str] | None = None


class AgentFormatMentionRequest(BaseModel):
    identifier: str
    style: str = "nostr_uri"


class AgentComposeMentionsRequest(BaseModel):
    base_text: str | None = None
    identifiers: list[str]
    style: str = "nostr_uri"


class AgentIssueEcashRequest(BaseModel):
    amount: int
    comment: str = "ecash withdrawal"


class AgentAcceptEcashRequest(BaseModel):
    ecash_token: str
    comment: str = "ecash deposit"
    tendered_amount: float | None = None
    tendered_currency: str = "SAT"


class AgentOnboardRequest(BaseModel):
    invite_code: str


class AgentOfferCreateRequest(BaseModel):
    grant_kind: int
    grant_name: str
    compact: bool = True
    transmittal_kind: int | None = None


class AgentOfferReceiveCreateRequest(BaseModel):
    grant_kind: int | None = None
    grant_name: str | None = None
    ttl_seconds: int = 120
    compact_qr: bool = True
    include_ascii_qr: bool = False
    recipient_host: str | None = None
    # Backward-compatible alias for older clients.
    compact: bool | None = None


class AgentOfferCaptureRequest(BaseModel):
    recipient_nauth: str


class AgentOfferSendRequest(BaseModel):
    recipient_nauth: str | None = None


class AgentAsciiQrRequest(BaseModel):
    qr_text: str
    invert: bool = True


def _build_ascii_qr(qr_text: str, invert: bool = True) -> str:
    qr = qrcode.QRCode()
    qr.add_data(qr_text)
    qr.make(fit=True)
    out = io.StringIO()
    qr.print_ascii(out=out, invert=bool(invert))
    return out.getvalue()


def _resolve_wallet_by_access_key(access_key: str | None) -> RegisteredSafebox:
    key = (access_key or "").strip().lower()
    if not key:
        raise HTTPException(status_code=401, detail="Missing API key")

    with Session(engine) as session:
        wallet = session.exec(
            select(RegisteredSafebox).where(RegisteredSafebox.access_key == key)
        ).first()
        if wallet:
            return wallet

        # Compatibility for hyphenless keys.
        leading_num = extract_leading_numbers(key)
        if not leading_num:
            raise HTTPException(status_code=401, detail="Invalid API key")

        candidates = session.exec(
            select(RegisteredSafebox).where(RegisteredSafebox.access_key.startswith(leading_num))
        ).all()
        for candidate in candidates:
            if not candidate.access_key:
                continue
            parts = candidate.access_key.split("-")
            if len(parts) >= 3 and parts[1] in key and parts[2] in key:
                return candidate

    raise HTTPException(status_code=401, detail="Invalid API key")


def _extract_client_ip(request: Request) -> str:
    forwarded_for = (request.headers.get("x-forwarded-for") or "").strip()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    client = request.client.host if request.client else ""
    return client or "unknown"


def _extract_client_ip_websocket(websocket: WebSocket) -> str:
    client = websocket.client.host if websocket.client else ""
    return client or "unknown"


def _enforce_rate_limit(scope_key: str, rpm: int, burst: int) -> None:
    if not settings.AGENT_RATE_LIMIT_ENABLED:
        return

    now = time.monotonic()
    window_seconds = 60.0
    max_requests = max(1, int(rpm) + int(burst))
    q = _RATE_LIMIT_WINDOWS[f"agent:{scope_key}"]

    while q and (now - q[0]) > window_seconds:
        q.popleft()

    if len(q) >= max_requests:
        retry_after = max(1, int(window_seconds - (now - q[0])))
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(retry_after)},
        )

    q.append(now)


async def _agent_get_acorn(
    request: Request,
    x_access_key: str | None = Header(default=None),
) -> Acorn:
    ip = _extract_client_ip(request)
    limit_key = (x_access_key or "").strip().lower() or f"ip:{ip}"
    _enforce_rate_limit(limit_key, settings.AGENT_RPM, settings.AGENT_BURST)

    wallet = _resolve_wallet_by_access_key(x_access_key)
    if not wallet.nsec:
        raise HTTPException(status_code=500, detail="Wallet is missing nsec")

    acorn_obj = Acorn(
        nsec=wallet.nsec,
        home_relay=wallet.home_relay,
        public_relays=settings.PUBLIC_RELAYS,
    )
    try:
        await acorn_obj.load_data()
    except Exception as exc:
        logger.warning("Agent wallet load failed for handle=%s: %s", wallet.handle, exc)
        raise HTTPException(status_code=500, detail="Unable to load wallet state")
    return acorn_obj


async def _agent_get_acorn_websocket(websocket: WebSocket) -> Acorn:
    header_key = (websocket.headers.get("x-access-key") or "").strip()
    query_key = (websocket.query_params.get("access_key") or "").strip()
    access_key = header_key or query_key

    ip = _extract_client_ip_websocket(websocket)
    limit_key = access_key.lower() if access_key else f"ip:{ip}"
    _enforce_rate_limit(limit_key, settings.AGENT_RPM, settings.AGENT_BURST)

    wallet = _resolve_wallet_by_access_key(access_key)
    if not wallet.nsec:
        raise HTTPException(status_code=500, detail="Wallet is missing nsec")

    acorn_obj = Acorn(
        nsec=wallet.nsec,
        home_relay=wallet.home_relay,
        public_relays=settings.PUBLIC_RELAYS,
    )
    try:
        await acorn_obj.load_data()
    except Exception as exc:
        logger.warning("Agent websocket wallet load failed for handle=%s: %s", wallet.handle, exc)
        raise HTTPException(status_code=500, detail="Unable to load wallet state")
    return acorn_obj


def _persist_wallet_balance(acorn_obj: Acorn) -> None:
    with Session(engine) as session:
        wallet = session.exec(
            select(RegisteredSafebox).where(RegisteredSafebox.npub == acorn_obj.pubkey_bech32)
        ).first()
        if wallet:
            wallet.balance = acorn_obj.balance
            session.add(wallet)
            session.commit()


def _normalize_relays(raw_relays: list[str] | None) -> list[str]:
    relay_list: list[str] = []
    for each in raw_relays or []:
        value = str(each or "").strip()
        if not value:
            continue
        normalized = value if value.startswith("wss://") else f"wss://{value}"
        if normalized not in relay_list:
            relay_list.append(normalized)
    return relay_list


def _parse_relays_csv(relays: str | None) -> list[str] | None:
    relay_list: list[str] | None = None
    if relays:
        relay_list = []
        for each in relays.split(","):
            each = each.strip()
            if not each:
                continue
            relay_list.append(each if each.startswith("wss://") else f"wss://{each}")
        if not relay_list:
            relay_list = None
    return relay_list


async def _is_identifier_followed(
    acorn_obj: Acorn,
    identifier: str,
    relays: list[str] | None = None,
) -> bool:
    try:
        target_pubhex = acorn_obj._resolve_pubkey_identifier(identifier)
    except Exception:
        return False

    latest_contacts = await acorn_obj._get_latest_contacts_event(relays=relays)
    if not latest_contacts:
        return False

    for each_tag in list(latest_contacts.tags):
        if not each_tag or each_tag[0] != "p" or len(each_tag) < 2:
            continue
        each_pub = str(each_tag[1]).strip().lower()
        if each_pub == target_pubhex:
            return True
    return False


def _agent_default_dm_relays() -> list[str]:
    # Keep DM send/read defaults aligned to avoid split-brain inbox behavior.
    # Include home relay plus configured DM and public relay sets.
    return _normalize_relays([settings.HOME_RELAY] + list(settings.DM_RELAYS or []) + list(settings.PUBLIC_RELAYS or []))


async def _resolve_sats_from_request(amount_sats: int | None, amount: float | None, currency: str | None) -> tuple[int, bool, str]:
    converted_from_currency = False
    currency_code = (currency or "SAT").strip().upper()

    if amount_sats is not None:
        sat_amount = int(amount_sats)
    else:
        if amount is None:
            raise HTTPException(status_code=400, detail="Provide amount_sats or amount+currency")
        amount_value = Decimal(str(amount))
        if amount_value <= 0:
            raise HTTPException(status_code=400, detail="amount must be greater than zero")
        if currency_code == "SAT":
            sat_amount = int(amount_value)
        else:
            try:
                local_currency = await get_currency_rate(currency_code)
            except Exception as exc:
                raise HTTPException(
                    status_code=400,
                    detail=f"Unsupported or unavailable currency code: {currency_code}",
                ) from exc
            rate = Decimal(str(local_currency.currency_rate or 0))
            if rate <= 0:
                raise HTTPException(
                    status_code=400,
                    detail=f"Unsupported or unavailable currency code: {currency_code}",
                )
            sat_amount = int((amount_value * Decimal("100000000")) / rate)
            converted_from_currency = True

    if sat_amount <= 0:
        raise HTTPException(status_code=400, detail="Payment amount must be greater than zero")

    return sat_amount, converted_from_currency, currency_code


def _upsert_payment_quote(
    acorn_obj: Acorn,
    quote: str,
    amount: int,
    mint: str,
    paid: bool,
) -> None:
    with Session(engine) as session:
        existing = session.exec(select(PaymentQuote).where(PaymentQuote.quote == quote)).first()
        if existing:
            existing.nsec = acorn_obj.privkey_bech32
            existing.handle = acorn_obj.handle
            existing.amount = amount
            existing.mint = mint
            existing.paid = paid
            session.add(existing)
        else:
            session.add(
                PaymentQuote(
                    nsec=acorn_obj.privkey_bech32,
                    handle=acorn_obj.handle,
                    quote=quote,
                    amount=amount,
                    mint=mint,
                    paid=paid,
                )
            )
        session.commit()


def _set_payment_quote_paid(quote: str, paid: bool) -> None:
    with Session(engine) as session:
        payment_quote = session.exec(select(PaymentQuote).where(PaymentQuote.quote == quote)).first()
        if not payment_quote:
            return
        payment_quote.paid = paid
        session.add(payment_quote)
        session.commit()


async def _track_agent_invoice_payment(
    acorn_obj: Acorn,
    cli_quote,
    amount: int,
    comment: str,
) -> None:
    success = await handle_payment(
        acorn_obj=acorn_obj,
        cli_quote=cli_quote,
        amount=amount,
        tendered_amount=float(amount),
        tendered_currency="SAT",
        comment=comment,
        mint=settings.HOME_MINT,
    )
    _set_payment_quote_paid(cli_quote.quote, bool(success))


def _validate_invite_code(invite_code: str) -> str:
    code = (invite_code or "").strip().lower()
    if not code:
        raise HTTPException(status_code=400, detail="Missing invite code")
    if code not in settings.INVITE_CODES:
        raise HTTPException(status_code=403, detail="Invalid invite code")
    return code


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


def _resolve_offer_for_wallet(offer_id: str, acorn_obj: Acorn) -> dict:
    offer = _AGENT_OFFERS.get(offer_id)
    if not offer:
        raise HTTPException(status_code=404, detail="Offer not found")
    if offer.get("owner_npub") != acorn_obj.pubkey_bech32:
        raise HTTPException(status_code=403, detail="Offer does not belong to this wallet")
    return offer


def _offer_status_payload(offer: dict) -> dict:
    return {
        "offer_id": offer["offer_id"],
        "status": offer["status"],
        "grant_kind": offer["grant_kind"],
        "grant_name": offer["grant_name"],
        "nauth": offer["nauth"],
        "recipient_nauth": offer.get("recipient_nauth"),
        "delivery_status": offer.get("delivery_status", "PENDING"),
        "dispatch_detail": offer.get("dispatch_detail"),
        "last_error": offer.get("last_error"),
        "dispatched_at": offer.get("dispatched_at"),
        "created_at": offer["created_at"],
        "updated_at": offer["updated_at"],
    }


def _resolve_receive_intent_for_wallet(intent_id: str, acorn_obj: Acorn) -> dict:
    intent = _AGENT_OFFER_RECEIVE_INTENTS.get(intent_id)
    if intent and intent.get("owner_npub") != acorn_obj.pubkey_bech32:
        raise HTTPException(status_code=403, detail="Receive intent does not belong to this wallet")
    if not intent:
        decoded_intent = _decode_receive_intent_token(intent_id)
        if not decoded_intent:
            raise HTTPException(status_code=404, detail="Receive intent not found")
        if decoded_intent.get("owner_npub") != acorn_obj.pubkey_bech32:
            raise HTTPException(status_code=403, detail="Receive intent does not belong to this wallet")
        intent = decoded_intent
    return intent


def _record_has_original_artifact(record: dict) -> bool:
    if not isinstance(record, dict):
        return False
    payload = record.get("payload")
    if isinstance(payload, dict):
        if payload.get("original_record") is not None:
            return True
        if payload.get("pqc_encrypted_original") is not None:
            return True
    return any(record.get(key) is not None for key in ("original_record", "pqc_encrypted_original", "origsha256", "blobref", "blobsha256"))


def _grant_kind_values() -> list[int]:
    kinds: list[int] = []
    for each in list(settings.GRANT_KINDS or []):
        try:
            kind_value = int(each[0]) if isinstance(each, (list, tuple)) else int(each)
        except Exception:
            continue
        if kind_value not in kinds:
            kinds.append(kind_value)
    return kinds


def _external_scheme(request: Request) -> str:
    forwarded_proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
    if forwarded_proto in {"http", "https"}:
        return forwarded_proto
    host = (request.url.hostname or "").strip().lower()
    if host in {"localhost", "127.0.0.1"}:
        return "http"
    return "https"


def _intent_signing_key() -> bytes:
    secret = (
        str(getattr(config, "SERVICE_NSEC", "") or "").strip()
        or str(settings.SERVICE_SECRET_KEY or "").strip()
        or "safebox-dev-intent-key"
    )
    return secret.encode("utf-8")


def _encode_receive_intent_token(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    body = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    sig = hmac.new(_intent_signing_key(), body.encode("ascii"), hashlib.sha256).hexdigest()
    return f"rxi_{body}.{sig}"


def _decode_receive_intent_token(token: str) -> dict | None:
    value = str(token or "").strip()
    if not value.startswith("rxi_") or "." not in value:
        return None
    body_part, sig_part = value[4:].rsplit(".", 1)
    expected_sig = hmac.new(_intent_signing_key(), body_part.encode("ascii"), hashlib.sha256).hexdigest()
    if not secrets.compare_digest(expected_sig, sig_part):
        return None
    padded = body_part + ("=" * (-len(body_part) % 4))
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        obj = json.loads(decoded.decode("utf-8"))
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    try:
        expires_at = int(obj.get("expires_at") or 0)
    except Exception:
        expires_at = 0
    now_ts = int(datetime.utcnow().timestamp())
    if expires_at <= 0 or now_ts > expires_at + 5:
        return None
    obj.setdefault("intent_id", value)
    obj.setdefault("status", "WAITING_SEND")
    obj.setdefault("updated_at", now_ts)
    return obj


def _resolve_offer_kind_for_grant(grant_kind: int | None) -> int | None:
    if grant_kind is None:
        return None
    grant_label = None
    for each in list(settings.GRANT_KINDS or []):
        if not isinstance(each, (list, tuple)) or len(each) < 2:
            continue
        try:
            if int(each[0]) == int(grant_kind):
                grant_label = str(each[1])
                break
        except Exception:
            continue
    if not grant_label:
        return None

    for each in list(settings.OFFER_KINDS or []):
        if not isinstance(each, (list, tuple)) or len(each) < 2:
            continue
        try:
            if str(each[1]) == grant_label:
                return int(each[0])
        except Exception:
            continue
    return None


def _grant_summary_row(record: dict, grant_kind: int) -> dict:
    return {
        "grant_kind": grant_kind,
        "id": record.get("id"),
        "event_id": record.get("id"),
        "tag": (record.get("tag") or [None])[0] if isinstance(record.get("tag"), list) else record.get("tag"),
        "type": record.get("type"),
        "content": record.get("content"),
        "created_at": record.get("created_at"),
        "timestamp": record.get("timestamp"),
        "presenter": record.get("presenter"),
        "sender": record.get("sender"),
        "has_original_record": _record_has_original_artifact(record),
    }


async def _ingest_offer_transmittals(
    acorn_obj: Acorn,
    transmittal_kind: int,
    transmittal_relays: list[str] | None,
    since_ts: int,
    seen_transmittal_ids: set[str],
    expected_presenter_hex: str | None = None,
) -> list[dict]:
    """Consume 21062-like transmittal records and persist them as local grant records."""
    ingested_rows: list[dict] = []
    print(f"listening for request on {transmittal_kind}")
    try:
        incoming_records = await acorn_obj.get_user_records(
            record_kind=transmittal_kind,
            since=since_ts,
            relays=transmittal_relays,
            reverse=True,
        )
    except Exception as exc:
        logger.warning("Agent transmittal poll failed kind=%s error=%s", transmittal_kind, exc)
        print("listen for request []")
        return ingested_rows
    if not incoming_records and since_ts is not None:
        # Relay/index clock skew can hide same-flow events behind strict `since`.
        # Fall back to full query and filter client-side.
        try:
            incoming_records = await acorn_obj.get_user_records(
                record_kind=transmittal_kind,
                since=None,
                relays=transmittal_relays,
                reverse=True,
            )
        except Exception:
            incoming_records = []
    print(f"listen for request {incoming_records}")

    for each in incoming_records:
        event_id = str(each.get("id") or "").strip()
        if event_id and event_id in seen_transmittal_ids:
            print(f"agent transmittal skip_seen_id id={event_id}")
            continue

        try:
            record_ts = int(each.get("timestamp") or 0)
        except Exception:
            record_ts = 0
        if since_ts is not None and record_ts and record_ts < int(since_ts):
            print(f"agent transmittal skip_old id={event_id} ts={record_ts} since={since_ts}")
            continue

        if expected_presenter_hex:
            expected_norm = str(expected_presenter_hex).strip().lower()
            sender_norm = str(each.get("sender") or "").strip().lower()
            presenter_norm = str(each.get("presenter") or "").strip().lower()
            if sender_norm != expected_norm and presenter_norm != expected_norm:
                print(
                    f"agent transmittal skip_presenter_mismatch id={event_id} sender={sender_norm[:8]} presenter={presenter_norm[:8]}"
                )
                continue

        payload_value = each.get("payload")
        decrypted_original = None

        record_ciphertext = each.get("ciphertext")
        record_kemalg = each.get("kemalg")
        if record_ciphertext and record_kemalg:
            try:
                pqc = oqs.KeyEncapsulation(record_kemalg, bytes.fromhex(config.PQC_KEM_SECRET_KEY))
                kem_shared_secret = pqc.decap_secret(bytes.fromhex(record_ciphertext))
                print(f"This is the shared secret: {kem_shared_secret.hex()}")
                k_pqc = Keys(priv_k=kem_shared_secret.hex())
                my_enc = ExtendedNIP44Encrypt(k_pqc)
                encrypted_payload = each.get("pqc_encrypted_payload")
                encrypted_original = each.get("pqc_encrypted_original")
                if encrypted_payload:
                    payload_value = my_enc.decrypt(payload=encrypted_payload, for_pub_k=k_pqc.public_key_hex())
                    try:
                        print(f"decrypted payload to put in content: {payload_value} compare to content: {each.get('payload')}")
                    except Exception:
                        pass
                if encrypted_original:
                    print("there is an original record in the presentation!")
                    decrypted_original = my_enc.decrypt(payload=encrypted_original, for_pub_k=k_pqc.public_key_hex())
                    print(f"decrypted original for presentation: {decrypted_original}")
            except Exception as exc:
                logger.warning(
                    "Agent transmittal PQC decrypt skipped id=%s kind=%s: %s",
                    event_id,
                    each.get("type"),
                    exc,
                )
        print(f"parse record json: {each}")

        raw_tag = each.get("tag")
        if isinstance(raw_tag, list) and raw_tag:
            record_name = str(raw_tag[0])
        else:
            record_name = str(each.get("content") or "received-offer")

        try:
            record_kind = int(each.get("type") or each.get("kind") or transmittal_kind)
        except Exception:
            record_kind = transmittal_kind

        record_value = payload_value
        if not isinstance(record_value, str):
            record_value = json.dumps(record_value)

        record_origin = each.get("presenter") or each.get("sender")
        try:
            if isinstance(record_origin, str) and len(record_origin) == 64:
                record_origin = hex_to_npub(record_origin)
        except Exception:
            pass

        try:
            await acorn_obj.put_record(
                record_name=record_name,
                record_value=record_value,
                record_kind=record_kind,
                record_origin=record_origin,
            )
            if event_id:
                seen_transmittal_ids.add(event_id)
            print(f"agent transmittal persist_ok id={event_id} name={record_name} kind={record_kind}")
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
                        "Agent transmittal transfer_blob non-fatal status record=%s kind=%s status=%s reason=%s",
                        record_name,
                        record_kind,
                        blob_result.get("status"),
                        blob_result.get("reason"),
                    )
            print(
                f"agent transmittal ingest_complete id={event_id} name={record_name} kind={record_kind} "
                f"blob_status={blob_result.get('status') if decrypted_original else 'SKIPPED'}"
            )
        except Exception as exc:
            logger.warning("Agent transmittal persist failed record=%s kind=%s: %s", record_name, record_kind, exc)
            print(f"agent transmittal persist_failed id={event_id} name={record_name} kind={record_kind} err={exc}")
            continue

        ingested_rows.append(
            {
                "grant_kind": record_kind,
                "id": event_id or None,
                "event_id": event_id or None,
                "tag": record_name,
                "type": str(record_kind),
                "content": each.get("content"),
                "created_at": each.get("created_at"),
                "timestamp": each.get("timestamp"),
                "presenter": each.get("presenter"),
                "sender": each.get("sender"),
                "has_original_record": bool(decrypted_original or each.get("pqc_encrypted_original")),
            }
        )
        print("incoming record  successful!")

    return ingested_rows


@router.get("/info", tags=["agent"])
async def agent_info(
    request: Request,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
    x_access_key: str | None = Header(default=None),
):
    lightning_local = acorn_obj.handle
    try:
        wallet = _resolve_wallet_by_access_key(x_access_key)
        if wallet.custom_handle:
            lightning_local = wallet.custom_handle
    except HTTPException:
        # If access-key re-resolution fails here, continue with loaded wallet handle.
        pass

    host = request.url.hostname or ""
    lightning_address = f"{lightning_local}@{host}" if host else lightning_local

    return {
        "status": "OK",
        "handle": acorn_obj.handle,
        "lightning_address": lightning_address,
        "npub": acorn_obj.pubkey_bech32,
        "balance": acorn_obj.balance,
        "home_relay": acorn_obj.home_relay,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.get("/balance", tags=["agent"])
async def agent_balance(acorn_obj: Acorn = Depends(_agent_get_acorn)):
    return {
        "status": "OK",
        "balance": acorn_obj.balance,
        "unit": "sat",
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.post("/set_custom_handle", tags=["agent"])
async def agent_set_custom_handle(
    payload: AgentSetCustomHandleRequest,
    request: Request,
    x_access_key: str | None = Header(default=None),
):
    candidate = (payload.custom_handle or "").strip().lower()
    if not candidate:
        raise HTTPException(status_code=400, detail="Missing custom_handle")
    if not validate_local_part(candidate):
        raise HTTPException(status_code=400, detail="Invalid custom_handle")

    wallet_ref = _resolve_wallet_by_access_key(x_access_key)
    try:
        with Session(engine) as session:
            wallet = session.exec(
                select(RegisteredSafebox).where(RegisteredSafebox.npub == wallet_ref.npub)
            ).first()
            if not wallet:
                raise HTTPException(status_code=404, detail="Wallet not found")
            wallet.custom_handle = candidate
            session.add(wallet)
            session.commit()
    except IntegrityError:
        raise HTTPException(status_code=409, detail="Custom handle already taken")
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Agent set_custom_handle failed")
        raise HTTPException(status_code=500, detail=f"Set custom handle failed: {exc}")

    host = request.url.hostname or ""
    lightning_address = f"{candidate}@{host}" if host else candidate
    return {
        "status": "OK",
        "custom_handle": candidate,
        "lightning_address": lightning_address,
        "detail": f"Custom handle set to {candidate}",
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.get("/tx_history", tags=["agent"])
async def agent_tx_history(
    limit: int = 50,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    max_limit = 500
    safe_limit = max(1, min(int(limit), max_limit))
    try:
        tx_history = await acorn_obj.get_tx_history()
    except Exception as exc:
        logger.exception("Agent tx_history failed")
        raise HTTPException(status_code=500, detail=f"Unable to read tx history: {exc}")

    # Return most recent entries first, bounded by limit.
    def _tx_sort_key(entry: dict) -> datetime:
        created = entry.get("create_time")
        if not created:
            return datetime.min
        try:
            return datetime.strptime(created, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return datetime.min

    tx_history_sorted = sorted(tx_history, key=_tx_sort_key, reverse=True)
    return {
        "status": "OK",
        "count": min(len(tx_history_sorted), safe_limit),
        "transactions": tx_history_sorted[:safe_limit],
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.get("/proof_safety_audit", tags=["agent"])
async def agent_proof_safety_audit(
    check_relay: bool = False,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    try:
        audit_report = await acorn_obj.proof_safety_audit(check_relay=check_relay)
    except Exception as exc:
        logger.exception("Agent proof_safety_audit failed")
        raise HTTPException(status_code=500, detail=f"Unable to run proof safety audit: {exc}")

    return {
        "status": "OK",
        "audit": audit_report,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.get("/supported_currencies", tags=["agent"])
async def agent_supported_currencies(acorn_obj: Acorn = Depends(_agent_get_acorn)):
    try:
        rates = await get_currency_rates()
    except Exception as exc:
        logger.exception("Agent supported_currencies failed")
        raise HTTPException(status_code=500, detail=f"Unable to read currency rates: {exc}")

    by_code = {str(each.currency_code).upper(): each for each in rates}
    currencies = []
    for code in settings.SUPPORTED_CURRENCIES:
        normalized = str(code).upper()
        rate_obj = by_code.get(normalized)
        currencies.append(
            {
                "currency_code": normalized,
                "currency_symbol": getattr(rate_obj, "currency_symbol", None),
                "currency_rate": getattr(rate_obj, "currency_rate", None),
                "fractional_unit": getattr(rate_obj, "fractional_unit", None),
                "number_to_base": getattr(rate_obj, "number_to_base", None),
                "refresh_time": (
                    int(rate_obj.refresh_time.timestamp())
                    if getattr(rate_obj, "refresh_time", None)
                    else None
                ),
                "available": rate_obj is not None and getattr(rate_obj, "currency_rate", None) is not None,
            }
        )

    return {
        "status": "OK",
        "currencies": currencies,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.get("/nostr/latest_kind1", tags=["agent"])
async def agent_latest_kind1_events(
    nip05: str,
    limit: int = 10,
    relays: str | None = None,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    nip05_value = (nip05 or "").strip()
    if not nip05_value or "@" not in nip05_value:
        raise HTTPException(status_code=400, detail="Invalid nip05 address")

    relay_list: list[str] | None = None
    if relays:
        relay_list = []
        for each in relays.split(","):
            each = each.strip()
            if not each:
                continue
            relay_list.append(each if each.startswith("wss://") else f"wss://{each}")
        if not relay_list:
            relay_list = None

    safe_limit = max(1, min(int(limit), 100))
    if not await _is_identifier_followed(
        acorn_obj=acorn_obj,
        identifier=nip05_value,
        relays=relay_list,
    ):
        raise HTTPException(
            status_code=403,
            detail="Identifier is not followed by this wallet",
        )

    try:
        events = await acorn_obj.get_latest_kind1_posts_by_nip05(
            nip05=nip05_value,
            limit=safe_limit,
            relays=relay_list,
        )
    except Exception as exc:
        logger.exception("Agent latest_kind1 query failed")
        raise HTTPException(status_code=400, detail=f"Latest kind1 query failed: {exc}")

    return {
        "status": "OK",
        "nip05": nip05_value,
        "count": len(events),
        "events": events,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.get("/nostr/discovery/latest_kind1", tags=["agent"])
async def agent_discovery_latest_kind1_events(
    nip05: str,
    limit: int = 10,
    relays: str | None = None,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    nip05_value = (nip05 or "").strip()
    if not nip05_value or "@" not in nip05_value:
        raise HTTPException(status_code=400, detail="Invalid nip05 address")

    relay_list = _parse_relays_csv(relays)
    safe_limit = max(1, min(int(limit), 100))

    try:
        events = await acorn_obj.get_latest_kind1_posts_by_nip05(
            nip05=nip05_value,
            limit=safe_limit,
            relays=relay_list,
        )
    except Exception as exc:
        logger.exception("Agent discovery latest_kind1 query failed")
        raise HTTPException(status_code=400, detail=f"Discovery latest kind1 query failed: {exc}")

    return {
        "status": "OK",
        "nip05": nip05_value,
        "scope": "discovery",
        "count": len(events),
        "events": events,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.get("/nostr/my_latest_kind1", tags=["agent"])
async def agent_my_latest_kind1_events(
    limit: int = 10,
    relays: str | None = None,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    relay_list: list[str] | None = None
    if relays:
        relay_list = []
        for each in relays.split(","):
            each = each.strip()
            if not each:
                continue
            relay_list.append(each if each.startswith("wss://") else f"wss://{each}")
        if not relay_list:
            relay_list = None

    safe_limit = max(1, min(int(limit), 100))
    try:
        events = await acorn_obj.get_latest_kind1_posts_by_author(
            pubhex=acorn_obj.pubkey_hex,
            limit=safe_limit,
            relays=relay_list,
        )
    except Exception as exc:
        logger.exception("Agent my_latest_kind1 query failed")
        raise HTTPException(status_code=400, detail=f"My latest kind1 query failed: {exc}")

    return {
        "status": "OK",
        "pubkey": acorn_obj.pubkey_hex,
        "count": len(events),
        "events": events,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.get("/nostr/zap_receipts", tags=["agent"])
async def agent_zap_receipts_for_event(
    event_id: str,
    limit: int = 100,
    strict: bool = False,
    relays: str | None = None,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    event_value = (event_id or "").strip()
    if not event_value:
        raise HTTPException(status_code=400, detail="Missing event_id")

    relay_list: list[str] | None = None
    if relays:
        relay_list = []
        for each in relays.split(","):
            each = each.strip()
            if not each:
                continue
            relay_list.append(each if each.startswith("wss://") else f"wss://{each}")
        if not relay_list:
            relay_list = None

    safe_limit = max(1, min(int(limit), 200))
    try:
        receipts = await acorn_obj.get_zap_receipts_for_event(
            event_id=event_value,
            limit=safe_limit,
            relays=relay_list,
            strict=bool(strict),
        )
    except Exception as exc:
        logger.exception("Agent zap_receipts query failed")
        raise HTTPException(status_code=400, detail=f"Zap receipts query failed: {exc}")

    return {
        "status": "OK",
        "event_id": event_value,
        "strict": bool(strict),
        "count": len(receipts),
        "receipts": receipts,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.get("/nostr/replies", tags=["agent"])
async def agent_replies_for_event(
    event_id: str,
    limit: int = 100,
    relays: str | None = None,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    event_value = (event_id or "").strip()
    if not event_value:
        raise HTTPException(status_code=400, detail="Missing event_id")

    relay_list: list[str] | None = None
    if relays:
        relay_list = []
        for each in relays.split(","):
            each = each.strip()
            if not each:
                continue
            relay_list.append(each if each.startswith("wss://") else f"wss://{each}")
        if not relay_list:
            relay_list = None

    safe_limit = max(1, min(int(limit), 200))
    try:
        replies = await acorn_obj.get_replies_for_event(
            event_id=event_value,
            limit=safe_limit,
            relays=relay_list,
        )
    except Exception as exc:
        logger.exception("Agent replies query failed")
        raise HTTPException(status_code=400, detail=f"Replies query failed: {exc}")

    return {
        "status": "OK",
        "event_id": event_value,
        "count": len(replies),
        "replies": replies,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.get("/nostr/following/latest_kind1", tags=["agent"])
async def agent_latest_kind1_from_following(
    limit: int = 20,
    relays: str | None = None,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    relay_list: list[str] | None = None
    if relays:
        relay_list = []
        for each in relays.split(","):
            each = each.strip()
            if not each:
                continue
            relay_list.append(each if each.startswith("wss://") else f"wss://{each}")
        if not relay_list:
            relay_list = None

    safe_limit = max(1, min(int(limit), 200))
    try:
        events = await acorn_obj.get_latest_kind1_posts_from_follow_list(
            limit=safe_limit,
            relays=relay_list,
        )
    except Exception as exc:
        logger.exception("Agent latest_kind1_from_following query failed")
        raise HTTPException(status_code=400, detail=f"Latest kind1 following query failed: {exc}")

    return {
        "status": "OK",
        "count": len(events),
        "events": events,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.get("/nostr/followers", tags=["agent"])
async def agent_followers(
    identifier: str | None = None,
    limit: int = 100,
    strict: bool = True,
    relays: str | None = None,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    relay_list = _parse_relays_csv(relays)
    safe_limit = max(1, min(int(limit), 500))
    target_identifier = (identifier or "").strip()

    try:
        followers = await acorn_obj.get_followers_for_identifier(
            identifier=target_identifier or None,
            limit=safe_limit,
            relays=relay_list,
            strict=bool(strict),
        )
    except Exception as exc:
        logger.exception("Agent followers query failed")
        raise HTTPException(status_code=400, detail=f"Followers query failed: {exc}")

    target_pubkey = (
        acorn_obj._resolve_pubkey_identifier(target_identifier)
        if target_identifier
        else acorn_obj.pubkey_hex
    )

    return {
        "status": "OK",
        "target_identifier": target_identifier or hex_to_npub(acorn_obj.pubkey_hex),
        "target_pubkey": target_pubkey,
        "strict": bool(strict),
        "count": len(followers),
        "followers": followers,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


async def _agent_stream_kind1_events(
    websocket: WebSocket,
    fetch_events,
    poll_seconds: float,
    context: dict | None = None,
):
    # Emit updates only when the top event ids change to limit duplicate payloads.
    last_event_ids: list[str] | None = None
    poll_interval = max(1.0, min(float(poll_seconds), 60.0))
    base_context = context or {}

    await websocket.send_json(
        {
            "status": "OK",
            "type": "connected",
            "poll_seconds": poll_interval,
            **base_context,
            "timestamp": int(datetime.utcnow().timestamp()),
        }
    )

    while True:
        try:
            events = await fetch_events()
            current_event_ids = [str(each.get("event_id") or each.get("id") or "") for each in events]
            if current_event_ids != last_event_ids:
                await websocket.send_json(
                    {
                        "status": "OK",
                        "type": "events",
                        "count": len(events),
                        "events": events,
                        **base_context,
                        "timestamp": int(datetime.utcnow().timestamp()),
                    }
                )
                last_event_ids = current_event_ids
            else:
                await websocket.send_json(
                    {
                        "status": "OK",
                        "type": "heartbeat",
                        "count": len(events),
                        **base_context,
                        "timestamp": int(datetime.utcnow().timestamp()),
                    }
                )
            await asyncio.sleep(poll_interval)
        except WebSocketDisconnect:
            return
        except Exception as exc:
            logger.exception("Agent websocket stream failed")
            await websocket.send_json(
                {
                    "status": "ERROR",
                    "detail": f"Stream error: {exc}",
                    **base_context,
                    "timestamp": int(datetime.utcnow().timestamp()),
                }
            )
            await asyncio.sleep(poll_interval)


async def _agent_stream_dm_messages(
    websocket: WebSocket,
    fetch_messages,
    poll_seconds: float,
    context: dict | None = None,
):
    # Emit updates only when the most-recent message ids/timestamps change.
    last_message_keys: list[str] | None = None
    poll_interval = max(1.0, min(float(poll_seconds), 60.0))
    base_context = context or {}

    await websocket.send_json(
        {
            "status": "OK",
            "type": "connected",
            "poll_seconds": poll_interval,
            **base_context,
            "timestamp": int(datetime.utcnow().timestamp()),
        }
    )

    while True:
        try:
            messages = await fetch_messages()
            current_keys = [
                str(each.get("id") or each.get("timestamp") or each.get("created_at") or "")
                for each in messages
            ]
            if current_keys != last_message_keys:
                await websocket.send_json(
                    {
                        "status": "OK",
                        "type": "messages",
                        "count": len(messages),
                        "messages": messages,
                        **base_context,
                        "timestamp": int(datetime.utcnow().timestamp()),
                    }
                )
                last_message_keys = current_keys
            else:
                await websocket.send_json(
                    {
                        "status": "OK",
                        "type": "heartbeat",
                        "count": len(messages),
                        **base_context,
                        "timestamp": int(datetime.utcnow().timestamp()),
                    }
                )
            await asyncio.sleep(poll_interval)
        except WebSocketDisconnect:
            return
        except Exception as exc:
            logger.exception("Agent websocket DM stream failed")
            await websocket.send_json(
                {
                    "status": "ERROR",
                    "detail": f"DM stream error: {exc}",
                    **base_context,
                    "timestamp": int(datetime.utcnow().timestamp()),
                }
            )
            await asyncio.sleep(poll_interval)


@router.websocket("/ws/nostr/latest_kind1")
async def agent_ws_latest_kind1_events(
    websocket: WebSocket,
    nip05: str,
    limit: int = 10,
    relays: str | None = None,
    poll_seconds: float = 5.0,
):
    await websocket.accept()
    try:
        acorn_obj = await _agent_get_acorn_websocket(websocket)
    except HTTPException as exc:
        await websocket.send_json({"status": "ERROR", "detail": exc.detail})
        await websocket.close(code=4401 if exc.status_code == 401 else 1011)
        return

    nip05_value = (nip05 or "").strip()
    if not nip05_value or "@" not in nip05_value:
        await websocket.send_json({"status": "ERROR", "detail": "Invalid nip05 address"})
        await websocket.close(code=1008)
        return

    relay_list = _parse_relays_csv(relays)
    safe_limit = max(1, min(int(limit), 100))
    if not await _is_identifier_followed(
        acorn_obj=acorn_obj,
        identifier=nip05_value,
        relays=relay_list,
    ):
        await websocket.send_json(
            {
                "status": "ERROR",
                "detail": "Identifier is not followed by this wallet",
            }
        )
        await websocket.close(code=1008)
        return

    async def _fetch():
        return await acorn_obj.get_latest_kind1_posts_by_nip05(
            nip05=nip05_value,
            limit=safe_limit,
            relays=relay_list,
        )

    await _agent_stream_kind1_events(
        websocket=websocket,
        fetch_events=_fetch,
        poll_seconds=poll_seconds,
        context={"nip05": nip05_value},
    )


@router.websocket("/ws/nostr/discovery/latest_kind1")
async def agent_ws_discovery_latest_kind1_events(
    websocket: WebSocket,
    nip05: str,
    limit: int = 10,
    relays: str | None = None,
    poll_seconds: float = 5.0,
):
    await websocket.accept()
    try:
        acorn_obj = await _agent_get_acorn_websocket(websocket)
    except HTTPException as exc:
        await websocket.send_json({"status": "ERROR", "detail": exc.detail})
        await websocket.close(code=4401 if exc.status_code == 401 else 1011)
        return

    nip05_value = (nip05 or "").strip()
    if not nip05_value or "@" not in nip05_value:
        await websocket.send_json({"status": "ERROR", "detail": "Invalid nip05 address"})
        await websocket.close(code=1008)
        return

    relay_list = _parse_relays_csv(relays)
    safe_limit = max(1, min(int(limit), 100))

    async def _fetch():
        return await acorn_obj.get_latest_kind1_posts_by_nip05(
            nip05=nip05_value,
            limit=safe_limit,
            relays=relay_list,
        )

    await _agent_stream_kind1_events(
        websocket=websocket,
        fetch_events=_fetch,
        poll_seconds=poll_seconds,
        context={"nip05": nip05_value, "scope": "discovery"},
    )


@router.websocket("/ws/nostr/my_latest_kind1")
async def agent_ws_my_latest_kind1_events(
    websocket: WebSocket,
    limit: int = 10,
    relays: str | None = None,
    poll_seconds: float = 5.0,
):
    await websocket.accept()
    try:
        acorn_obj = await _agent_get_acorn_websocket(websocket)
    except HTTPException as exc:
        await websocket.send_json({"status": "ERROR", "detail": exc.detail})
        await websocket.close(code=4401 if exc.status_code == 401 else 1011)
        return

    relay_list = _parse_relays_csv(relays)
    safe_limit = max(1, min(int(limit), 100))

    async def _fetch():
        return await acorn_obj.get_latest_kind1_posts_by_author(
            pubhex=acorn_obj.pubkey_hex,
            limit=safe_limit,
            relays=relay_list,
        )

    await _agent_stream_kind1_events(
        websocket=websocket,
        fetch_events=_fetch,
        poll_seconds=poll_seconds,
        context={"pubkey": acorn_obj.pubkey_hex},
    )


@router.websocket("/ws/nostr/following/latest_kind1")
async def agent_ws_latest_kind1_from_following(
    websocket: WebSocket,
    limit: int = 20,
    relays: str | None = None,
    poll_seconds: float = 5.0,
):
    await websocket.accept()
    try:
        acorn_obj = await _agent_get_acorn_websocket(websocket)
    except HTTPException as exc:
        await websocket.send_json({"status": "ERROR", "detail": exc.detail})
        await websocket.close(code=4401 if exc.status_code == 401 else 1011)
        return

    relay_list = _parse_relays_csv(relays)
    safe_limit = max(1, min(int(limit), 200))

    async def _fetch():
        return await acorn_obj.get_latest_kind1_posts_from_follow_list(
            limit=safe_limit,
            relays=relay_list,
        )

    await _agent_stream_kind1_events(
        websocket=websocket,
        fetch_events=_fetch,
        poll_seconds=poll_seconds,
    )


@router.websocket("/ws/read_dms")
async def agent_ws_read_dms(
    websocket: WebSocket,
    limit: int = 50,
    kind: int = 1059,
    relays: str | None = None,
    poll_seconds: float = 5.0,
):
    await websocket.accept()
    try:
        acorn_obj = await _agent_get_acorn_websocket(websocket)
    except HTTPException as exc:
        await websocket.send_json({"status": "ERROR", "detail": exc.detail})
        await websocket.close(code=4401 if exc.status_code == 401 else 1011)
        return

    safe_limit = max(1, min(int(limit), 200))
    if kind <= 0:
        await websocket.send_json({"status": "ERROR", "detail": "Invalid kind"})
        await websocket.close(code=1008)
        return

    relay_list = _parse_relays_csv(relays)
    effective_relays = relay_list if relay_list is not None else _agent_default_dm_relays()

    async def _fetch():
        messages = await acorn_obj.get_user_records(
            record_kind=kind,
            relays=effective_relays,
            reverse=True,
        )
        return messages[:safe_limit]

    await _agent_stream_dm_messages(
        websocket=websocket,
        fetch_messages=_fetch,
        poll_seconds=poll_seconds,
        context={"kind": kind},
    )


@router.websocket("/ws/offers/receive/{intent_id}")
async def agent_ws_receive_offer(
    websocket: WebSocket,
    intent_id: str,
    timeout_seconds: int = 120,
    poll_seconds: float = 2.0,
    relays: str | None = None,
):
    await websocket.accept()
    try:
        acorn_obj = await _agent_get_acorn_websocket(websocket)
    except HTTPException as exc:
        await websocket.send_json({"status": "ERROR", "detail": exc.detail})
        await websocket.close(code=4401 if exc.status_code == 401 else 1011)
        return

    try:
        intent = _resolve_receive_intent_for_wallet(intent_id=intent_id, acorn_obj=acorn_obj)
    except HTTPException as exc:
        await websocket.send_json({"status": "ERROR", "detail": exc.detail, "intent_id": intent_id})
        await websocket.close(code=4403 if exc.status_code == 403 else 1011)
        return

    safe_timeout = max(5, min(int(timeout_seconds), 600))
    poll_interval = max(0.5, min(float(poll_seconds), 5.0))
    relay_list = _parse_relays_csv(relays)

    now_ts = int(datetime.utcnow().timestamp())
    expires_at = int(intent.get("expires_at") or now_ts)
    if now_ts >= expires_at:
        intent["status"] = "EXPIRED"
        intent["updated_at"] = now_ts
        await websocket.send_json(
            {
                "status": "TIMEOUT",
                "type": "timeout",
                "detail": "Receive intent already expired",
                "intent": {
                    "intent_id": intent["intent_id"],
                    "status": intent["status"],
                    "expires_at": intent["expires_at"],
                    "updated_at": intent["updated_at"],
                },
                "timestamp": now_ts,
            }
        )
        await websocket.close(code=1000)
        return

    grant_kind = intent.get("grant_kind")
    if grant_kind is not None:
        grant_kinds = [int(grant_kind)]
    else:
        grant_kinds = _grant_kind_values()
        if not grant_kinds:
            await websocket.send_json({"status": "ERROR", "detail": "No configured grant kinds", "intent_id": intent_id})
            await websocket.close(code=1011)
            return

    since_ts = max(0, int(intent.get("created_at") or now_ts) - 5)
    auth_since_ts = max(0, int(intent.get("created_at") or now_ts) - 5)
    transmittal_since_ts = since_ts
    deadline = min(time.monotonic() + safe_timeout, time.monotonic() + max(1, expires_at - now_ts))
    handshake_complete = False
    expected_presenter_hex: str | None = None

    recipient_nauth = str(intent.get("recipient_nauth") or "").strip()
    if not recipient_nauth:
        await websocket.send_json({"status": "ERROR", "detail": "Receive intent missing recipient_nauth", "intent_id": intent_id})
        await websocket.close(code=1011)
        return
    parsed_intent_nauth = parse_nauth(recipient_nauth)
    expected_nonce = parsed_intent_nauth.get("values", {}).get("nonce")
    auth_kind = parsed_intent_nauth.get("values", {}).get("auth_kind", settings.AUTH_KIND)
    auth_relays = _normalize_relays(parsed_intent_nauth.get("values", {}).get("auth_relays") or settings.AUTH_RELAYS)
    transmittal_kind = int(parsed_intent_nauth.get("values", {}).get("transmittal_kind", settings.RECORD_TRANSMITTAL_KIND))
    transmittal_relays = _normalize_relays(
        parsed_intent_nauth.get("values", {}).get("transmittal_relays") or settings.RECORD_TRANSMITTAL_RELAYS
    )
    if relay_list is None:
        relay_list = transmittal_relays or _normalize_relays(settings.RECORD_TRANSMITTAL_RELAYS)
    seen_transmittal_ids: set[str] = set()

    await websocket.send_json(
        {
            "status": "OK",
            "type": "connected",
            "intent": {
                "intent_id": intent["intent_id"],
                "status": intent.get("status", "WAITING_SEND"),
                "grant_kind": intent.get("grant_kind"),
                "grant_name": intent.get("grant_name"),
                "expires_at": intent.get("expires_at"),
                "updated_at": intent.get("updated_at"),
            },
            "poll_seconds": poll_interval,
            "handshake_complete": handshake_complete,
            "timestamp": int(datetime.utcnow().timestamp()),
        }
    )

    while time.monotonic() < deadline:
        try:
            if not handshake_complete:
                candidate_nauth, _, _ = await listen_for_request(
                    acorn_obj=acorn_obj,
                    kind=auth_kind,
                    since_now=auth_since_ts,
                    relays=auth_relays,
                    expected_nonce=expected_nonce,
                )
                auth_since_ts = int(datetime.utcnow().timestamp()) - 1
                if candidate_nauth and isinstance(candidate_nauth, str):
                    try:
                        parsed_presenter = parse_nauth(candidate_nauth)
                        presenter_pubhex = parsed_presenter.get("values", {}).get("pubhex")
                        if not presenter_pubhex:
                            raise ValueError("Presenter pubhex missing")
                        presenter_npub = hex_to_npub(presenter_pubhex)
                        presenter_auth_kind = parsed_presenter.get("values", {}).get("auth_kind", settings.AUTH_KIND)
                        presenter_auth_relays = _normalize_relays(
                            parsed_presenter.get("values", {}).get("auth_relays") or settings.AUTH_RELAYS
                        )

                        kem_material = {
                            "kem_public_key": config.PQC_KEM_PUBLIC_KEY,
                            "kemalg": settings.PQC_KEMALG,
                        }
                        kem_nembed = create_nembed_compressed(kem_material)
                        response_message = f"{recipient_nauth}:{kem_nembed}"
                        await acorn_obj.secure_transmittal(
                            nrecipient=presenter_npub,
                            message=response_message,
                            kind=presenter_auth_kind,
                            dm_relays=presenter_auth_relays,
                        )
                        handshake_complete = True
                        expected_presenter_hex = str(presenter_pubhex or "").strip().lower() or None
                        # Only accept transmittals produced after handshake completion.
                        transmittal_since_ts = max(transmittal_since_ts, int(datetime.utcnow().timestamp()) - 2)
                        print(
                            f"agent ws handshake complete intent_id={intent_id} presenter={presenter_npub} auth_relays={presenter_auth_relays}"
                        )
                        logger.info(
                            "Agent websocket receive-offer handshake completed intent_id=%s presenter=%s",
                            intent_id,
                            presenter_npub,
                        )
                    except Exception as exc:
                        print(f"agent ws handshake failure intent_id={intent_id}: {exc}")
                        logger.exception("Agent websocket receive-offer handshake response failed intent_id=%s", intent_id)

            if handshake_complete:
                ingested_rows = await _ingest_offer_transmittals(
                    acorn_obj=acorn_obj,
                    transmittal_kind=transmittal_kind,
                    transmittal_relays=relay_list,
                    since_ts=transmittal_since_ts,
                    seen_transmittal_ids=seen_transmittal_ids,
                    expected_presenter_hex=expected_presenter_hex,
                )
                for grant_row in ingested_rows:
                    try:
                        ingested_kind = int(grant_row.get("grant_kind") or 0)
                    except Exception:
                        ingested_kind = 0
                    if ingested_kind not in grant_kinds:
                        continue
                    intent["status"] = "RECEIVED"
                    intent["received_event_id"] = grant_row.get("event_id")
                    intent["received_grant_kind"] = ingested_kind
                    intent["updated_at"] = int(datetime.utcnow().timestamp())
                    await websocket.send_json(
                        {
                            "status": "OK",
                            "type": "received",
                            "detail": "Grant received",
                            "intent": {
                                "intent_id": intent["intent_id"],
                                "status": intent["status"],
                                "grant_kind": intent.get("grant_kind"),
                                "grant_name": intent.get("grant_name"),
                                "expires_at": intent.get("expires_at"),
                                "updated_at": intent.get("updated_at"),
                                "received_event_id": intent.get("received_event_id"),
                                "received_grant_kind": intent.get("received_grant_kind"),
                            },
                            "grant": grant_row,
                            "timestamp": int(datetime.utcnow().timestamp()),
                        }
                    )
                    await websocket.close(code=1000)
                    return

            for each_kind in grant_kinds:
                records = await acorn_obj.get_user_records(
                    record_kind=each_kind,
                    relays=relay_list,
                    reverse=True,
                )
                for record in records:
                    try:
                        record_ts = int(record.get("timestamp") or 0)
                    except Exception:
                        record_ts = 0
                    if record_ts < since_ts:
                        continue

                    grant_row = _grant_summary_row(record=record, grant_kind=each_kind)
                    intent["status"] = "RECEIVED"
                    intent["received_event_id"] = grant_row.get("event_id")
                    intent["received_grant_kind"] = each_kind
                    intent["updated_at"] = int(datetime.utcnow().timestamp())

                    await websocket.send_json(
                        {
                            "status": "OK",
                            "type": "received",
                            "detail": "Grant received",
                            "intent": {
                                "intent_id": intent["intent_id"],
                                "status": intent["status"],
                                "grant_kind": intent.get("grant_kind"),
                                "grant_name": intent.get("grant_name"),
                                "expires_at": intent.get("expires_at"),
                                "updated_at": intent.get("updated_at"),
                                "received_event_id": intent.get("received_event_id"),
                                "received_grant_kind": intent.get("received_grant_kind"),
                            },
                            "grant": grant_row,
                            "timestamp": int(datetime.utcnow().timestamp()),
                        }
                    )
                    await websocket.close(code=1000)
                    return

            remaining = max(0, int(deadline - time.monotonic()))
            await websocket.send_json(
                {
                    "status": "OK",
                    "type": "heartbeat",
                    "intent_id": intent_id,
                    "handshake_complete": handshake_complete,
                    "remaining_seconds": remaining,
                    "timestamp": int(datetime.utcnow().timestamp()),
                }
            )
            await asyncio.sleep(poll_interval)
        except WebSocketDisconnect:
            return
        except Exception as exc:
            logger.exception("Agent websocket receive-offer stream failed intent_id=%s", intent_id)
            await websocket.send_json(
                {
                    "status": "ERROR",
                    "type": "error",
                    "detail": f"Receive stream error: {exc}",
                    "intent_id": intent_id,
                    "timestamp": int(datetime.utcnow().timestamp()),
                }
            )
            await asyncio.sleep(poll_interval)

    intent["status"] = "TIMEOUT"
    intent["updated_at"] = int(datetime.utcnow().timestamp())
    try:
        await websocket.send_json(
            {
                "status": "TIMEOUT",
                "type": "timeout",
                "detail": "No grant received before timeout",
                "intent": {
                    "intent_id": intent["intent_id"],
                    "status": intent["status"],
                    "grant_kind": intent.get("grant_kind"),
                    "grant_name": intent.get("grant_name"),
                    "expires_at": intent.get("expires_at"),
                    "updated_at": intent.get("updated_at"),
                },
                "timestamp": int(datetime.utcnow().timestamp()),
            }
        )
    except WebSocketDisconnect:
        logger.info("Agent websocket receive-offer disconnected before timeout send intent_id=%s", intent_id)
    finally:
        try:
            await websocket.close(code=1000)
        except Exception:
            pass


@router.get("/market/orders", tags=["agent"])
async def agent_market_orders(
    limit: int = 50,
    kind: int = 1,
    market: str = "safebox-v1",
    side: str | None = None,
    asset: str | None = None,
    relays: str | None = None,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    relay_list: list[str] | None = None
    if relays:
        relay_list = []
        for each in relays.split(","):
            each = each.strip()
            if not each:
                continue
            relay_list.append(each if each.startswith("wss://") else f"wss://{each}")
        if not relay_list:
            relay_list = None

    safe_limit = max(1, min(int(limit), 200))
    try:
        orders = await acorn_obj.get_market_orders_from_follow_list(
            limit=safe_limit,
            kind=int(kind),
            market=(market or "safebox-v1").strip(),
            side=side,
            asset=asset,
            relays=relay_list,
        )
    except Exception as exc:
        logger.exception("Agent market orders query failed")
        raise HTTPException(status_code=400, detail=f"Market orders query failed: {exc}")

    return {
        "status": "OK",
        "count": len(orders),
        "kind": int(kind),
        "market": (market or "safebox-v1").strip(),
        "side": side,
        "asset": asset,
        "orders": orders,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.post("/nostr/format_mention", tags=["agent"])
async def agent_format_mention(
    payload: AgentFormatMentionRequest,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    identifier = (payload.identifier or "").strip()
    if not identifier:
        raise HTTPException(status_code=400, detail="Missing identifier")
    try:
        result = acorn_obj.format_mention(identifier=identifier, style=payload.style)
    except Exception as exc:
        logger.exception("Agent format_mention failed")
        raise HTTPException(status_code=400, detail=f"Mention formatting failed: {exc}")
    return {
        "status": "OK",
        "result": result,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.post("/nostr/compose_mentions", tags=["agent"])
async def agent_compose_mentions(
    payload: AgentComposeMentionsRequest,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    if not payload.identifiers:
        raise HTTPException(status_code=400, detail="identifiers must include at least one value")
    try:
        result = acorn_obj.compose_post_with_mentions(
            base_text=payload.base_text,
            identifiers=payload.identifiers,
            style=payload.style,
        )
    except Exception as exc:
        logger.exception("Agent compose_mentions failed")
        raise HTTPException(status_code=400, detail=f"Mention compose failed: {exc}")
    return {
        "status": "OK",
        "result": result,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.get("/nostr/kind0", tags=["agent"])
async def agent_kind0_profile(
    identifier: str,
    relays: str | None = None,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    identifier_value = (identifier or "").strip()
    if not identifier_value:
        raise HTTPException(status_code=400, detail="Missing identifier")

    relay_list: list[str] | None = None
    if relays:
        relay_list = []
        for each in relays.split(","):
            each = each.strip()
            if not each:
                continue
            relay_list.append(each if each.startswith("wss://") else f"wss://{each}")
        if not relay_list:
            relay_list = None

    try:
        profile_event = await acorn_obj.get_kind0_profile_by_identifier(
            identifier=identifier_value,
            relays=relay_list,
        )
    except Exception as exc:
        logger.exception("Agent kind0 lookup failed")
        raise HTTPException(status_code=400, detail=f"Kind0 lookup failed: {exc}")

    return {
        "status": "OK",
        "identifier": identifier_value,
        "profile_event": profile_event,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.get("/read_dms", tags=["agent"])
async def agent_read_dms(
    limit: int = 50,
    kind: int = 1059,
    relays: str | None = None,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    safe_limit = max(1, min(int(limit), 200))
    if kind <= 0:
        raise HTTPException(status_code=400, detail="Invalid kind")

    relay_list: list[str] | None = None
    if relays:
        relay_list = []
        for each in relays.split(","):
            each = each.strip()
            if not each:
                continue
            relay_list.append(each if each.startswith("wss://") else f"wss://{each}")
        if not relay_list:
            relay_list = None

    try:
        effective_relays = relay_list if relay_list is not None else _agent_default_dm_relays()
        messages = await acorn_obj.get_user_records(
            record_kind=kind,
            relays=effective_relays,
            reverse=True,
        )
    except Exception as exc:
        logger.exception("Agent read_dms failed")
        raise HTTPException(status_code=400, detail=f"Read DMs failed: {exc}")

    return {
        "status": "OK",
        "kind": kind,
        "count": min(len(messages), safe_limit),
        "messages": messages[:safe_limit],
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.get("/grants", tags=["agent"])
async def agent_grants(
    grant_kind: int | None = None,
    limit: int = 100,
    relays: str | None = None,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    safe_limit = max(1, min(int(limit), 500))

    relay_list = _parse_relays_csv(relays)

    if grant_kind is not None:
        if int(grant_kind) <= 0:
            raise HTTPException(status_code=400, detail="Invalid grant_kind")
        grant_kinds = [int(grant_kind)]
    else:
        grant_kinds = _grant_kind_values()
        if not grant_kinds:
            raise HTTPException(status_code=500, detail="No configured grant kinds")

    records_by_kind: dict[int, list[dict]] = {}
    combined: list[dict] = []

    for each_kind in grant_kinds:
        try:
            records = await acorn_obj.get_user_records(
                record_kind=each_kind,
                relays=relay_list,
                reverse=True,
            )
        except Exception as exc:
            logger.exception("Agent grants query failed for kind=%s", each_kind)
            raise HTTPException(status_code=400, detail=f"Grant query failed for kind {each_kind}: {exc}")

        rows: list[dict] = []
        for record in records:
            row = _grant_summary_row(record=record, grant_kind=each_kind)
            rows.append(row)
            combined.append(row)

        if rows:
            records_by_kind[each_kind] = rows[:safe_limit]
        else:
            records_by_kind[each_kind] = []

    combined.sort(key=lambda r: int(r.get("timestamp") or 0), reverse=True)

    if grant_kind is not None:
        return {
            "status": "OK",
            "grant_kind": int(grant_kind),
            "count": min(len(records_by_kind[int(grant_kind)]), safe_limit),
            "grants": records_by_kind[int(grant_kind)][:safe_limit],
            "timestamp": int(datetime.utcnow().timestamp()),
        }

    return {
        "status": "OK",
        "grant_kinds": grant_kinds,
        "count": min(len(combined), safe_limit),
        "grants": combined[:safe_limit],
        "by_kind": records_by_kind,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.get("/offers/receive/{intent_id}/wait", tags=["agent"])
async def agent_wait_receive_offer(
    intent_id: str,
    timeout_seconds: int = 120,
    poll_seconds: float = 2.0,
    relays: str | None = None,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    intent = _resolve_receive_intent_for_wallet(intent_id=intent_id, acorn_obj=acorn_obj)

    safe_timeout = max(5, min(int(timeout_seconds), 600))
    safe_poll = max(0.5, min(float(poll_seconds), 5.0))
    relay_list = _parse_relays_csv(relays)

    now_ts = int(datetime.utcnow().timestamp())
    expires_at = int(intent.get("expires_at") or now_ts)
    if now_ts >= expires_at:
        intent["status"] = "EXPIRED"
        intent["updated_at"] = now_ts
        return {
            "status": "TIMEOUT",
            "detail": "Receive intent already expired",
            "intent": {
                "intent_id": intent["intent_id"],
                "status": intent["status"],
                "expires_at": intent["expires_at"],
                "updated_at": intent["updated_at"],
            },
            "timestamp": now_ts,
        }

    grant_kind = intent.get("grant_kind")
    if grant_kind is not None:
        grant_kinds = [int(grant_kind)]
    else:
        grant_kinds = _grant_kind_values()
        if not grant_kinds:
            raise HTTPException(status_code=500, detail="No configured grant kinds")

    listen_deadline = min(time.monotonic() + safe_timeout, time.monotonic() + max(1, expires_at - now_ts))
    since_ts = max(0, int(intent.get("created_at") or now_ts) - 5)
    auth_since_ts = max(0, int(intent.get("created_at") or now_ts) - 5)
    transmittal_since_ts = since_ts
    handshake_complete = False
    expected_presenter_hex: str | None = None

    recipient_nauth = str(intent.get("recipient_nauth") or "").strip()
    if not recipient_nauth:
        raise HTTPException(status_code=500, detail="Receive intent missing recipient_nauth")
    parsed_intent_nauth = parse_nauth(recipient_nauth)
    expected_nonce = parsed_intent_nauth.get("values", {}).get("nonce")
    auth_kind = parsed_intent_nauth.get("values", {}).get("auth_kind", settings.AUTH_KIND)
    auth_relays = _normalize_relays(parsed_intent_nauth.get("values", {}).get("auth_relays") or settings.AUTH_RELAYS)
    transmittal_kind = int(parsed_intent_nauth.get("values", {}).get("transmittal_kind", settings.RECORD_TRANSMITTAL_KIND))
    transmittal_relays = _normalize_relays(
        parsed_intent_nauth.get("values", {}).get("transmittal_relays") or settings.RECORD_TRANSMITTAL_RELAYS
    )
    if relay_list is None:
        relay_list = transmittal_relays or _normalize_relays(settings.RECORD_TRANSMITTAL_RELAYS)
    seen_transmittal_ids: set[str] = set()

    while time.monotonic() < listen_deadline:
        if not handshake_complete:
            candidate_nauth, _, _ = await listen_for_request(
                acorn_obj=acorn_obj,
                kind=auth_kind,
                since_now=auth_since_ts,
                relays=auth_relays,
                expected_nonce=expected_nonce,
            )
            auth_since_ts = int(datetime.utcnow().timestamp()) - 1
            if candidate_nauth and isinstance(candidate_nauth, str):
                try:
                    parsed_presenter = parse_nauth(candidate_nauth)
                    presenter_pubhex = parsed_presenter.get("values", {}).get("pubhex")
                    if not presenter_pubhex:
                        raise ValueError("Presenter pubhex missing")
                    presenter_npub = hex_to_npub(presenter_pubhex)
                    presenter_auth_kind = parsed_presenter.get("values", {}).get("auth_kind", settings.AUTH_KIND)
                    presenter_auth_relays = _normalize_relays(
                        parsed_presenter.get("values", {}).get("auth_relays") or settings.AUTH_RELAYS
                    )

                    kem_material = {
                        "kem_public_key": config.PQC_KEM_PUBLIC_KEY,
                        "kemalg": settings.PQC_KEMALG,
                    }
                    kem_nembed = create_nembed_compressed(kem_material)
                    response_message = f"{recipient_nauth}:{kem_nembed}"
                    await acorn_obj.secure_transmittal(
                        nrecipient=presenter_npub,
                        message=response_message,
                        kind=presenter_auth_kind,
                        dm_relays=presenter_auth_relays,
                    )
                    handshake_complete = True
                    expected_presenter_hex = str(presenter_pubhex or "").strip().lower() or None
                    # Only accept transmittals produced after handshake completion.
                    transmittal_since_ts = max(transmittal_since_ts, int(datetime.utcnow().timestamp()) - 2)
                    print(
                        f"agent wait handshake complete intent_id={intent_id} presenter={presenter_npub} auth_relays={presenter_auth_relays}"
                    )
                    logger.info(
                        "Agent receive wait handshake completed intent_id=%s presenter=%s",
                        intent_id,
                        presenter_npub,
                    )
                except Exception as exc:
                    print(f"agent wait handshake failure intent_id={intent_id}: {exc}")
                    logger.exception("Agent receive wait handshake response failed intent_id=%s", intent_id)

        if handshake_complete:
            ingested_rows = await _ingest_offer_transmittals(
                acorn_obj=acorn_obj,
                transmittal_kind=transmittal_kind,
                transmittal_relays=relay_list,
                since_ts=transmittal_since_ts,
                seen_transmittal_ids=seen_transmittal_ids,
                expected_presenter_hex=expected_presenter_hex,
            )
            for grant_row in ingested_rows:
                try:
                    ingested_kind = int(grant_row.get("grant_kind") or 0)
                except Exception:
                    ingested_kind = 0
                if ingested_kind not in grant_kinds:
                    continue
                intent["status"] = "RECEIVED"
                intent["received_event_id"] = grant_row.get("event_id")
                intent["received_grant_kind"] = ingested_kind
                intent["updated_at"] = int(datetime.utcnow().timestamp())
                return {
                    "status": "OK",
                    "detail": "Grant received",
                    "handshake_complete": handshake_complete,
                    "intent": {
                        "intent_id": intent["intent_id"],
                        "status": intent["status"],
                        "grant_kind": intent.get("grant_kind"),
                        "grant_name": intent.get("grant_name"),
                        "expires_at": intent["expires_at"],
                        "updated_at": intent["updated_at"],
                        "received_event_id": intent.get("received_event_id"),
                        "received_grant_kind": intent.get("received_grant_kind"),
                    },
                    "grant": grant_row,
                    "timestamp": int(datetime.utcnow().timestamp()),
                }

        for each_kind in grant_kinds:
            try:
                records = await acorn_obj.get_user_records(
                    record_kind=each_kind,
                    relays=relay_list,
                    reverse=True,
                )
            except Exception as exc:
                logger.exception("Agent receive wait query failed for kind=%s intent=%s", each_kind, intent_id)
                raise HTTPException(status_code=400, detail=f"Receive wait query failed for kind {each_kind}: {exc}")

            for record in records:
                try:
                    record_ts = int(record.get("timestamp") or 0)
                except Exception:
                    record_ts = 0
                if record_ts < since_ts:
                    continue

                grant_row = _grant_summary_row(record=record, grant_kind=each_kind)
                intent["status"] = "RECEIVED"
                intent["received_event_id"] = grant_row.get("event_id")
                intent["received_grant_kind"] = each_kind
                intent["updated_at"] = int(datetime.utcnow().timestamp())
                return {
                    "status": "OK",
                    "detail": "Grant received",
                    "handshake_complete": handshake_complete,
                    "intent": {
                        "intent_id": intent["intent_id"],
                        "status": intent["status"],
                        "grant_kind": intent.get("grant_kind"),
                        "grant_name": intent.get("grant_name"),
                        "expires_at": intent["expires_at"],
                        "updated_at": intent["updated_at"],
                        "received_event_id": intent.get("received_event_id"),
                        "received_grant_kind": intent.get("received_grant_kind"),
                    },
                    "grant": grant_row,
                    "timestamp": int(datetime.utcnow().timestamp()),
                }

        await asyncio.sleep(safe_poll)

    intent["status"] = "TIMEOUT"
    intent["updated_at"] = int(datetime.utcnow().timestamp())
    return {
        "status": "TIMEOUT",
        "detail": "No grant received before timeout",
        "handshake_complete": handshake_complete,
        "intent": {
            "intent_id": intent["intent_id"],
            "status": intent["status"],
            "grant_kind": intent.get("grant_kind"),
            "grant_name": intent.get("grant_name"),
            "expires_at": intent["expires_at"],
            "updated_at": intent["updated_at"],
        },
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.post("/create_invoice", tags=["agent"])
async def agent_create_invoice(
    payload: AgentInvoiceRequest, acorn_obj: Acorn = Depends(_agent_get_acorn)
):
    if payload.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be greater than zero")

    try:
        cli_quote = await asyncio.to_thread(acorn_obj.deposit, amount=payload.amount, mint=settings.HOME_MINT)
    except Exception as exc:
        logger.exception("Agent create_invoice failed")
        raise HTTPException(status_code=500, detail=f"Unable to create invoice: {exc}")

    _upsert_payment_quote(
        acorn_obj=acorn_obj,
        quote=cli_quote.quote,
        amount=payload.amount,
        mint=settings.HOME_MINT,
        paid=False,
    )
    asyncio.create_task(
        _track_agent_invoice_payment(
            acorn_obj=acorn_obj,
            cli_quote=cli_quote,
            amount=payload.amount,
            comment=payload.comment,
        )
    )

    return {
        "status": "OK",
        "invoice": cli_quote.invoice,
        "quote": cli_quote.quote,
        "amount": payload.amount,
        "unit": "sat",
        "invoice_status": "PENDING",
        "status_path": f"/agent/invoice_status/{cli_quote.quote}",
    }


@router.get("/invoice_status/{quote}", tags=["agent"])
async def agent_invoice_status(quote: str, acorn_obj: Acorn = Depends(_agent_get_acorn)):
    with Session(engine) as session:
        payment_quote = session.exec(
            select(PaymentQuote).where(
                PaymentQuote.quote == quote,
                PaymentQuote.handle == acorn_obj.handle,
            )
        ).first()

    if not payment_quote:
        raise HTTPException(status_code=404, detail="Invoice quote not found")

    quote_status = "PAID" if payment_quote.paid else "PENDING"
    return {
        "status": "OK",
        "quote": payment_quote.quote,
        "quote_status": quote_status,
        "amount": payment_quote.amount,
        "mint": payment_quote.mint,
    }


@router.post("/pay_invoice", tags=["agent"])
async def agent_pay_invoice(
    payload: AgentPayInvoiceRequest, acorn_obj: Acorn = Depends(_agent_get_acorn)
):
    if not payload.invoice:
        raise HTTPException(status_code=400, detail="Missing invoice")

    try:
        msg_out, final_fees, payment_hash, payment_preimage, description_hash = await acorn_obj.pay_multi_invoice(
            payload.invoice,
            comment=payload.comment,
            tendered_amount=payload.tendered_amount,
            tendered_currency=payload.tendered_currency,
        )
        await acorn_obj.load_data()
        _persist_wallet_balance(acorn_obj)
    except Exception as exc:
        logger.exception("Agent pay_invoice failed")
        raise HTTPException(status_code=400, detail=f"Invoice payment failed: {exc}")

    return {
        "status": "OK",
        "message": msg_out,
        "fees_paid": final_fees,
        "payment_hash": payment_hash,
        "payment_preimage": payment_preimage,
        "description_hash": description_hash,
        "balance": acorn_obj.balance,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.post("/pay_lightning_address", tags=["agent"])
async def agent_pay_lightning_address(
    payload: AgentPayLightningAddressRequest,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    lightning_address = (payload.lightning_address or "").strip().lower()
    if not lightning_address:
        raise HTTPException(status_code=400, detail="Missing lightning_address")
    if "@" not in lightning_address:
        raise HTTPException(status_code=400, detail="Invalid lightning_address format")

    local_part, domain = lightning_address.split("@", 1)
    if not local_part or not domain:
        raise HTTPException(status_code=400, detail="Invalid lightning_address format")
    sat_amount, converted_from_currency, currency_code = await _resolve_sats_from_request(
        payload.amount_sats,
        payload.amount,
        payload.currency,
    )

    tendered_amount = payload.tendered_amount
    if tendered_amount is None:
        tendered_amount = float(payload.amount) if payload.amount is not None else float(sat_amount)

    tendered_currency = (payload.tendered_currency or currency_code or "SAT").upper()

    try:
        msg_out, final_fees = await acorn_obj.pay_multi(
            amount=sat_amount,
            lnaddress=lightning_address,
            comment=payload.comment,
            tendered_amount=tendered_amount,
            tendered_currency=tendered_currency,
        )
        await acorn_obj.load_data()
        _persist_wallet_balance(acorn_obj)
    except Exception as exc:
        logger.exception("Agent pay_lightning_address failed")
        raise HTTPException(status_code=400, detail=f"Lightning address payment failed: {exc}")

    return {
        "status": "OK",
        "message": msg_out,
        "lightning_address": lightning_address,
        "amount_sats": sat_amount,
        "converted_from_currency": converted_from_currency,
        "fees_paid": final_fees,
        "balance": acorn_obj.balance,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.post("/zap", tags=["agent"])
async def agent_zap(
    payload: AgentZapRequest,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    event = (payload.event or payload.event_id or "").strip()
    if not event:
        raise HTTPException(status_code=400, detail="Missing event or event_id")

    sat_amount, converted_from_currency, currency_code = await _resolve_sats_from_request(
        payload.amount_sats,
        payload.amount,
        payload.currency,
    )
    try:
        message = await acorn_obj.zap(sat_amount, event, payload.comment)
        await acorn_obj.load_data()
        _persist_wallet_balance(acorn_obj)
    except Exception as exc:
        logger.exception("Agent zap failed")
        raise HTTPException(status_code=400, detail=f"Zap failed: {exc}")

    return {
        "status": "OK",
        "message": message,
        "event": event,
        "amount_sats": sat_amount,
        "currency": currency_code,
        "converted_from_currency": converted_from_currency,
        "balance": acorn_obj.balance,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.post("/publish_kind0", tags=["agent"])
async def agent_publish_kind0(
    payload: AgentPublishKind0Request,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    extra_fields: dict = {}
    if payload.extra_fields:
        if not isinstance(payload.extra_fields, dict):
            raise HTTPException(status_code=400, detail="extra_fields must be an object")
        extra_fields.update(payload.extra_fields)

    if payload.display_name is not None:
        extra_fields["display_name"] = payload.display_name
    if payload.nip05 is not None:
        extra_fields["nip05"] = payload.nip05
    if payload.banner is not None:
        extra_fields["banner"] = payload.banner
    if payload.website is not None:
        extra_fields["website"] = payload.website
    if payload.lud16 is not None:
        extra_fields["lud16"] = payload.lud16

    relay_list: list[str] | None = None
    if payload.relays:
        relay_list = []
        for each in payload.relays:
            value = str(each or "").strip()
            if not value:
                continue
            relay_list.append(value if value.startswith("wss://") else f"wss://{value}")
        if not relay_list:
            relay_list = None

    try:
        result = await acorn_obj.publish_kind0_metadata(
            name=payload.name,
            about=payload.about,
            picture=payload.picture,
            extra_fields=extra_fields if extra_fields else None,
            relays=relay_list,
            persist_profile_record=True,
        )
    except Exception as exc:
        logger.exception("Agent publish_kind0 failed")
        raise HTTPException(status_code=400, detail=f"Publish kind0 failed: {exc}")

    return {
        "status": "OK",
        "event_id": result.get("event_id"),
        "profile": result.get("profile"),
        "relays": result.get("relays"),
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.post("/publish_kind1", tags=["agent"])
async def agent_publish_kind1(
    payload: AgentPublishKind1Request,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    content = (payload.content or "").strip()
    if not content:
        raise HTTPException(status_code=400, detail="Missing content")

    relay_list: list[str] | None = None
    if payload.relays:
        relay_list = []
        for each in payload.relays:
            value = str(each or "").strip()
            if not value:
                continue
            relay_list.append(value if value.startswith("wss://") else f"wss://{value}")
        if not relay_list:
            relay_list = None

    try:
        result = await acorn_obj.publish_kind1_post(content=content, relays=relay_list)
    except Exception as exc:
        logger.exception("Agent publish_kind1 failed")
        raise HTTPException(status_code=400, detail=f"Publish kind1 failed: {exc}")

    return {
        "status": "OK",
        "event_id": result.get("event_id"),
        "content": result.get("content"),
        "relays": result.get("relays"),
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.post("/delete_request", tags=["agent"])
async def agent_delete_request(
    payload: AgentDeleteRequest,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    relay_list: list[str] | None = None
    if payload.relays:
        relay_list = []
        for each in payload.relays:
            value = str(each or "").strip()
            if not value:
                continue
            relay_list.append(value if value.startswith("wss://") else f"wss://{value}")
        if not relay_list:
            relay_list = None

    try:
        result = await acorn_obj.publish_deletion_request(
            event_ids=payload.event_ids,
            a_tags=payload.a_tags,
            kinds=payload.kinds,
            reason=payload.reason,
            relays=relay_list,
        )
    except Exception as exc:
        logger.exception("Agent delete_request failed")
        raise HTTPException(status_code=400, detail=f"Delete request publish failed: {exc}")

    result["timestamp"] = int(datetime.utcnow().timestamp())
    return result


@router.post("/market/order", tags=["agent"])
async def agent_create_market_order(
    payload: AgentMarketOrderRequest,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    relay_list: list[str] | None = None
    if payload.relays:
        relay_list = []
        for each in payload.relays:
            value = str(each or "").strip()
            if not value:
                continue
            relay_list.append(value if value.startswith("wss://") else f"wss://{value}")
        if not relay_list:
            relay_list = None

    try:
        result = await acorn_obj.create_market_order(
            side=payload.side,
            asset=payload.asset,
            price_sats=payload.price_sats,
            quantity=payload.quantity,
            market=(payload.market or "safebox-v1").strip(),
            order_id=payload.order_id,
            content=payload.content,
            relays=relay_list,
            flow=payload.flow,
        )
    except Exception as exc:
        logger.exception("Agent market order create failed")
        raise HTTPException(status_code=400, detail=f"Market order create failed: {exc}")

    result["timestamp"] = int(datetime.utcnow().timestamp())
    return result


@router.post("/market/ms02/construct_ask", tags=["agent"])
async def agent_construct_ms02_ask(
    payload: AgentMS02ConstructAskRequest,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    try:
        result = acorn_obj.construct_ms02_ask(
            wrapper_scheme=payload.wrapper_scheme,
            wrapper_ref=payload.wrapper_ref,
            price_sats=payload.price_sats,
            expiry=payload.expiry,
            wrapper_commitment=payload.wrapper_commitment,
            fulfillment_mode=payload.fulfillment_mode,
            sealed_delivery_alg=payload.sealed_delivery_alg,
            encrypted_entitlement=payload.encrypted_entitlement,
            instrument=payload.instrument,
            quantity=payload.quantity,
            redemption_provider=payload.redemption_provider,
            provider_commitment=payload.provider_commitment,
            settlement_method=payload.settlement_method,
            market=payload.market,
            hash_alg=payload.hash_alg,
            content_format=payload.content_format,
        )
    except Exception as exc:
        logger.exception("Agent MS-02 ask construct failed")
        raise HTTPException(status_code=400, detail=f"MS-02 ask construct failed: {exc}")

    result["timestamp"] = int(datetime.utcnow().timestamp())
    return result


@router.post("/market/ms02/publish_ask", tags=["agent"])
async def agent_publish_ms02_ask(
    payload: AgentMS02PublishAskRequest,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    content = str(payload.content or "").strip()
    if not content:
        raise HTTPException(status_code=400, detail="Missing content")

    relay_list: list[str] | None = None
    if payload.relays:
        relay_list = []
        for each in payload.relays:
            value = str(each or "").strip()
            if not value:
                continue
            relay_list.append(value if value.startswith("wss://") else f"wss://{value}")
        if not relay_list:
            relay_list = None

    try:
        result = await acorn_obj.publish_event(
            content=content,
            tags=payload.tags or [],
            kind=payload.kind,
            relays=relay_list,
        )
    except Exception as exc:
        logger.exception("Agent MS-02 ask publish failed")
        raise HTTPException(status_code=400, detail=f"MS-02 ask publish failed: {exc}")

    ask_id = None
    for each in result.get("tags") or []:
        if isinstance(each, list) and len(each) >= 2 and str(each[0]) == "ask_id":
            ask_id = str(each[1])
            break
    result["ask_id"] = ask_id
    result["timestamp"] = int(datetime.utcnow().timestamp())
    return result


@router.post("/market/ms02/generate_entitlement", tags=["agent"])
async def agent_generate_ms02_entitlement(
    payload: AgentMS02GenerateEntitlementRequest,
    _acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    entitlement_code = str(payload.entitlement_code or "").strip()
    entitlement_secret = str(payload.entitlement_secret or "").strip()

    generated_code = False
    generated_secret = False

    if not entitlement_code:
        entitlement_code = f"TEST-{datetime.utcnow().strftime('%Y%m%d')}-{secrets.token_hex(4).upper()}"
        generated_code = True

    if not entitlement_secret:
        entitlement_secret = secrets.token_urlsafe(24)
        generated_secret = True

    return {
        "status": "OK",
        "entitlement_code": entitlement_code,
        "entitlement_secret": entitlement_secret,
        "generated_test_entitlement": bool(generated_code or generated_secret),
        "generated_code": generated_code,
        "generated_secret": generated_secret,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.post("/market/ms02/generate_wrapper", tags=["agent"])
async def agent_generate_ms02_wrapper(
    payload: AgentMS02GenerateWrapperRequest,
    _acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    try:
        result = Acorn.generate_ms02_nostr_wrapper(nsec=payload.nsec)
    except Exception as exc:
        logger.exception("Agent MS-02 wrapper generation failed")
        raise HTTPException(status_code=400, detail=f"MS-02 wrapper generation failed: {exc}")

    result["warning"] = (
        "Sensitive: wrapper_secret_nsec is returned. Treat it as the delivery encoding of wrapper_secret "
        "and avoid logging it."
    )
    result["timestamp"] = int(datetime.utcnow().timestamp())
    return result


@router.post("/market/ms02/derive_wrapper_commitment", tags=["agent"])
async def agent_derive_ms02_wrapper_commitment(
    payload: AgentMS02DeriveWrapperCommitmentRequest,
    _acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    try:
        result = Acorn.derive_ms02_wrapper_commitment(
            wrapper_scheme=payload.wrapper_scheme,
            nsec=payload.nsec,
            entitlement_code=payload.entitlement_code,
            entitlement_secret=payload.entitlement_secret,
            hash_alg=payload.hash_alg,
        )
    except Exception as exc:
        logger.exception("Agent MS-02 wrapper commitment derivation failed")
        raise HTTPException(status_code=400, detail=f"MS-02 wrapper commitment derivation failed: {exc}")

    result["timestamp"] = int(datetime.utcnow().timestamp())
    return result


@router.post("/market/secret_hash/derive", tags=["agent"])
async def agent_derive_market_secret_hash(
    payload: AgentDeriveTokenSecretHashRequest,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    try:
        hash_value = acorn_obj.derive_token_secret_hash(
            spec_id=payload.spec_id,
            token_id=payload.token_id,
            redemption_secret=payload.redemption_secret,
            issuer_identifier=payload.issuer_pubkey,
            hash_alg=payload.hash_alg,
        )
    except Exception as exc:
        logger.exception("Agent derive market secret hash failed")
        raise HTTPException(status_code=400, detail=f"Derive secret hash failed: {exc}")

    return {
        "status": "OK",
        "spec_id": str(payload.spec_id or "").strip().upper(),
        "token_id": str(payload.token_id or "").strip(),
        "hash_alg": str(payload.hash_alg or "").strip().lower(),
        "secret_hash": hash_value,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.post("/market/secret_hash/verify", tags=["agent"])
async def agent_verify_market_secret_hash(
    payload: AgentVerifyTokenSecretHashRequest,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    try:
        is_valid = acorn_obj.verify_token_secret_hash(
            expected_hash=payload.expected_hash,
            spec_id=payload.spec_id,
            token_id=payload.token_id,
            redemption_secret=payload.redemption_secret,
            issuer_identifier=payload.issuer_pubkey,
            hash_alg=payload.hash_alg,
        )
    except Exception as exc:
        logger.exception("Agent verify market secret hash failed")
        raise HTTPException(status_code=400, detail=f"Verify secret hash failed: {exc}")

    return {
        "status": "OK",
        "valid": bool(is_valid),
        "spec_id": str(payload.spec_id or "").strip().upper(),
        "token_id": str(payload.token_id or "").strip(),
        "hash_alg": str(payload.hash_alg or "").strip().lower(),
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.post("/secure_dm", tags=["agent"])
async def agent_secure_dm(
    payload: AgentSecureDmRequest,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    recipient = (payload.recipient or "").strip()
    message = (payload.message or "").strip()
    if not recipient:
        raise HTTPException(status_code=400, detail="Missing recipient")
    if not message:
        raise HTTPException(status_code=400, detail="Missing message")

    raw_relays = payload.relays if payload.relays else _agent_default_dm_relays()
    relay_list = _normalize_relays(raw_relays)
    if not relay_list:
        raise HTTPException(status_code=400, detail="No relays configured for secure_dm")

    try:
        result = await acorn_obj.secure_dm(
            nrecipient=recipient,
            message=message,
            dm_relays=relay_list,
        )
    except Exception as exc:
        logger.exception("Agent secure_dm failed")
        raise HTTPException(status_code=400, detail=f"Secure DM failed: {exc}")

    return {
        "status": "OK",
        "message": result,
        "recipient": recipient,
        "relays": relay_list,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.post("/react", tags=["agent"])
async def agent_react(
    payload: AgentReactRequest,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    target_event_id = (payload.event_id or "").strip()

    relay_list: list[str] | None = None
    if payload.relays:
        relay_list = []
        for each in payload.relays:
            value = str(each or "").strip()
            if not value:
                continue
            relay_list.append(value if value.startswith("wss://") else f"wss://{value}")
        if not relay_list:
            relay_list = None

    try:
        if target_event_id:
            result = await acorn_obj.publish_reaction(
                target_event_id=target_event_id,
                content=payload.content,
                reacted_pubkey=payload.reacted_pubkey,
                reacted_kind=payload.reacted_kind,
                relay_hint=payload.relay_hint,
                a_tag=payload.a_tag,
                extra_tags=payload.extra_tags,
                relays=relay_list,
            )
        else:
            if not payload.external_tags:
                raise HTTPException(
                    status_code=400,
                    detail="Provide event_id for kind-7 reaction, or external_tags for kind-17 external reaction",
                )
            result = await acorn_obj.publish_external_reaction(
                content=payload.content,
                external_tags=payload.external_tags,
                extra_tags=payload.extra_tags,
                relays=relay_list,
            )
    except Exception as exc:
        logger.exception("Agent react failed")
        raise HTTPException(status_code=400, detail=f"Reaction publish failed: {exc}")

    return {
        "status": "OK",
        "event_id": result.get("event_id"),
        "kind": result.get("kind", 7),
        "target_event_id": result.get("target_event_id"),
        "content": result.get("content"),
        "tags": result.get("tags"),
        "relays": result.get("relays"),
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.post("/reply", tags=["agent"])
async def agent_reply(
    payload: AgentReplyRequest,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    target_event_id = (payload.event_id or "").strip()
    content = (payload.content or "").strip()
    if not target_event_id:
        raise HTTPException(status_code=400, detail="Missing event_id")
    if not content:
        raise HTTPException(status_code=400, detail="Missing content")

    relay_list: list[str] | None = None
    if payload.relays:
        relay_list = []
        for each in payload.relays:
            value = str(each or "").strip()
            if not value:
                continue
            relay_list.append(value if value.startswith("wss://") else f"wss://{value}")
        if not relay_list:
            relay_list = None

    try:
        result = await acorn_obj.publish_reply(
            target_event_id=target_event_id,
            content=content,
            target_pubkey=payload.target_pubkey,
            target_kind=payload.target_kind,
            relay_hint=payload.relay_hint,
            extra_tags=payload.extra_tags,
            relays=relay_list,
        )
    except Exception as exc:
        logger.exception("Agent reply failed")
        raise HTTPException(status_code=400, detail=f"Reply publish failed: {exc}")

    return {
        "status": "OK",
        "event_id": result.get("event_id"),
        "target_event_id": result.get("target_event_id"),
        "content": result.get("content"),
        "tags": result.get("tags"),
        "relays": result.get("relays"),
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.post("/follow", tags=["agent"])
async def agent_follow(
    payload: AgentFollowRequest,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    identifier = (payload.identifier or "").strip()
    if not identifier:
        raise HTTPException(status_code=400, detail="Missing identifier")

    relay_list: list[str] | None = None
    if payload.relays:
        relay_list = []
        for each in payload.relays:
            value = str(each or "").strip()
            if not value:
                continue
            relay_list.append(value if value.startswith("wss://") else f"wss://{value}")
        if not relay_list:
            relay_list = None

    try:
        result = await acorn_obj.follow(
            identifier=identifier,
            relay_hint=payload.relay_hint,
            relays=relay_list,
        )
    except Exception as exc:
        logger.exception("Agent follow failed")
        raise HTTPException(status_code=400, detail=f"Follow failed: {exc}")

    return {
        "status": "OK",
        "identifier": identifier,
        "result": result,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.post("/unfollow", tags=["agent"])
async def agent_unfollow(
    payload: AgentUnfollowRequest,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    identifier = (payload.identifier or "").strip()
    if not identifier:
        raise HTTPException(status_code=400, detail="Missing identifier")

    relay_list: list[str] | None = None
    if payload.relays:
        relay_list = []
        for each in payload.relays:
            value = str(each or "").strip()
            if not value:
                continue
            relay_list.append(value if value.startswith("wss://") else f"wss://{value}")
        if not relay_list:
            relay_list = None

    try:
        result = await acorn_obj.unfollow(
            identifier=identifier,
            relays=relay_list,
        )
    except Exception as exc:
        logger.exception("Agent unfollow failed")
        raise HTTPException(status_code=400, detail=f"Unfollow failed: {exc}")

    return {
        "status": "OK",
        "identifier": identifier,
        "result": result,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.post("/issue_ecash", tags=["agent"])
async def agent_issue_ecash(
    payload: AgentIssueEcashRequest, acorn_obj: Acorn = Depends(_agent_get_acorn)
):
    if payload.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be greater than zero")

    try:
        token = await acorn_obj.issue_token(payload.amount, comment=payload.comment)
        _persist_wallet_balance(acorn_obj)
    except Exception as exc:
        logger.exception("Agent issue_ecash failed")
        raise HTTPException(status_code=400, detail=f"Unable to issue ecash: {exc}")

    return {
        "status": "OK",
        "ecash_token": token,
        "amount": payload.amount,
        "unit": "sat",
        "balance": acorn_obj.balance,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.post("/accept_ecash", tags=["agent"])
async def agent_accept_ecash(
    payload: AgentAcceptEcashRequest, acorn_obj: Acorn = Depends(_agent_get_acorn)
):
    if not payload.ecash_token:
        raise HTTPException(status_code=400, detail="Missing ecash token")

    try:
        message, token_amount = await acorn_obj.accept_token(
            cashu_token=payload.ecash_token,
            comment=payload.comment,
            tendered_amount=payload.tendered_amount,
            tendered_currency=payload.tendered_currency,
        )
        _persist_wallet_balance(acorn_obj)
    except Exception as exc:
        logger.exception("Agent accept_ecash failed")
        raise HTTPException(status_code=400, detail=f"Unable to accept ecash: {exc}")

    return {
        "status": "OK",
        "message": message,
        "accepted_amount": token_amount,
        "unit": "sat",
        "balance": acorn_obj.balance,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.post("/offers/create", tags=["agent"])
async def agent_create_offer(
    request: Request,
    payload: AgentOfferCreateRequest,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    if payload.grant_kind <= 0:
        raise HTTPException(status_code=400, detail="Invalid grant_kind")
    if not payload.grant_name or not payload.grant_name.strip():
        raise HTTPException(status_code=400, detail="Missing grant_name")

    transmittal_kind = payload.transmittal_kind or settings.RECORD_TRANSMITTAL_KIND
    if payload.compact:
        nonce = generate_nonce(length=1)
        auth_relays = None
        transmittal_relays = None
    else:
        nonce = generate_nonce(length=16)
        auth_relays = settings.AUTH_RELAYS
        transmittal_relays = settings.RECORD_TRANSMITTAL_RELAYS

    nauth = create_nauth(
        npub=acorn_obj.pubkey_bech32,
        nonce=nonce,
        auth_kind=settings.AUTH_KIND,
        auth_relays=auth_relays,
        transmittal_npub=acorn_obj.pubkey_bech32,
        transmittal_kind=transmittal_kind,
        transmittal_relays=transmittal_relays,
        name=acorn_obj.handle,
        scope=f"offer:{payload.grant_kind}",
        grant=payload.grant_name.strip(),
    )

    offer_id = secrets.token_urlsafe(12)
    now_ts = int(datetime.utcnow().timestamp())
    _AGENT_OFFERS[offer_id] = {
        "offer_id": offer_id,
        "owner_npub": acorn_obj.pubkey_bech32,
        "nauth": nauth,
        "grant_kind": payload.grant_kind,
        "grant_name": payload.grant_name.strip(),
        "status": "WAITING_RECIPIENT",
        "recipient_nauth": None,
        "delivery_status": "PENDING",
        "dispatch_detail": None,
        "last_error": None,
        "dispatched_at": None,
        "created_at": now_ts,
        "updated_at": now_ts,
    }

    host = request.url.hostname or ""
    qr_text = nauth
    qr_image_url = (
        f"https://{host}/safebox/qr/{urllib.parse.quote(qr_text, safe='')}" if host else None
    )

    return {
        "status": "OK",
        "offer": _offer_status_payload(_AGENT_OFFERS[offer_id]),
        "qr_text": qr_text,
        "qr_image_url": qr_image_url,
    }


@router.post("/offers/receive/create", tags=["agent"])
async def agent_create_offer_receive(
    request: Request,
    payload: AgentOfferReceiveCreateRequest,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    ttl_seconds = int(payload.ttl_seconds or 0)
    if ttl_seconds < 30 or ttl_seconds > 600:
        raise HTTPException(status_code=400, detail="ttl_seconds must be between 30 and 600")
    grant_kind = payload.grant_kind
    if grant_kind is not None and grant_kind <= 0:
        raise HTTPException(status_code=400, detail="Invalid grant_kind")
    grant_name = payload.grant_name.strip() if payload.grant_name else None

    compact_qr = payload.compact_qr if payload.compact is None else payload.compact

    host = request.url.hostname or ""
    port = request.url.port
    if host:
        if port and ((request.url.scheme == "https" and port != 443) or (request.url.scheme == "http" and port != 80)):
            inferred_recipient_host = f"{host}:{port}"
        else:
            inferred_recipient_host = host
    else:
        inferred_recipient_host = ""

    requested_host = (payload.recipient_host or "").strip()
    if requested_host:
        parsed_requested = urllib.parse.urlparse(
            requested_host if "://" in requested_host else f"https://{requested_host}"
        )
        host_part = (parsed_requested.hostname or "").strip()
        if parsed_requested.port and host_part:
            recipient_host = f"{host_part}:{parsed_requested.port}"
        else:
            recipient_host = host_part
    else:
        recipient_host = inferred_recipient_host

    scope_value = "offer_request"
    if recipient_host:
        scope_grant_kind = int(grant_kind) if grant_kind is not None else 0
        scope_offer_kind = _resolve_offer_kind_for_grant(grant_kind) or 0
        scope_value = f"offer_request:{scope_grant_kind}:{scope_offer_kind}:{recipient_host}"

    transmittal_kind = settings.RECORD_TRANSMITTAL_KIND
    if compact_qr:
        nonce = generate_nonce(length=1)
        auth_relays = None
        transmittal_relays = None
    else:
        nonce = generate_nonce(length=16)
        auth_relays = settings.AUTH_RELAYS
        transmittal_relays = settings.RECORD_TRANSMITTAL_RELAYS

    recipient_nauth = create_nauth(
        npub=acorn_obj.pubkey_bech32,
        nonce=nonce,
        auth_kind=settings.AUTH_KIND,
        auth_relays=auth_relays,
        transmittal_npub=acorn_obj.pubkey_bech32,
        transmittal_kind=transmittal_kind,
        transmittal_relays=transmittal_relays,
        name=acorn_obj.handle,
        scope=scope_value,
        grant="offer_request",
    )

    now_ts = int(datetime.utcnow().timestamp())
    expires_at = now_ts + ttl_seconds

    intent_payload = {
        "v": 1,
        "owner_npub": acorn_obj.pubkey_bech32,
        "status": "WAITING_SEND",
        "grant_kind": grant_kind,
        "grant_name": grant_name,
        "recipient_nauth": recipient_nauth,
        "created_at": now_ts,
        "updated_at": now_ts,
        "expires_at": expires_at,
    }
    intent_id = _encode_receive_intent_token(intent_payload)

    _AGENT_OFFER_RECEIVE_INTENTS[intent_id] = {
        "intent_id": intent_id,
        **intent_payload,
    }

    qr_payload = {
        "v": 1,
        "mode": "recipient_first_offer",
        "intent_id": intent_id,
        "recipient_nauth": recipient_nauth,
        "expires_at": expires_at,
        "compact_qr": compact_qr,
    }
    if not compact_qr:
        qr_payload["auth_kind"] = settings.AUTH_KIND
        qr_payload["auth_relays"] = auth_relays or settings.AUTH_RELAYS
        qr_payload["transmittal_kind"] = transmittal_kind
        qr_payload["transmittal_relays"] = transmittal_relays or settings.RECORD_TRANSMITTAL_RELAYS
        qr_payload["kem_public_key"] = config.PQC_KEM_PUBLIC_KEY
        qr_payload["kemalg"] = settings.PQC_KEMALG
    if grant_kind is not None:
        qr_payload["grant_kind"] = grant_kind
    if grant_name:
        qr_payload["grant_name"] = grant_name
    qr_text = recipient_nauth
    scheme = _external_scheme(request)
    qr_image_url = (
        f"{scheme}://{host}/safebox/qr/{urllib.parse.quote(qr_text, safe='')}" if host else None
    )

    response_payload = {
        "status": "OK",
        "intent": {
            "intent_id": intent_id,
            "status": "WAITING_SEND",
            "grant_kind": grant_kind,
            "grant_name": grant_name,
            "created_at": now_ts,
            "expires_at": expires_at,
        },
        "recipient": {
            "recipient_nauth": recipient_nauth,
            "recipient_host": recipient_host or None,
        },
        "qr_payload": qr_payload,
        "qr_text": qr_text,
        "qr_image_url": qr_image_url,
    }
    if payload.include_ascii_qr:
        response_payload["ascii_qr"] = _build_ascii_qr(qr_text=qr_text, invert=True)
    return response_payload


@router.post("/terminal/ascii_qr", tags=["agent"])
async def agent_terminal_ascii_qr(
    request: Request,
    payload: AgentAsciiQrRequest,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    _ = acorn_obj
    qr_text = (payload.qr_text or "").strip()
    if not qr_text:
        raise HTTPException(status_code=400, detail="Missing qr_text")

    ascii_qr = _build_ascii_qr(qr_text=qr_text, invert=payload.invert)
    host = request.url.hostname or ""
    scheme = _external_scheme(request)
    qr_image_url = (
        f"{scheme}://{host}/safebox/qr/{urllib.parse.quote(qr_text, safe='')}" if host else None
    )

    return {
        "status": "OK",
        "qr_text": qr_text,
        "ascii_qr": ascii_qr,
        "qr_image_url": qr_image_url,
        "timestamp": int(datetime.utcnow().timestamp()),
    }


@router.get("/offers/{offer_id}/status", tags=["agent"])
async def agent_offer_status(
    offer_id: str,
    wait_seconds: int = 0,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    offer = _resolve_offer_for_wallet(offer_id, acorn_obj)

    if offer.get("status") == "WAITING_RECIPIENT" and wait_seconds > 0:
        parsed_offer = parse_nauth(offer["nauth"])
        expected_nonce = parsed_offer["values"].get("nonce")
        auth_kind = parsed_offer["values"].get("auth_kind", settings.AUTH_KIND)
        auth_relays = parsed_offer["values"].get("auth_relays", settings.AUTH_RELAYS)
        since_now = max(0, int(offer["created_at"]) - 5)
        deadline = time.monotonic() + max(1, min(wait_seconds, settings.LISTEN_TIMEOUT))
        while time.monotonic() < deadline:
            candidate_nauth = None
            try:
                candidate_nauth, _, _ = await listen_for_request(
                    acorn_obj=acorn_obj,
                    kind=auth_kind,
                    since_now=since_now,
                    relays=auth_relays,
                )
            except Exception:
                candidate_nauth = None

            if candidate_nauth and _nonce_matches(expected_nonce, candidate_nauth):
                offer["recipient_nauth"] = candidate_nauth
                offer["status"] = "RECIPIENT_READY"
                offer["updated_at"] = int(datetime.utcnow().timestamp())
                break

            since_now = int(datetime.utcnow().timestamp()) - 1
            await asyncio.sleep(1)

    return {"status": "OK", "offer": _offer_status_payload(offer)}


@router.post("/offers/{offer_id}/capture", tags=["agent"])
async def agent_offer_capture_recipient(
    offer_id: str,
    payload: AgentOfferCaptureRequest,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    offer = _resolve_offer_for_wallet(offer_id, acorn_obj)
    parsed_offer = parse_nauth(offer["nauth"])
    expected_nonce = parsed_offer["values"].get("nonce")
    if not _nonce_matches(expected_nonce, payload.recipient_nauth):
        raise HTTPException(status_code=400, detail="Recipient nauth nonce mismatch")

    offer["recipient_nauth"] = payload.recipient_nauth
    offer["status"] = "RECIPIENT_READY"
    offer["updated_at"] = int(datetime.utcnow().timestamp())
    return {"status": "OK", "offer": _offer_status_payload(offer)}


@router.post("/offers/{offer_id}/send", tags=["agent"])
async def agent_offer_send(
    request: Request,
    offer_id: str,
    payload: AgentOfferSendRequest,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    offer = _resolve_offer_for_wallet(offer_id, acorn_obj)
    recipient_nauth = payload.recipient_nauth or offer.get("recipient_nauth")
    if not recipient_nauth:
        raise HTTPException(status_code=400, detail="Recipient nauth is required")

    offer["status"] = "SENDING"
    offer["delivery_status"] = "PENDING"
    offer["last_error"] = None
    offer["updated_at"] = int(datetime.utcnow().timestamp())

    send_parms = sendRecordParms(
        nauth=recipient_nauth,
        grant_name=offer["grant_name"],
        grant_kind=offer["grant_kind"],
    )
    try:
        send_result = await records_router.post_send_record(
            request=request,
            record_parms=send_parms,
            acorn_obj=acorn_obj,
        )
    except Exception as exc:
        offer["status"] = "FAILED"
        offer["delivery_status"] = "FAILED"
        offer["last_error"] = str(exc)
        offer["updated_at"] = int(datetime.utcnow().timestamp())
        logger.exception("Agent offer send failed for offer_id=%s", offer_id)
        raise HTTPException(status_code=400, detail=f"Offer send failed: {exc}")

    if send_result.get("status") != "OK":
        offer["status"] = "FAILED"
        offer["delivery_status"] = "FAILED"
        offer["last_error"] = send_result.get("detail", "Offer send failed")
        offer["updated_at"] = int(datetime.utcnow().timestamp())
        raise HTTPException(status_code=400, detail=send_result.get("detail", "Offer send failed"))

    offer["status"] = "SENT"
    offer["delivery_status"] = "DISPATCHED"
    offer["dispatch_detail"] = send_result.get("detail", "Offer sent")
    offer["dispatched_at"] = int(datetime.utcnow().timestamp())
    offer["updated_at"] = int(datetime.utcnow().timestamp())
    return {
        "status": "OK",
        "detail": send_result.get("detail", "Offer sent"),
        "offer": _offer_status_payload(offer),
    }


@router.get("/offers/{offer_id}/delivery", tags=["agent"])
async def agent_offer_delivery_status(
    offer_id: str,
    wait_seconds: int = 0,
    acorn_obj: Acorn = Depends(_agent_get_acorn),
):
    offer = _resolve_offer_for_wallet(offer_id, acorn_obj)

    if offer.get("status") == "SENDING" and wait_seconds > 0:
        deadline = time.monotonic() + max(1, min(wait_seconds, settings.LISTEN_TIMEOUT))
        while time.monotonic() < deadline:
            if offer.get("status") in {"SENT", "FAILED"}:
                break
            await asyncio.sleep(1)

    return {
        "status": "OK",
        "offer_id": offer["offer_id"],
        "offer_status": offer.get("status"),
        "delivery_status": offer.get("delivery_status", "PENDING"),
        "dispatch_detail": offer.get("dispatch_detail"),
        "last_error": offer.get("last_error"),
        "dispatched_at": offer.get("dispatched_at"),
        "updated_at": offer.get("updated_at"),
    }


@router.post("/onboard", tags=["agent"])
async def agent_onboard(payload: AgentOnboardRequest, request: Request):
    onboard_key = f"onboard-ip:{_extract_client_ip(request)}"
    _enforce_rate_limit(
        onboard_key,
        settings.AGENT_ONBOARD_RPM,
        settings.AGENT_ONBOARD_BURST,
    )

    invite_code = _validate_invite_code(payload.invite_code)

    private_key = Keys()
    nsec = private_key.private_key_bech32()
    acorn_obj = Acorn(
        nsec=nsec,
        relays=settings.RELAYS,
        mints=settings.MINTS,
        home_relay=settings.HOME_RELAY,
        logging_level=settings.LOGGING_LEVEL,
    )

    try:
        await acorn_obj.create_instance()
        await acorn_obj.load_data()
        await acorn_obj.put_record(
            "medical emergency card",
            settings.EMERGENCY_INFO,
            record_kind=32226,
        )
    except Exception as exc:
        logger.exception("Agent onboard wallet initialization failed")
        raise HTTPException(status_code=500, detail=f"Unable to initialize wallet: {exc}")

    emergency_code = generate_pnr()
    register_safebox = RegisteredSafebox(
        handle=acorn_obj.handle,
        npub=acorn_obj.pubkey_bech32,
        nsec=acorn_obj.privkey_bech32,
        home_relay=acorn_obj.home_relay,
        onboard_code=invite_code,
        access_key=acorn_obj.access_key,
        emergency_code=emergency_code,
    )

    with Session(engine) as session:
        try:
            session.add(register_safebox)
            session.commit()
        except IntegrityError:
            session.rollback()
            raise HTTPException(status_code=409, detail="Wallet registration conflict, retry onboarding")

    access_token = create_jwt_token(
        {"sub": acorn_obj.access_key},
        expires_delta=timedelta(
            weeks=settings.TOKEN_EXPIRES_WEEKS,
            hours=settings.TOKEN_EXPIRES_HOURS,
        ),
    )

    return {
        "status": "OK",
        "wallet": {
            "handle": acorn_obj.handle,
            "npub": acorn_obj.pubkey_bech32,
            "nsec": acorn_obj.privkey_bech32,
            "access_key": acorn_obj.access_key,
            "home_relay": acorn_obj.home_relay,
            "balance": acorn_obj.balance,
            "seed_phrase": acorn_obj.seed_phrase,
            "emergency_code": emergency_code,
        },
        "session": {
            "access_token": access_token,
            "token_type": "bearer",
        },
        "timestamp": int(datetime.utcnow().timestamp()),
    }
