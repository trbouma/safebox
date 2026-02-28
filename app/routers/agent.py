import asyncio
import logging
import secrets
import time
import urllib.parse
from collections import defaultdict, deque
from decimal import Decimal
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlmodel import Session, select
from sqlalchemy.exc import IntegrityError

from app.appmodels import PaymentQuote, RegisteredSafebox, sendRecordParms
from app.config import ConfigWithFallback, Settings
from app.db import engine
from app.rates import get_currency_rate, get_currency_rates
from app.routers import records as records_router
from app.tasks import handle_payment
from app.utils import (
    create_jwt_token,
    create_nauth,
    extract_leading_numbers,
    generate_nonce,
    generate_pnr,
    listen_for_request,
    parse_nauth,
)
from monstr.encrypt import Keys
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
    # Backward-compatible alias for older clients.
    compact: bool | None = None


class AgentOfferCaptureRequest(BaseModel):
    recipient_nauth: str


class AgentOfferSendRequest(BaseModel):
    recipient_nauth: str | None = None


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


def _persist_wallet_balance(acorn_obj: Acorn) -> None:
    with Session(engine) as session:
        wallet = session.exec(
            select(RegisteredSafebox).where(RegisteredSafebox.npub == acorn_obj.pubkey_bech32)
        ).first()
        if wallet:
            wallet.balance = acorn_obj.balance
            session.add(wallet)
            session.commit()


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
        scope="offer_request",
        grant="offer_request",
    )

    intent_id = f"rx_{secrets.token_urlsafe(9)}"
    now_ts = int(datetime.utcnow().timestamp())
    expires_at = now_ts + ttl_seconds

    _AGENT_OFFER_RECEIVE_INTENTS[intent_id] = {
        "intent_id": intent_id,
        "owner_npub": acorn_obj.pubkey_bech32,
        "status": "WAITING_SEND",
        "grant_kind": grant_kind,
        "grant_name": grant_name,
        "recipient_nauth": recipient_nauth,
        "created_at": now_ts,
        "updated_at": now_ts,
        "expires_at": expires_at,
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
    host = request.url.hostname or ""
    scheme = request.url.scheme or "https"
    qr_image_url = (
        f"{scheme}://{host}/safebox/qr/{urllib.parse.quote(qr_text, safe='')}" if host else None
    )

    return {
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
        },
        "qr_payload": qr_payload,
        "qr_text": qr_text,
        "qr_image_url": qr_image_url,
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
