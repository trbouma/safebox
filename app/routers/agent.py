import asyncio
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlmodel import Session, select
from sqlalchemy.exc import IntegrityError

from app.appmodels import RegisteredSafebox
from app.config import Settings
from app.db import engine
from app.tasks import handle_payment
from app.utils import create_jwt_token, extract_leading_numbers, generate_pnr
from monstr.encrypt import Keys
from safebox.acorn import Acorn

router = APIRouter()
logger = logging.getLogger(__name__)
settings = Settings()
_RATE_LIMIT_WINDOWS: dict[str, deque[float]] = defaultdict(deque)


class AgentInvoiceRequest(BaseModel):
    amount: int
    comment: str = "Please Pay!"


class AgentPayInvoiceRequest(BaseModel):
    invoice: str
    comment: str = "Paid by agent"
    tendered_amount: float | None = None
    tendered_currency: str = "SAT"


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

    acorn_obj = Acorn(nsec=wallet.nsec, home_relay=wallet.home_relay)
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


def _validate_invite_code(invite_code: str) -> str:
    code = (invite_code or "").strip().lower()
    if not code:
        raise HTTPException(status_code=400, detail="Missing invite code")
    if code not in settings.INVITE_CODES:
        raise HTTPException(status_code=403, detail="Invalid invite code")
    return code


@router.get("/info", tags=["agent"])
async def agent_info(acorn_obj: Acorn = Depends(_agent_get_acorn)):
    return {
        "status": "OK",
        "handle": acorn_obj.handle,
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

    asyncio.create_task(
        handle_payment(
            acorn_obj=acorn_obj,
            cli_quote=cli_quote,
            amount=payload.amount,
            tendered_amount=float(payload.amount),
            tendered_currency="SAT",
            comment=payload.comment,
            mint=settings.HOME_MINT,
        )
    )

    return {
        "status": "OK",
        "invoice": cli_quote.invoice,
        "quote": cli_quote.quote,
        "amount": payload.amount,
        "unit": "sat",
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

    register_safebox = RegisteredSafebox(
        handle=acorn_obj.handle,
        npub=acorn_obj.pubkey_bech32,
        nsec=acorn_obj.privkey_bech32,
        home_relay=acorn_obj.home_relay,
        onboard_code=invite_code,
        access_key=acorn_obj.access_key,
        emergency_code=generate_pnr(),
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
            "emergency_code": register_safebox.emergency_code,
        },
        "session": {
            "access_token": access_token,
            "token_type": "bearer",
        },
        "timestamp": int(datetime.utcnow().timestamp()),
    }
