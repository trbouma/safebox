import asyncio
import json
import logging
from datetime import timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

from fastapi import Depends, Request, APIRouter, Form, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlmodel import Session, select

from safebox.acorn import Acorn
from app.appmodels import RegisteredSafebox, paymentByToken, lnPOSInvoice, lnPOSInfo
from app.config import Settings
from app.db import engine
from app.branding import build_templates
from app.rates import get_currency_rate
from app.tasks import handle_payment
from app.utils import create_jwt_token, fetch_safebox, extract_leading_numbers, get_acorn



settings = Settings()
logger = logging.getLogger(__name__)

templates = build_templates()


router = APIRouter()

class POSAccessKey(BaseModel):
    access_key: str


def _to_two_decimals(value: float | int | str) -> Decimal:
    return Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


async def _wallet_currency_context(acorn_obj: Acorn) -> tuple[str, str]:
    currency_code = "SAT"
    currency_symbol = "₿"
    with Session(engine) as session:
        safebox = session.exec(
            select(RegisteredSafebox).where(RegisteredSafebox.npub == acorn_obj.pubkey_bech32)
        ).first()
        if safebox and safebox.currency_code:
            currency_code = safebox.currency_code.upper()
    if currency_code != "SAT":
        try:
            rate = await get_currency_rate(currency_code)
            if rate and rate.currency_symbol:
                currency_symbol = rate.currency_symbol
        except Exception:
            logger.debug("POS currency symbol lookup failed for %s", currency_code)
    return currency_code, currency_symbol



@router.get("/", tags=["pos"]) 
async def pos_main (    request: Request, 
                        acorn_obj = Depends(get_acorn)
                    ):
    if not acorn_obj:
        return RedirectResponse(url="/")
    currency_code, currency_symbol = await _wallet_currency_context(acorn_obj)
    return templates.TemplateResponse(
        "pos.html",
        {
            "request": request,
            "expression": "",
            "pos_currency": currency_code,
            "pos_currency_symbol": currency_symbol,
        },
    )

@router.post("/calculate", response_class=HTMLResponse)
async def calculate(request: Request, expression: str = Form(...)):
    try:
        # WARNING: `eval` should be avoided or sandboxed in production
        result = eval(expression)
    except Exception:
        result = "Error"
    return templates.TemplateResponse("result.html", {"request": request, "expression": str(result)})

@router.post("/accesstoken", tags=["pos"])
async def access_token(request: Request, payload: POSAccessKey):


    access_key = (payload.access_key or "").strip().lower()
    if not access_key:
        return {"access_token": None}

    match = False
    # Authenticate user
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.access_key==access_key)
        logger.debug("pos access key lookup: %s", statement)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
        if safebox_found:
            pass
        else:
            # Try to find without hyphens
            leading_num = extract_leading_numbers(access_key)
            if not leading_num:
                return {"access_token": None}
            
            statement = select(RegisteredSafebox).where(RegisteredSafebox.access_key.startswith(leading_num))
            safeboxes = session.exec(statement)
            for each_safebox in safeboxes:
                access_key_on_record = each_safebox.access_key
                split_key= access_key_on_record.split("-")
                if split_key[1] in access_key and split_key[2] in access_key:
                    logger.info("POS access key matched hyphenless variant")
                    # set the access key to the one of record
                    access_key = access_key_on_record
                    match=True
                    break
                logger.debug("No match for candidate safebox id=%s", each_safebox.id)
            
            if not match:
                
                return {"access_token": None}


    # Create JWT token
    settings.TOKEN_EXPIRES_HOURS
    access_token = create_jwt_token({"sub": access_key}, expires_delta=timedelta(hours=settings.TOKEN_EXPIRES_HOURS,weeks=settings.TOKEN_EXPIRES_WEEKS))
    
   
    return {"access_token": access_token}


@router.post("/invoice", tags=["pos"])
async def ln_invoice_payment(   request: Request, 
                        ln_invoice: lnPOSInvoice,
                        acorn_obj: Acorn = Depends(get_acorn),
                        ):
    try:
        if not acorn_obj:
            if not ln_invoice.access_token:
                return {"status": "ERROR", "detail": "Unable to authenticate POS wallet."}
            safebox_found = await fetch_safebox(access_token=ln_invoice.access_token)
            acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
            await acorn_obj.load_data()
    except Exception as exc:
        logger.warning("POS invoice wallet auth failed: %s", exc)
        return {"status": "ERROR", "detail": "Unable to authenticate POS wallet."}

    try:
        amount_dec = _to_two_decimals(ln_invoice.amount)
    except (InvalidOperation, ValueError):
        return {"status": "ERROR", "detail": "Invalid amount format."}

    currency_code = (ln_invoice.currency or "SAT").upper()
    if currency_code == "SAT":
        sat_amount = int(amount_dec.to_integral_value(rounding=ROUND_HALF_UP))
    else:
        local_currency = await get_currency_rate(currency_code)
        logger.debug("POS invoice currency rate=%s", local_currency.currency_rate)
        if not local_currency or not local_currency.currency_rate:
            return {"status": "ERROR", "detail": f"Unsupported currency: {currency_code}"}
        sat_amount = int(
            (amount_dec * Decimal("100000000") / Decimal(str(local_currency.currency_rate)))
            .to_integral_value(rounding=ROUND_HALF_UP)
        )
    
    if sat_amount <= 0:
        return {"status": "ERROR", "detail": "Amount must be greater than zero."}

    try:
        cli_quote = await asyncio.to_thread(acorn_obj.deposit, amount=sat_amount, mint=settings.HOME_MINT)
    except Exception as exc:
        logger.exception("POS invoice quote generation failed")
        return {"status": "ERROR", "detail": f"Unable to create invoice: {exc}"}

    asyncio.create_task(
        handle_payment(
            acorn_obj=acorn_obj,
            cli_quote=cli_quote,
            amount=sat_amount,
            tendered_amount=float(amount_dec),
            tendered_currency=currency_code,
            comment=ln_invoice.comment,
            mint=settings.HOME_MINT,
        )
    )

   
    
    return {"status": "ok", "invoice": cli_quote.invoice}

@router.post("/info", tags=["pos"])
async def info(   request: Request, 
                        ln_pos: lnPOSInfo,
                        acorn_obj: Acorn = Depends(get_acorn),
                        ):
    
    try:
        if not acorn_obj:
            if not ln_pos.access_token:
                return {"status": "ERROR", "detail": "Not found"}
            safebox_found = await fetch_safebox(access_token=ln_pos.access_token)
            acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
            await acorn_obj.load_data()
    except Exception as exc:
        logger.warning("POS info lookup failed: %s", exc)
        return {"status": "ERROR", "detail": "Not found"}
       
    
    currency_code, currency_symbol = await _wallet_currency_context(acorn_obj)
    return {
        "status": "OK",
        "detail": "Found",
        "handle": acorn_obj.handle,
        "balance": acorn_obj.balance,
        "currency": currency_code,
        "currency_symbol": currency_symbol,
    }


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    acorn_obj: Acorn = Depends(get_acorn),
):
    if not acorn_obj:
        await websocket.accept()
        await websocket.send_json({"status": "ERROR", "detail": "Authentication required"})
        await websocket.close(code=1008)
        return

    await websocket.accept()

    await websocket.send_json({
        "status": "OK",
        "action": "init",
        "detail": f"Connected to: {acorn_obj.handle}",
    })
    try:
        while True:
            data = await websocket.receive_text()  # raw message
            try:
                message = json.loads(data)  # parse JSON
                logger.info("POS websocket message action=%s", message.get("action"))



                # Example: handle specific message types
                if message.get("action") == "get_balance":
                    if acorn_obj:
                        await acorn_obj.load_data()
                        await websocket.send_json({"status": "OK", "action": "get_balance", "detail": acorn_obj.balance})
                    else:
                        await websocket.send_json({"status": "ERROR", "action": "get_balance","detail": "Not found"})

                elif message.get("action") == "nfc_token":
                    if not acorn_obj:
                        await websocket.send_json({"status": "ERROR", "action": "nfc_token", "detail": "Not connected"})
                        continue
                    nfc_token = message.get("value")
                    nfc_amount = message.get("amount")
                    nfc_currency = message.get("currency")
                    nfc_comment = message.get("comment")
                    await websocket.send_json({"status": "OK", "action": "nfc_token", "detail": "Processing payment..."})
                    try:
                        # Reuse the hardened NFC request flow used by /safebox/access.
                        from app.routers.safebox import request_nfc_payment

                        pos_payment = paymentByToken(
                            payment_token=nfc_token,
                            amount=float(nfc_amount or 0),
                            currency=str(nfc_currency or "SAT"),
                            comment=str(nfc_comment or "Paid from POS"),
                        )
                        response_json = await request_nfc_payment(
                            request=None,
                            payment_token=pos_payment,
                            acorn_obj=acorn_obj,
                        )
                        status = response_json.get("status", "INFO")
                        detail = response_json.get("detail", "Payment request submitted.")
                        await websocket.send_json({"status": status, "action": "nfc_token", "detail": detail})
                    except Exception as exc:
                        logger.exception("POS NFC payment request failed")
                        await websocket.send_json({"status": "ERROR", "action": "nfc_token", "detail": f"NFC payment error: {exc}"})
                    



                else:
                    await websocket.send_json({"status": "ERROR", "action": message.get("action"), "detail": "unknown action"})

            except json.JSONDecodeError:
                await websocket.send_json({"status": "ERROR", "detail": "Invalid JSON format"})
            except Exception as exc:
                logger.exception("POS websocket action processing failed")
                await websocket.send_json({"status": "ERROR", "detail": f"Processing failed: {exc}"})

    except WebSocketDisconnect:
        logger.info("POS websocket disconnected")
    
    
