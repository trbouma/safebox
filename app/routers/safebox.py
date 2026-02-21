import urllib.parse
from collections import defaultdict
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Request, APIRouter, Response, Form, Header, Cookie, Query
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, StreamingResponse

from pydantic import BaseModel
from typing import Optional, List
from fastapi.templating import Jinja2Templates
import asyncio,qrcode, io, urllib

from qrcode.image.styledpil import StyledPilImage
from qrcode.image.styles.moduledrawers.pil import RoundedModuleDrawer
from qrcode.image.styles.colormasks import RadialGradiantColorMask

from datetime import datetime, timedelta, timezone
from safebox.acorn import Acorn
from time import sleep
import json
import bolt11
import hashlib
import secrets
from monstr.util import util_funcs
import requests
import httpx
import time

from monstr.client.client import ClientPool

from monstr.relay.relay import Relay

from monstr.client.client import Client
from typing import List
from monstr.encrypt import NIP4Encrypt, Keys, NIP44Encrypt, DecryptionException
from monstr.event.event import Event
from safebox.models import cliQuote
from urllib.parse import quote, unquote


from app.utils import create_jwt_token, fetch_safebox,extract_leading_numbers, fetch_balance, db_state_change, create_nprofile_from_hex, npub_to_hex, validate_local_part, parse_nostr_bech32, hex_to_npub, create_naddr_from_npub,create_nprofile_from_npub, generate_nonce, create_nauth_from_npub, create_nauth, parse_nauth, get_safebox, get_acorn, db_lookup_safebox, create_nembed_compressed, parse_nembed_compressed, sign_payload, verify_payload, fetch_safebox_by_npub, generate_secure_pin, encode_lnurl, lightning_address_to_lnurl, ensure_csrf_cookie, validate_csrf_token
from sqlmodel import Field, Session, SQLModel, select
from app.appmodels import RegisteredSafebox, CurrencyRate, lnPayAddress, lnPayInvoice, lnInvoice, ecashRequest, ecashAccept, ownerData, customHandle, addCard, deleteCard, updateCard, transmitConsultation, incomingRecord, paymentByToken, nwcVault, nfcCard, nfcPayOutRequest, signedEvent, attestationOwner, rootEntity, wotEntity, NWCSecret
from app.config import Settings, ConfigWithFallback
from app.db import engine
from app.branding import build_templates, get_branding_for_request
from app.tasks import service_poll_for_payment, invoice_poll_for_payment, handle_payment, handle_ecash, task_pay_to_nfc_tag, task_to_send_along_ecash, task_pay_multi, task_pay_multi_invoice
from app.rates import get_currency_rate

import logging, jwt
from sqlalchemy.exc import IntegrityError

logger = logging.getLogger(__name__)


global_websocket: WebSocket = None
notify_connections: dict[str, set[WebSocket]] = defaultdict(set)
settings = Settings()
config = ConfigWithFallback()


HOME_MINT = settings.HOME_MINT
MINTS = settings.MINTS

templates = build_templates()


router = APIRouter()

# SQLModel.metadata.create_all(engine,checkfirst=True)


async def notify_user(npub: str, payload: dict) -> None:
    sockets = list(notify_connections.get(npub, set()))
    stale: list[WebSocket] = []
    for ws in sockets:
        try:
            await ws.send_json(payload)
        except Exception:
            stale.append(ws)
    for ws in stale:
        try:
            notify_connections[npub].remove(ws)
        except KeyError:
            pass


def get_or_create_nwc_secret(npub: str, rotate: bool = False) -> str:
    with Session(engine) as session:
        existing = session.exec(select(NWCSecret).where(NWCSecret.npub == npub)).all()

        if existing and not rotate:
            return existing[0].nwc_secret

        if existing and rotate:
            for each in existing:
                session.delete(each)
            session.flush()

        nwc_secret = Keys().private_key_hex()
        session.add(NWCSecret(nwc_secret=nwc_secret, npub=npub))
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            # In the unlikely case of a collision/race, retry one time.
            nwc_secret = Keys().private_key_hex()
            session.add(NWCSecret(nwc_secret=nwc_secret, npub=npub))
            session.commit()
        return nwc_secret


def resolve_npub_from_card_secret(token_secret: str) -> str:
    """
    Resolve an NFC token secret to safebox npub from active NWCSecret mapping.
    """
    with Session(engine) as session:
        mapped = session.exec(select(NWCSecret).where(NWCSecret.nwc_secret == token_secret)).first()
        if mapped:
            return mapped.npub
    raise ValueError("Card secret is invalid or revoked")

def _welcome_retry_response(request: Request):
    csrf_cookie = request.cookies.get(settings.CSRF_COOKIE_NAME)
    csrf_token = csrf_cookie if csrf_cookie and len(csrf_cookie) >= 32 else secrets.token_urlsafe(32)
    branding = get_branding_for_request(request)
    response = templates.TemplateResponse(
        "welcome.html",
        {
            "request": request,
            "title": "Welcome Page",
            "branding": branding["branding"],
            "branding_message": branding["branding_retry"],
            "csrf_token": csrf_token,
        },
    )
    ensure_csrf_cookie(response=response, current_token=csrf_token, request=request)
    return response




@router.post("/login", tags=["safebox"])
async def login(
    request: Request,
    access_key: str = Form(),
    csrf_token: str = Form(),
    csrf_cookie_token: str | None = Cookie(default=None, alias="csrf_token"),
):
    validate_csrf_token(csrf_form_token=csrf_token, csrf_cookie_token=csrf_cookie_token)


    access_key=access_key.strip().lower()
    match = False
    # Authenticate user
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.access_key==access_key)
        print(statement)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            pass
            # Try to find withouy hypens
            leading_num = extract_leading_numbers(access_key)
            if not leading_num:
                return _welcome_retry_response(request)
                # raise HTTPException(status_code=404, detail=f"{access_key} not found")
            
            statement = select(RegisteredSafebox).where(RegisteredSafebox.access_key.startswith(leading_num))
            safeboxes = session.exec(statement)
            for each_safebox in safeboxes:
                access_key_on_record = each_safebox.access_key
                split_key= access_key_on_record.split("-")
                if split_key[1] in access_key and split_key[2] in access_key:
                    print("match!")
                    # set the access key to the one of record
                    access_key = access_key_on_record
                    match=True
                    break
                
                print(each_safebox)
            
            if not match:
                
                return _welcome_retry_response(request)
                # raise HTTPException(status_code=404, detail=f"{access_key} not found")


    # Create JWT token
    settings.TOKEN_EXPIRES_HOURS
    access_token = create_jwt_token({"sub": access_key}, expires_delta=timedelta(hours=settings.TOKEN_EXPIRES_HOURS,weeks=settings.TOKEN_EXPIRES_WEEKS))
    

    

    # Create response with JWT as HttpOnly cookie
    response = RedirectResponse(url="/safebox/access", status_code=302)
    # response = JSONResponse({"message": "Login successful"})
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,  # Prevent JavaScript access
        max_age=3600 * 24 * settings.SESSION_AGE_DAYS,  # Set login session length
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE.lower(),
    )
    return response

@router.post("/loginwithkey", tags=["safebox"])
async def login_withkey(request: Request, access_key: str):


    access_key=access_key.strip().lower()
    match = False
    # Authenticate user
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.access_key==access_key)
        print(statement)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            pass
            # Try to find withouy hypens
            leading_num = extract_leading_numbers(access_key)
            if not leading_num:
                return _welcome_retry_response(request)
                # raise HTTPException(status_code=404, detail=f"{access_key} not found")
            
            statement = select(RegisteredSafebox).where(RegisteredSafebox.access_key.startswith(leading_num))
            safeboxes = session.exec(statement)
            for each_safebox in safeboxes:
                access_key_on_record = each_safebox.access_key
                split_key= access_key_on_record.split("-")
                if split_key[1] in access_key and split_key[2] in access_key:
                    print("match!")
                    # set the access key to the one of record
                    access_key = access_key_on_record
                    match=True
                    break
                
                print(each_safebox)
            
            if not match:
                
                return _welcome_retry_response(request)
                # raise HTTPException(status_code=404, detail=f"{access_key} not found")


    # Create JWT token
    settings.TOKEN_EXPIRES_HOURS
    access_token = create_jwt_token({"sub": access_key}, expires_delta=timedelta(hours=settings.TOKEN_EXPIRES_HOURS,weeks=settings.TOKEN_EXPIRES_WEEKS))
    

    

    # Create response with JWT as HttpOnly cookie
    response = RedirectResponse(url="/safebox/access", status_code=302)
    # response = JSONResponse({"message": "Login successful"})
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,  # Prevent JavaScript access
        max_age=3600 * 24 * settings.SESSION_AGE_DAYS,  # Set login session length
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE.lower(),
    )
    return response


@router.post("/accesstoken", tags=["safebox"])
async def access_token(request: Request, access_key: str):


    access_key=access_key.strip().lower()
    match = False
    # Authenticate user
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.access_key==access_key)
        print(statement)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            pass
            # Try to find withouy hypens
            leading_num = extract_leading_numbers(access_key)
            if not leading_num:
                return {"access_token": None}
            
            statement = select(RegisteredSafebox).where(RegisteredSafebox.access_key.startswith(leading_num))
            safeboxes = session.exec(statement)
            for each_safebox in safeboxes:
                access_key_on_record = each_safebox.access_key
                split_key= access_key_on_record.split("-")
                if split_key[1] in access_key and split_key[2] in access_key:
                    print("match!")
                    # set the access key to the one of record
                    access_key = access_key_on_record
                    match=True
                    break
                
                print(each_safebox)
            
            if not match:
                
                return {"access_token": None}


    # Create JWT token
    settings.TOKEN_EXPIRES_HOURS
    access_token = create_jwt_token({"sub": access_key}, expires_delta=timedelta(hours=settings.TOKEN_EXPIRES_HOURS,weeks=settings.TOKEN_EXPIRES_WEEKS))
    
   
    return {"access_token": access_token}

@router.post("/loginwithnfc", tags=["safebox"])
async def nfc_login(request: Request, nfc_card: nfcCard):

    k = Keys(config.SERVICE_NSEC)
    my_enc = NIP44Encrypt(k)
    nembed_acquired = nfc_card.nembed
    try:
        parsed_data = parse_nembed_compressed(nembed_acquired)
        host = parsed_data["h"]
        encrypted_key = parsed_data["k"]
    except (KeyError, ValueError, TypeError) as exc:
        logger.warning("NFC login payload invalid: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid NFC payload")

    try:
        decrypted_payload = my_enc.decrypt(encrypted_key, for_pub_k=k.public_key_hex())
    except DecryptionException as exc:
        logger.warning("NFC login decrypt failed: %s", exc)
        raise HTTPException(status_code=401, detail="Invalid NFC card")
    except (ValueError, TypeError) as exc:
        logger.warning("NFC login decrypt payload invalid: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid NFC payload")

    try:
        decrypted_key, decrypted_secure_pin = decrypted_payload.split(":", 1)
        nfc = parsed_data.get("n",["",""])
        logger.info("NFC login payload parsed for host=%s", host)
        if host != request.url.hostname:
            logger.warning("NFC login host mismatch, redirecting to host=%s", host)
            return RedirectResponse(url=f"https://{host}",status_code=301)
           
        # Resolve mapped card secret only.
        npub = resolve_npub_from_card_secret(decrypted_key)
        logger.info("NFC login matched npub=%s", npub)
    except (IndexError, ValueError, TypeError) as exc:
        logger.warning("NFC login decrypted payload malformed: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid NFC payload")
    pass

    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.npub==npub)
        logger.debug("NFC login query: %s", statement)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
        if not safebox_found:
            logger.warning("NFC login failed: npub not registered")
            raise HTTPException(status_code=404, detail="Safebox not found")
    logger.info("NFC login succeeded for handle=%s", safebox_found.handle)

        # Create JWT token
    settings.TOKEN_EXPIRES_HOURS
    access_token = create_jwt_token({"sub": safebox_found.access_key}, expires_delta=timedelta(hours=settings.TOKEN_EXPIRES_HOURS,weeks=settings.TOKEN_EXPIRES_WEEKS))
    

    # Create response with JWT as HttpOnly cookie
    response = RedirectResponse(url="/safebox/access", status_code=302)
    # response = JSONResponse({"message": "Login successful"})
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,  # Prevent JavaScript access
        max_age=3600 * 24 * settings.SESSION_AGE_DAYS,  # Set login session length
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE.lower(),
    )
    return response

@router.get("/logout")
async def logout():
    response = JSONResponse({"message": "Successfully logged out"})
    response.delete_cookie(key="access_token")
    return response

@router.get("/brandqr/{qr_text}", tags=["public"])
async def create_brand_qr(qr_text: str):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_text)
    qr.make(fit=True)

    # Generate an image with blue fill and white background
    img = qr.make_image(fill_color="blue", back_color="white")
    img_2 = qr.make_image(image_factory=StyledPilImage, color_mask=RadialGradiantColorMask())
    

    buf = io.BytesIO()
    img_2.save(buf)
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/jpeg")

@router.get("/qr/{qr_text}", tags=["public"])
async def create_qr(qr_text: str):
          
          
    img = qrcode.make(qr_text)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0) # important here!
    return StreamingResponse(buf, media_type="image/jpeg")

@router.get("/nwcqr", tags=["public"])
async def create_nwc_qr(request: Request,
                        acorn_obj: Acorn= Depends(get_acorn)):
    nwc_secret = get_or_create_nwc_secret(acorn_obj.pubkey_bech32, rotate=False)
    qr_text = f"nostr+walletconnect://{acorn_obj.pubkey_hex}?relay={settings.NWC_RELAYS[0]}&secret={nwc_secret}"

    # &lud16={handle}@{request.url.hostname}
    encoded_qr_text = urllib.parse.quote(qr_text)
    print(f"nwc secret link: {qr_text} {encoded_qr_text}")  

    # Publish the info event
    # 
   
    # 
    async with Client(settings.NWC_RELAYS[0]) as c:
        capabilities = "pay_invoice pay_keysend get_balance get_info make_invoice lookup_invoice list_transactions multi_pay_invoice multi_pay_keysend sign_message notifications"
        n_msg = Event(kind=13194,
                content= capabilities,
                pub_key=acorn_obj.pubkey_hex,
                tags= [["notifications","payment_received payment_sent"]]
                )


        n_msg.sign(acorn_obj.privkey_hex)
        c.publish(n_msg)
        print(f"we published info event ") 
          
    img = qrcode.make(qr_text)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0) # important here!
    return StreamingResponse(buf, media_type="image/jpeg")

@router.api_route("/access", tags=["safebox", "protected"], methods=["GET","POST"])
async def protected_route(    request: Request, 
                        onboard: bool = False, 
                        action_mode:str=None, 
                        action_data: str = None,
                        action_amount: int = None,
                        action_comment: str = None,
                        invoice: str | None = None,
                        invoice_amount: int | None = None,
                        invoice_comment: str | None = None,
                        lnaddress: str | None = None,
                        ecash: str | None = None,
                        nprofile: str | None = None,
                        amount: float = 0,
                        currency: str = 'SAT',
                        acorn_obj = Depends(get_acorn)
                    ):

    if not acorn_obj:
        return RedirectResponse(url="/")

    if request.method == "POST":
        data = await request.json()
        print(f"data from post {data}")
        action_data = data.get("data", None)

    # Preferred explicit query parameters.
    if invoice:
        action_mode = "lninvoice"
        action_data = invoice
        action_amount = invoice_amount
        action_comment = invoice_comment
    elif lnaddress:
        action_mode = "lnaddress"
        action_data = lnaddress
    elif ecash:
        action_mode = "ecash"
        action_data = ecash
    elif nprofile:
        action_mode = "nprofile"
        action_data = nprofile

    if action_data:
        action_data = unquote(action_data)



    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.npub ==acorn_obj.pubkey_bech32)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            raise ValueError("Could not find safebox!")
            

        
        try:
            fiat_currency = await get_currency_rate(safebox_found.currency_code)
            currency_code  = fiat_currency.currency_code
            currency_rate = fiat_currency.currency_rate
            currency_symbol = fiat_currency.currency_symbol
        except Exception as exc:
            currency_code = "SAT"
            currency_rate = 1e8
            currency_symbol = ""

        safebox_found.balance = acorn_obj.balance
        session.add(safebox_found)
        session.commit()
        account_access_key = safebox_found.access_key
        
    if safebox_found.custom_handle:
        lightning_address = f"{safebox_found.custom_handle}@{request.url.hostname}"
    else:
        lightning_address = f"{safebox_found.handle}@{request.url.hostname}"   

    currencies = settings.SUPPORTED_CURRENCIES
    # Token is valid, proceed

    final_url, final_lnurl= lightning_address_to_lnurl(lightning_address)


    host = request.url.hostname
    scheme = "ws" if host in ("localhost", "127.0.0.1") else "wss"
    port = f":{request.url.port}" if request.url.port not in (None, 80) else ""
    ws_url = f"{scheme}://{host}{port}/safebox/ws/status"
    ws_url_notify = f"{scheme}://{host}{port}/safebox/ws/notify"
    
    print(f"ws url {ws_url}")

    return templates.TemplateResponse(  "access.html", 
                                        {   "request": request, 
                                            "title": "Welcome Page", 
                                            "message": "Welcome to Safebox Web!", 
                                            "acorn" : acorn_obj,
                                            "account_access_key":account_access_key, 
                                            "currency_code": currency_code,
                                            "currency_rate": currency_rate,
                                            "currency_symbol": currency_symbol,
                                            "currencies" : currencies,
                                            "lightning_address": lightning_address,
                                            "ws_url": ws_url,
                                            "ws_url_notify": ws_url_notify,
                                            "lnurl": final_lnurl,
                                            "onboard": onboard,
                                            "action_mode": action_mode,
                                            "action_data": action_data,
                                            "action_amount": action_amount,
                                            "amount": amount,
                                            "currency": currency,
                                            "action_comment": action_comment

                                        })
    

@router.post("/payaddress", tags=["protected"])
async def ln_pay_address(   request: Request, 
                            ln_pay: lnPayAddress,
                            acorn_obj: Acorn = Depends(get_acorn)):
    msg_out ="No payment"
    tendered = ""
    status = "OK"

    if ln_pay.currency == "SAT":
        sat_amount = int(ln_pay.amount)
    else:
        local_currency = await get_currency_rate(ln_pay.currency.upper())
        print(local_currency.currency_rate)
        sat_amount = int(ln_pay.amount* 1e8 // local_currency.currency_rate)
        tendered = f" {ln_pay.amount} {ln_pay.currency.upper()}"

    if sat_amount <= 0:
        return {"status": "ERROR", "detail": "Amount must be greater than zero."}

    # Fast-fail in request path so UI gets immediate, structured feedback.
    if sat_amount > acorn_obj.balance:
        return {
            "status": "ERROR",
            "detail": "Insufficient balance for this payment.",
        }

    # check to see if address is local only  

    if '@' not in ln_pay.address:
        pass
        final_address = f"{ln_pay.address.strip().lower()}@{request.url.hostname}"
    else:
        final_address = ln_pay.address.strip().lower()



    # then do regular lightning
    # if response.status_code==200:
    #   
    #    pubkey =response.json()["pubkey"]
    #    safebox_relays = response.json()["relays"]
    #    print(f"this is a safebox: {pubkey} {safebox_relays}")
    #   
    #    msg_out = f"Payment to another safebox for {sat_amount} sats"
    #    text_out = await acorn_obj.send_ecash(amount=sat_amount, nrecipient=hex_to_npub(pubkey), ecash_relays=safebox_relays, comment=ln_pay.comment)
    #    print(f"ecash sent {text_out}")
    #    return {"detail": f"{msg_out} {text_out}"}
    
    try:
        
        pass
        # msg_out, final_fees = await acorn_obj.pay_multi(amount=sat_amount,lnaddress=final_address,comment=ln_pay.comment + tendered)
        # task1 = asyncio.create_task(acorn_obj.pay_multi(amount=sat_amount,lnaddress=final_address,comment=ln_pay.comment + tendered, tendered_amount=ln_pay.amount,tendered_currency=ln_pay.currency))

        task2 = asyncio.create_task(
            task_pay_multi(
                acorn_obj=acorn_obj,
                amount=sat_amount,
                lnaddress=final_address,
                comment=ln_pay.comment + tendered,
                tendered_amount=ln_pay.amount,
                tendered_currency=ln_pay.currency,
                notify_callback=lambda payload: notify_user(acorn_obj.pubkey_bech32, payload),
            )
        )

        # await acorn_obj.add_tx_history( tx_type='D',
        #                                amount=sat_amount,
        #                                tendered_amount=ln_pay.amount,
        #                                tendered_currency=ln_pay.currency,
        #                                comment=ln_pay.comment + tendered, 
        #                                fees=final_fees)
    except (ValueError, RuntimeError) as e:
        logger.warning("Lightning payaddress failed: %s", e)
        return {"status": "ERROR", "detail": f"error {e}"}
    except Exception as e:
        logger.exception("Unexpected error in payaddress")
        return {"status": "ERROR", "detail": f"error {e}"}

    msg_out = "Payment sent!!"

    return {"status": "OK", "detail": msg_out}

@router.post("/swap", tags=["protected"])
async def ln_swap(   request: Request, 
                            acorn_obj: Acorn = Depends(get_acorn)
                        ):
    msg_out ="No error"

    try:
       # msg_out = await acorn_obj.swap_multi_each()
       msg_out = await acorn_obj.swap_multi_consolidate()
       pass
 
    except (ValueError, RuntimeError) as e:
        logger.warning("Swap failed: %s", e)
        return {"status": "ERROR", "detail": f"error {e}"}
    except Exception as e:
        logger.exception("Unexpected error in swap")
        return {"status": "ERROR", "detail": f"error {e}"}


    return {"status": "OK", "detail": f"{msg_out} {acorn_obj.balance} sats"}

@router.post("/payinvoice", tags=["protected"])
async def ln_pay_invoice(   request: Request, 
                        ln_invoice: lnPayInvoice,
                        acorn_obj: Acorn = Depends(get_acorn)):
    msg_out = "No payment"
    try:
        decoded_invoice = bolt11.decode(ln_invoice.invoice)
        invoice_amount_sat = 0
        if decoded_invoice.amount_msat:
            invoice_amount_sat = decoded_invoice.amount_msat // 1000

        # Fast-fail when invoice amount is known and exceeds current balance.
        if invoice_amount_sat > 0 and invoice_amount_sat > acorn_obj.balance:
            return {
                "status": "ERROR",
                "detail": "Insufficient balance for this invoice.",
            }

        task2 = asyncio.create_task(
            task_pay_multi_invoice(
                acorn_obj=acorn_obj,
                lninvoice=ln_invoice.invoice,
                comment=ln_invoice.comment,
                notify_callback=lambda payload: notify_user(acorn_obj.pubkey_bech32, payload),
            )
        )
        msg_out = "Payment request accepted."
        # msg_out, final_fees = await  acorn_obj.pay_multi_invoice(lninvoice=ln_invoice.invoice, comment=ln_invoice.comment)
        # decoded_invoice = bolt11.decode(ln_invoice.invoice)
       
        # print(f"decoded invoice: {decoded_invoice}")
        # amount = decoded_invoice.amount_msat//1000
        # description = decoded_invoice.description


       

    except (ValueError, RuntimeError) as e:
        logger.warning("Invoice payment failed: %s", e)
        return {"status": "ERROR", "detail": f"error {e}"}
    except Exception:
        logger.exception("Unexpected error in payinvoice")
        return {"status": "ERROR", "detail": "internal payment error"}


    
    return {"status": "OK", "detail": msg_out}

@router.post("/issueecash", tags=["protected"])
async def issue_ecash(   request: Request, 
                        ecash_request: ecashRequest,
                        acorn_obj: Acorn = Depends(get_acorn)):
    msg_out ="No payment"
    try:
        # safebox_found = await fetch_safebox(access_token=access_token)
        # acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
        # await acorn_obj.load_data()

        # msg_out = await  acorn_obj.pay_multi_invoice(lninvoice=ln_invoice.invoice, comment=ln_invoice.comment)
        msg_out = await acorn_obj.issue_token(ecash_request.amount)
        # await acorn_obj.add_tx_history(tx_type='D',amount=ecash_request.amount,comment='ecash withdrawal')
    except (ValueError, RuntimeError) as e:
        logger.warning("Issue ecash failed: %s", e)
        return {    "status": "ERROR",
                    f"detail": f"error {e}"}
    except Exception:
        logger.exception("Unexpected error in issueecash")
        return {"status": "ERROR", "detail": "internal ecash issue error"}


    
    return {    "status": "OK",
                "detail": msg_out
            }

@router.post("/acceptecash", tags=["protected"])
async def accept_ecash(   request: Request, 
                        ecash_accept: ecashAccept,
                        acorn_obj: Acorn = Depends(get_acorn)):
    msg_out ="No message"
    acorn_obj.load_data()
    try:
     
        
        msg_out, token_accepted_amount = await acorn_obj.accept_token(ecash_accept.ecash_token, comment="test")
        # await acorn_obj.add_tx_history(tx_type='C', amount=token_accepted_amount, comment='ecash deposit')
        pass
    except (ValueError, RuntimeError) as e:
        logger.warning("Accept ecash failed: %s", e)
        return {    "status": "ERROR",
                    "detail": f"error {e}"}
    except Exception:
        logger.exception("Unexpected error in acceptecash")
        return {"status": "ERROR", "detail": "internal ecash accept error"}


    
    return {    "status": "OK",
                "detail": msg_out
            }

@router.post("/invoice", tags=["protected"])
async def ln_invoice_payment(   request: Request, 
                        ln_invoice: lnInvoice,
                        acorn_obj: Acorn = Depends(get_acorn)):
    msg_out ="No payment"
    if ln_invoice.currency == "SAT":
        sat_amount = int(ln_invoice.amount)
    else:
        local_currency = await get_currency_rate(ln_invoice.currency.upper())
        print(local_currency.currency_rate)
        sat_amount = int(ln_invoice.amount* 1e8 // local_currency.currency_rate)
    
    

    cli_quote = await asyncio.to_thread(acorn_obj.deposit, amount=sat_amount, mint=HOME_MINT)

    task = asyncio.create_task(handle_payment(acorn_obj=acorn_obj,cli_quote=cli_quote, amount=sat_amount, tendered_amount= ln_invoice.amount, tendered_currency= ln_invoice.currency, comment=ln_invoice.comment, mint=HOME_MINT))

    # task2 = asyncio.create_task(invoice_poll_for_payment(acorn_obj=acorn_obj,quote=cli_quote.quote, amount=sat_amount, mint=HOME_MINT))
    
    return {"status": "ok", "invoice": cli_quote.invoice}

    # Do the update for the polling balance
 
    # task = asyncio.create_task(acorn_obj.poll_for_payment(quote=cli_quote.quote, amount=ln_invoice.amount,mint=HOME_MINT))
    # Update the cache amout   
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.handle ==safebox_found.handle)
        safeboxes = session.exec(statement)
        safebox_update = safeboxes.first()
        safebox_update.balance = safebox_update.balance + ln_invoice.amount
        session.add(safebox_update)
        session.commit()
    



    return {"status": "ok",
            "invoice": cli_quote.invoice}


@router.get("/poll", tags=["protected"])
async def poll_for_balance(request: Request, access_token: str = Cookie(None)):
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
        
    except HTTPException as exc:
        logger.warning("Poll auth failure: %s", exc.detail)
        return {"detail": "error",
                "balance": 0}
    except Exception:
        logger.exception("Unexpected error in poll_for_balance")
        return {"detail": "error",
                "balance": 0}

    print(f"safebox poll {safebox_found.handle} {safebox_found.balance}")


    return {"detail": "polling",
            "balance": safebox_found.balance}

@router.get("/privatedata", tags=["safebox", "protected"])
async def my_private_data(      request: Request,
                                private_mode:str = "card", 
                                kind:int = 37375,
                                acorn_obj = Depends(get_acorn)
                    ):
    """Protected access to private data stored in home relay"""



    user_records = await acorn_obj.get_user_records(record_kind=kind)
    
    referer = urllib.parse.urlparse(request.headers.get("referer")).path

    return templates.TemplateResponse(  "privatedata.html", 
                                        {   "request": request,                                            
                                            "user_records": user_records,                                          
                                            "referer": referer
                                            })

@router.get("/personalmessages", tags=["safebox", "protected"])
async def my_personal_messages(      request: Request,
                                private_mode:str = "card", 
                                kind:int = 1059,
                                acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to private data stored in home relay"""


    dm_relays = settings.DM_RELAYS
    print(acorn_obj.pubkey_bech32)
    since_last = (datetime.now() - timedelta(days=1)).timestamp()

    user_records = await acorn_obj.get_user_records(record_kind=kind,relays=dm_relays, reverse=False)
   
    print(f"user_records: {user_records}")
    
    
    referer = urllib.parse.urlparse(request.headers.get("referer")).path

    return templates.TemplateResponse(  "messages/privatemessages.html", 
                                        {   "request": request,                                            
                                            "user_records": user_records,                                          
                                            "referer": referer
                                            })

@router.get("/txhistory", tags=["safebox", "protected"])
async def my_tx_history(    request: Request,
                                
                            access_token: str = Cookie(None)
                    ):
    """Protected access to private data stored in home relay"""
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
    except HTTPException:
        logger.info("txhistory access denied; redirecting")
        response = RedirectResponse(url="/", status_code=302)
        return response
    except Exception:
        logger.exception("Unexpected error in txhistory")
        response = RedirectResponse(url="/", status_code=302)
        return response
    
    acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    await acorn_obj.load_data()
    tx_history = await acorn_obj.get_tx_history()
    
    # print(f"tx history {tx_history}")

    return templates.TemplateResponse(  "txhistory.html", 
                                        {   "request": request,
                                            "safebox": safebox_found ,
                                            "tx_history": tx_history
                                            
                                            })

@router.get("/inbox", tags=["safebox", "protected"])
async def get_inbox(      request: Request,

                                nauth: str = None,                         
                                access_token: str = Cookie(None)
                    ):
    """Protected access to inbox in home relay"""
    nprofile_parse = None
 
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
    except HTTPException:
        logger.info("inbox access denied; redirecting")
        response = RedirectResponse(url="/", status_code=302)
        return response
    except Exception:
        logger.exception("Unexpected error in inbox")
        response = RedirectResponse(url="/", status_code=302)
        return response
    
    acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    await acorn_obj.load_data()
    # since = None
    since = util_funcs.date_as_ticks(datetime.now())
   
    
    

    


    if nauth:
        
        print("nauth")
        parsed_result = parse_nauth(nauth)
        npub = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values']['nonce']
        auth_kind = parsed_result['values'].get("auth_kind",settings.AUTH_KIND)
        auth_relays = parsed_result['values'].get("auth_relays",settings.AUTH_RELAYS)
        transmittal_kind = parsed_result['values'].get("transmittal_kind",settings.TRANSMITTAL_KIND)
        transmittal_relays = parsed_result['values'].get("transmittal_relays",settings.TRANSMITTAL_RELAYS)
        
        user_records = await acorn_obj.get_user_records(record_kind=transmittal_kind, relays=transmittal_relays)
        

    return templates.TemplateResponse(  "inbox.html", 
                                        {   "request": request,
                                            "safebox": safebox_found ,
                                            "user_records": user_records,
                                            "transmittal_kind": transmittal_kind,
                                            "nauth": nauth

                                        })

@router.get("/health", tags=["safebox", "protected"])
async def my_health_data(       request: Request, 
                                nauth: str = None,
                                nonce: str = None,
                                access_token: str = Cookie(None)
                    ):
    """Protected access to private data stored in home relay"""
    #FIXME Remove this function
    nauth_response = None
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
    except HTTPException:
        logger.info("health access denied; redirecting")
        response = RedirectResponse(url="/", status_code=302)
        return response
    except Exception:
        logger.exception("Unexpected error in my_health_data auth")
        response = RedirectResponse(url="/", status_code=302)
        return response
    
    acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    await acorn_obj.load_data()
    try:
        health_records = await acorn_obj.get_user_records(record_kind=32225 )
    except (ValueError, RuntimeError) as exc:
        logger.warning("Health records unavailable: %s", exc)
        health_records = None
    except Exception:
        logger.exception("Unexpected error loading health records")
        health_records = None

    if nauth:
        
        print("nauth")

        

        parsed_result = parse_nauth(nauth)
        npub_initiator = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values']['nonce']
        auth_kind = parsed_result['values'].get("auth_kind")
        auth_relays = parsed_result['values'].get("auth_relays")
        transmittal_kind = parsed_result['values'].get("transmittal_kind")
        transmittal_relays = parsed_result['values'].get("transmittal_relays")
        scope = parsed_result['values'].get("scope")
    

        
        # also need to set transmittal npub 


        nauth_response = create_nauth(    npub=acorn_obj.pubkey_bech32,
                                    nonce=nonce,
                                    auth_kind= auth_kind,
                                    auth_relays=auth_relays,
                                    transmittal_npub=acorn_obj.pubkey_bech32,
                                    transmittal_kind=transmittal_kind,
                                    transmittal_relays=transmittal_relays,
                                    name=safebox_found.handle,
                                    scope='transmit',
                                    grant=scope
        )

        print(f"my health data initiator npub: {npub_initiator} and nonce: {nonce} auth relays: {auth_kind} auth kind: {auth_kind} transmittal relays: {transmittal_relays} transmittal kind: {transmittal_kind}")

        
        # send the recipient nauth message
        msg_out = await acorn_obj.secure_transmittal(nrecipient=npub_initiator,message=nauth_response,dm_relays=auth_relays,kind=auth_kind)

    else:
       pass

        

    
    return templates.TemplateResponse(  "healthdata.html", 
                                        {   "request": request,
                                            "safebox": safebox_found,
                                            "health_records": health_records ,
                                            "nauth": nauth_response

                                        })


@router.get("/credentials", tags=["safebox", "protected"])
async def my_credentials(       request: Request, 
                        access_token: str = Cookie(None)
                    ):
    """Protected access to credentials stored in home relay"""
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
    except Exception as exc:
        response = RedirectResponse(url="/", status_code=302)
        return response
    
    

    return templates.TemplateResponse(  "credentials.html", 
                                        {   "request": request,
                                            "safebox": safebox_found 

                                        })


@router.get("/ecash", tags=["safebox", "protected"])
async def my_ecash(       request: Request, 
                        access_token: str = Cookie(None)
                    ):
    """Protected access to credentials stored in home relay"""
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
    except Exception as exc:
        response = RedirectResponse(url="/", status_code=302)
        return response
    
    

    return templates.TemplateResponse(  "ecash.html", 
                                        {   "request": request,
                                            "safebox": safebox_found 

                                        })


@router.get("/attest", tags=["safebox", "protected"])
async def my_attest(       request: Request, 
                        acorn_obj: Acorn = Depends(get_acorn)
                    ):
    
    print(f"{acorn_obj.pubkey_bech32}")
    return templates.TemplateResponse(      "attest/attest.html", 
                                        {   "request": request,
                                            "acorn_obj": acorn_obj


                                        })  

@router.get("/trust", tags=["safebox", "protected"])
async def my_attest(       request: Request, 
                        acorn_obj: Acorn = Depends(get_acorn)
                    ):
    
    root_entities = ""
    wot_entities = []
    try:
        await acorn_obj.load_data()
        root_entities = await acorn_obj.get_root_entities(relays=settings.RELAYS)
        wot_entities = await acorn_obj.get_wot_entities(relays=settings.RELAYS)
    except Exception as exc:
        logger.exception("Failed loading trust page data")

    wot_entities_str = ""
    for each in wot_entities:
        wot_entities_str += each + " "
    

    
    print(f"root entities: {root_entities}")
    return templates.TemplateResponse(      "attest/trust.html", 
                                        {   "request": request,
                                            "root_entities": root_entities,
                                            "wot_entities":  wot_entities_str,
                                            "acorn_obj": acorn_obj


                                        })  

@router.post("/setrootentities", tags=["safebox", "protected"])
async def set_root_entities(            request: Request, 
                                        root_entity: rootEntity,
                                        acorn_obj: Acorn = Depends(get_acorn)
                    ):
    
   
    await acorn_obj.load_data()
    print(f"root entities received: {root_entity.root_entities}")
    await acorn_obj.set_trusted_entities(pub_list_str=root_entity.root_entities)
    root_entities = await acorn_obj.get_root_entities(relays=settings.RELAYS)
    
   
    return {"status": "OK", "detail": root_entities}

@router.post("/setwotentities", tags=["safebox", "protected"])
async def set_wot_entities(            request: Request, 
                                        wot_entity: wotEntity,
                                        acorn_obj: Acorn = Depends(get_acorn)
                    ):
    
   
    await acorn_obj.load_data()
    print(f"wot entities received: {wot_entity.wot_entities}")
    await acorn_obj.set_wot_entities(pub_list_str=wot_entity.wot_entities)
    wot_entities = await acorn_obj.get_wot_entities(relays=settings.RELAYS)
    # convert to a string with npubs
    wot_entities_str = ""
    for each in wot_entities:
        wot_entities_str += each + ' '
    
   
    return {"status": "OK", "detail": wot_entities_str}

@router.get("/gettrustlist", tags=["safebox", "protected"])
async def get_trust_list(            request: Request, 
                                        
                                    acorn_obj: Acorn = Depends(get_acorn)
                    ):
    
    trust_out = ''
    trust_count = 1
    await acorn_obj.load_data()
   
    try: 
        trust_list = await acorn_obj.get_trusted_entities(relays=settings.RELAYS)
        
        for each in trust_list:
            try:
                k_each = Keys(pub_k=each)            
                trust_out += f"{k_each.public_key_bech32()} "
                trust_count +=1
            except Exception as exc:
                logger.debug("Skipping invalid trusted entity entry=%s error=%s", each, exc)
    except Exception as exc:
        logger.exception("Failed to fetch trusted entities")
        trust_out = "Error"
    
   
    return {"status": "OK", "detail": trust_out}

                                    


@router.get("/dangerzone", tags=["safebox", "protected"])
async def my_danger_zone(       request: Request, 
                        acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to danger zone"""

 


    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.npub ==acorn_obj.pubkey_bech32)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
       
    emergency_code = safebox_found.emergency_code

    # Do the nostr wallet connect
    nwc_secret = get_or_create_nwc_secret(acorn_obj.pubkey_bech32, rotate=False)
    nwc_key = f"nostr+walletconnect://{acorn_obj.pubkey_hex}?relay={settings.NWC_RELAYS[0]}&secret={nwc_secret}"

    # Publish profile
    async with Client(settings.NWC_RELAYS[0]) as c:
        n_msg = Event(kind=13194,
                    content= "pay_invoice get_balance get_info make invoice list_transactions multi_pay_invoice multi_pay_keysend sign_message notifications payment_received",
                    pub_key=acorn_obj.pubkey_hex,
                    tags=[["notifications","payment_received payment_sent balance_changed"]],
                   
                    )


        n_msg.sign(acorn_obj.privkey_hex)
        c.publish(n_msg)


    
    k = Keys(config.SERVICE_NSEC)
    my_enc = NIP44Encrypt(k)

    secure_pin = generate_secure_pin()
    plaintext_to_encrypt = f"{nwc_secret}:{secure_pin}"
  
    encrypt_token = my_enc.encrypt(plaintext_to_encrypt, to_pub_k=k.public_key_hex())
   
    token_obj = {"h": request.url.hostname, "k": encrypt_token, "a": 21}
    nembed = create_nembed_compressed(token_obj)
    print(f"nembed length {len(nembed)} {nembed}")
    payment_token=nembed

    return templates.TemplateResponse(      "dangerzone.html", 
                                        {   "request": request,
                                            "emergency_code": emergency_code,
                                            "currencies": settings.SUPPORTED_CURRENCIES,
                                            "payment_token" : payment_token,
                                            "secure_pin": secure_pin,
                                            "nwc_key": nwc_key

                                        })

@router.get("/issuecard", tags=["safebox", "protected"])
async def issue_card(       request: Request, 
                        rotate: bool = Query(False),
                        acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to danger zone"""

    


    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.npub ==acorn_obj.pubkey_bech32)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
       
    emergency_code = safebox_found.emergency_code

    # Do the nostr wallet connect
    nwc_secret = get_or_create_nwc_secret(acorn_obj.pubkey_bech32, rotate=rotate)
    nwc_key = f"nostr+walletconnect://{acorn_obj.pubkey_hex}?relay={settings.NWC_RELAYS[0]}&secret={nwc_secret}"

    # Publish profile
    async with Client(settings.NWC_RELAYS[0]) as c:
        n_msg = Event(kind=13194,
                    content= "pay_invoice get_balance get_info make invoice list_transactions multi_pay_invoice multi_pay_keysend sign_message notifications payment_received",
                    pub_key=acorn_obj.pubkey_hex,
                    tags=[["notifications","payment_received payment_sent balance_changed"]],
                   
                    )


        n_msg.sign(acorn_obj.privkey_hex)
        c.publish(n_msg)


    
    k = Keys(config.SERVICE_NSEC)
    my_enc = NIP44Encrypt(k)

    secure_pin = generate_secure_pin()
    plaintext_to_encrypt = f"{nwc_secret}:{secure_pin}"
  
    encrypt_token = my_enc.encrypt(plaintext_to_encrypt, to_pub_k=k.public_key_hex())
    nfc_default = settings.NFC_DEFAULT
    token_obj = {"h": request.url.hostname, "k": encrypt_token, "a": 21, "n": nfc_default}
    nembed = create_nembed_compressed(token_obj)
    print(f"nembed length {len(nembed)} {nembed}")
    payment_token=nembed

    return templates.TemplateResponse(      "issuecard.html", 
                                        {   "request": request,
                                            "emergency_code": emergency_code,
                                            "currencies": settings.SUPPORTED_CURRENCIES,
                                            "payment_token" : payment_token,
                                            "secure_pin": secure_pin,
                                            "rotated": rotate

                                        })

@router.get("/facerec", tags=["safebox", "protected"])
async def my_face_rec(       request: Request, 
                        acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to danger zone"""

    return templates.TemplateResponse(      "facerec/capture.html", 
                                        {   "request": request
                                            

                                        })

@router.get("/displaycard", tags=["safebox", "protected"])
async def display_card(     request: Request, 
                            card: str = None,
                            kind: int = 37375,
                            action_mode: str = None,
                            acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to updating the card"""

    
    if action_mode == 'edit':

        record = await acorn_obj.get_record(record_name=card, record_kind=kind)
        
        content = record["payload"]
    elif action_mode =='add':
        card = ""
        content =""
    
    referer = urllib.parse.urlparse(request.headers.get("referer")).path

    return templates.TemplateResponse(  "card.html", 
                                        {   "request": request,
                                            
                                            "card": card,
                                            "record_kind": kind,
                                            "referer": referer,
                                            "action_mode":action_mode,
                                            "content": content
                                            
                                        })

@router.get("/displaymessage", tags=["safebox", "protected"])
async def display_message(     request: Request, 
                            card: str = None,
                            kind: int = 1059,
                            action_mode: str = None,
                            acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to updating the card"""

    
    if action_mode == 'edit':

        record = await acorn_obj.get_record(record_name=card, record_kind=kind)
        
        # content = record["payload"]
        content = record
    elif action_mode =='add':
        card = ""
        content =""
    
    referer = urllib.parse.urlparse(request.headers.get("referer")).path

    return templates.TemplateResponse(  "messages/message.html", 
                                        {   "request": request,
                                            
                                            "card": card,
                                            "record_kind": kind,
                                            "referer": referer,
                                            "action_mode":action_mode,
                                            "content": content
                                            
                                        })


@router.get("/profile/{handle}", response_class=HTMLResponse)
async def root_get_user_profile(    request: Request, 
                                    handle: str, 

                                   
                                ):

    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.handle ==handle)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            raise HTTPException(status_code=404, detail=f"{handle} not found")

    user_name = safebox_found.handle    
    lightning_address = f"{safebox_found.handle}@{request.url.hostname}"

    return templates.TemplateResponse("profile.html", 
                                      {"request": request, "user_name": user_name, 
                                       "lightning_address": lightning_address,
                                          
                                            })


@router.websocket("/ws/notify")
async def ws_status(websocket: WebSocket,  acorn_obj: Acorn = Depends(get_acorn)):

    # Event channel for completion/status notifications.
    await websocket.accept()
    notify_connections[acorn_obj.pubkey_bech32].add(websocket)
    await websocket.send_json({"notify":"connected"})
    try:
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=45)
            except asyncio.TimeoutError:
                await websocket.send_json({"notify": "heartbeat"})
    except WebSocketDisconnect as e:
        print(f"Client disconnected {e.code}")
    finally:
        notify_connections[acorn_obj.pubkey_bech32].discard(websocket)


@router.websocket("/ws/status")
async def ws_status(websocket: WebSocket,  acorn_obj: Acorn = Depends(get_acorn)):


                

 
    global global_websocket
    await websocket.accept()
    
    global_websocket = websocket
    
    start_time = time.time()
    duration = 300  # 5 minutes in seconds



    # starting_balance = safebox_found.balance
    await acorn_obj.load_data()
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.npub == acorn_obj.pubkey_bech32)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
        starting_balance = safebox_found.balance if safebox_found else acorn_obj.get_balance()
    # new_balance = starting_balance
    message = "All payments up to date!"
    status = "SAME"
    print(f"the local currency is {acorn_obj.local_currency}")

   
    since_now = int(datetime.now(timezone.utc).timestamp())
    
    
    try:
    
        fiat_currency = await get_currency_rate(acorn_obj.local_currency)
        currency_code  = fiat_currency.currency_code
        currency_rate = fiat_currency.currency_rate
        currency_symbol = fiat_currency.currency_symbol
        
        while time.time() - start_time < duration:
            try:
                latest_balance = await db_state_change(acorn_obj=acorn_obj, baseline_balance=starting_balance)

                new_balance = latest_balance
                # print(f"websocket balances: {starting_balance} {test_balance} {new_balance}")

                # print(f"acorn local currency {acorn_obj.local_currency}")
                fiat_balance = f"{currency_symbol}{(currency_rate * new_balance / 1e8):.2f} {acorn_obj.local_currency}"


                if new_balance > starting_balance:
                    # fiat_received = f"{currency_symbol}{(currency_rate * (new_balance-starting_balance) / 1e8):.2f} {acorn_obj.local_currency}"

                    message = f"Transaction successful!"
                    status = "RECD"

                elif new_balance < starting_balance:
                    message = f"Transaction successful!"
                    status = "SENT"

                elif new_balance == starting_balance:
                    continue
                    # message = f"Ready."
                    # status = "OK"

                
                # fiat_balance = f"{currency_symbol}{'{:.2f}'.format(currency_rate * new_balance / 1e8)} {currency_code}"
                
                print(f"new_balance: {new_balance} status: {status} fiat balance: {fiat_balance}")
                await websocket.send_json({"balance":new_balance,"fiat_balance":fiat_balance, "message": message, "status": status})
                starting_balance = new_balance

            
            
            except Exception as e:
                print(f"Websocket message: {e}")
                break
    except Exception as e:
        # print ("Error {e}")
        pass
    finally:

        print("websocket connection closed and task canceled")
        try:
            await websocket.close()
        except Exception:
            pass

        
          
    

@router.websocket("/wsrequesttransmittal/{nauth}")
async def websocket_requesttransmittal( websocket: WebSocket, 
                                        nauth:str=None, 
                                        acorn_obj = Depends(get_acorn)
                                        ):

    print(f"ws nauth: {nauth}")
    auth_relays = None

    await websocket.accept()

    if nauth:
        parsed_nauth = parse_nauth(nauth)   
        auth_kind = parsed_nauth['values'] ['auth_kind']   
        auth_relays = parsed_nauth['values']['auth_relays']
        print(f"ws auth relays: {auth_relays}")



    # acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    # await acorn_obj.load_data()

    naddr = acorn_obj.pubkey_bech32
    nauth_old = None
    # since_now = None
    since_now = int(datetime.now(timezone.utc).timestamp())

    while True:
        try:
            # await acorn_obj.load_data()
            try:
                client_nauth = await listen_for_request(acorn_obj=acorn_obj,kind=auth_kind, since_now=since_now, relays=auth_relays)
            except Exception as exc:
                client_nauth=None
            

            
            # parsed_nauth = parse_nauth(client_nauth)
            # name = parsed_nauth['name']
            # print(f"client nauth {client_nauth}")
            

            if client_nauth != nauth_old: 
                parsed_nauth = parse_nauth(client_nauth)
                transmittal_kind = parsed_nauth['values'].get('transmittal_kind',settings.TRANSMITTAL_KIND)
                transmittal_relays = parsed_nauth['values'].get('transmittal_relays',settings.TRANSMITTAL_RELAYS)
                nprofile = {'nauth': client_nauth, 'name': 'safebox user', 'transmittal_kind': transmittal_kind, "transmittal_relays": transmittal_relays}
                print(f"send {client_nauth}") 
                await websocket.send_json(nprofile)
                nauth_old = client_nauth
                break
           
        
        except Exception as e:
            print(f"Websocket message: {e}")
            break
        
        await asyncio.sleep(5)
        
     
    # await websocket.close()
    print("websocket connection closed")

@router.get("/getrecords", tags=["safebox", "protected"])
async def get_records(      request: Request, 
                            kind: str = 37375,
                            access_token: str = Cookie(None)
                    ):
    """Protected access to private data stored in home relay"""
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
        
    except Exception as exc:
        response = RedirectResponse(url="/", status_code=302)
        return response
    
    acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    await acorn_obj.load_data()
    records_out = await acorn_obj.get_user_records(record_kind=kind)

    return records_out

@router.post("/addcard", tags=["safebox", "protected"])
async def add_card(         request: Request, 
                            add_card: addCard,
                            access_token: str = Cookie(None)
                    ):
    """Add card to safebox"""
    status = "OK"
    detail = "Nothing yet"
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
        
    except Exception as exc:
        response = RedirectResponse(url="/", status_code=302)
        return response
    
    try:
        acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
        await acorn_obj.load_data()
        await acorn_obj.put_record(record_name=add_card.title,record_value=add_card.content)
        detail = "Update successful!"
    except Exception as e:
        status = "ERROR"
        detail = f"Error: {e}"
    

    return {"status": status, "detail": detail}  

@router.post("/updatecard", tags=["safebox", "protected"])
async def update_card(         request: Request, 
                            update_card: updateCard,
                            access_token: str = Cookie(None)
                    ):
    """Update card in safebox"""
    status = "OK"
    detail = "Nothing yet"
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
        
    except Exception as exc:
        response = RedirectResponse(url="/", status_code=302)
        return response
    
    
    # This is where we can do specialized handling for records that need to be transmittee

    try:
        acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
        await acorn_obj.load_data()
        await acorn_obj.put_record(record_name=update_card.title,record_value=update_card.content, record_kind=update_card.final_kind)
        detail = "Update successful!"
    except Exception as e:
        status = "ERROR"
        detail = f"Error: {e}"
    

    return {"status": status, "detail": detail}  

@router.post("/deletecard", tags=["safebox", "protected"])
async def delete_card(         request: Request, 
                            delete_card: deleteCard,
                            access_token: str = Cookie(None)
                    ):
    """Delete card from safebox"""
    status = "OK"
    detail = "Nothing yet"
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
        
    except Exception as exc:
        response = RedirectResponse(url="/", status_code=302)
        return response
    
    try:
        acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
        await acorn_obj.load_data()
        msg_out = await acorn_obj.delete_record(label=delete_card.title, record_kind=delete_card.kind)
        detail = f"Success! {msg_out}"
    except Exception as e:
        status = "ERROR"
        detail = f"Error: {e}"
    

    return {"status": status, "detail": detail} 

@router.post("/setcustomhandle", tags=["safebox", "protected"])
async def set_custom_handle(   request: Request, 
                            custom_handle: customHandle,
                            access_token: str = Cookie(None)
                    ):
    """Protected access to private data stored in home relay"""
    status = "OK"
    detail =""
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
        
    except Exception as exc:
        response = RedirectResponse(url="/", status_code=302)
        return response
    

    
    if custom_handle.custom_handle:
        
        cust_db = custom_handle.custom_handle.lower().strip()
        if validate_local_part(cust_db):
            try:
                with Session(engine) as session:   
                                
                    safebox_found.custom_handle = cust_db
                    session.add(safebox_found)
                    session.commit() 
                    detail = f"Congratulations, you now have {cust_db}@{request.url.hostname}!"
                
            except Exception as e:
                status = "ERROR"
                detail = f"Custom handle maybe taken?"  
        else:
            status = "ERROR"
            detail = f"Handle has invalid characters, try again??" 
        
    
      


    return {"status": status, "detail": detail }  

@router.post("/setownerdata", tags=["safebox", "protected"])
async def set_owner_data(   request: Request, 
                            owner_data: ownerData,
                            acorn_obj: Acorn = Depends(get_acorn)
                    ):
    #TODO confirm this function 
    """Protected access to private data stored in home relay"""
    status = "OK"
    msg_out ="success!"

    
    if owner_data.local_currency:
        owner_data.local_currency = owner_data.local_currency.upper().strip()
        if owner_data.local_currency not in settings.SUPPORTED_CURRENCIES:
            return {"status": "ERROR", "detail": "Not a supported currency!" }
    
        try:
  
            await acorn_obj.set_owner_data(local_currency=owner_data.local_currency, npub=owner_data.npub)
            with Session(engine) as session:  
                statement = select(RegisteredSafebox).where(RegisteredSafebox.npub==acorn_obj.pubkey_bech32)
                safeboxes = session.exec(statement)
                safebox_found = safeboxes.first()               
                safebox_found.currency_code = owner_data.local_currency
                session.add(safebox_found)
                session.commit() 
            msg_out = "success!"
        except Exception as exc:
            return {"status": "ERROR", "detail": "Owner update error, maybe bad npub format?" }
   
            
    if owner_data.npub:
            
        try:

            await acorn_obj.set_owner_data(npub=owner_data.npub)
            with Session(engine) as session:   
                statement = select(RegisteredSafebox).where(RegisteredSafebox.npub==acorn_obj.pubkey_bech32)
                safeboxes = session.exec(statement)
                safebox_found = safeboxes.first()               
                safebox_found.owner = owner_data.npub
                session.add(safebox_found)
                session.commit() 
            
                

        except Exception as e:
            msg_out = f"Error: {e}"
            status = "ERROR"
         
        msg_out = msg_out 


    return {"status": status, "detail": msg_out }  

@router.get("/nprofile", tags=["safebox", "protected"])
async def get_nprofile(    request: Request, 
                        access_token: str = Cookie(None)
                    ):
    """Protected access to private data stored in home relay"""
    status = "OK"
    detail = "None"
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
    except Exception as exc:
        response = RedirectResponse(url="/", status_code=302)
        return response
    
    acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    await acorn_obj.load_data()
    # figure out to use the owner key or the wallet key
    # just use the wallet
  
    pub_hex_to_use = acorn_obj.pubkey_hex

    try:
        nprofile = await create_nprofile_from_hex(pub_hex_to_use,[acorn_obj.home_relay])
        detail = nprofile
    except Exception as exc:
        detail = "Not created"

    return {"status": status, "detail": detail}

@router.get("/nauth", tags=["safebox", "protected"])
async def get_nauth(    request: Request, 
                        scope: str = 'transmit',
                        acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to private data stored in home relay"""
    status = "OK"
    detail = "None"

    
    # acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    # await acorn_obj.load_data()
    # figure out to use the owner key or the wallet key
    # just use the wallet
  
    # pub_hex_to_use = acorn_obj.pubkey_hex
    npub_to_use = acorn_obj.pubkey_bech32
    nonce = generate_nonce()
    print(f"nonce: {nonce}")
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.npub==acorn_obj.pubkey_bech32)
        safeboxes = session.exec(statement)
        safebox_for_nonce = safeboxes.first()
        safebox_for_nonce.session_nonce = nonce
        session.add(safebox_for_nonce)
        session.commit()

    try:
        #TODO add in nonce to safebox table and change from naddr to nauth
        # detail = create_nauth_from_npub(    npub_bech32=npub_to_use,
        #                                    relays=[settings.AUTH_RELAY], 
        #                                    nonce=nonce,
        #                                    kind=settings.HEALTH_SECURE_AUTH_KIND,
        #                                    transmittal_relays=[settings.HOME_RELAY],
        #                                    transmittal_kind=settings.HEALTH_SECURE_TRANSMITTAL_KIND
        # )
        
        auth_kind = settings.AUTH_KIND
        auth_relays = settings.AUTH_RELAYS
        detail = create_nauth(  npub=npub_to_use,
                                nonce=nonce,
                                auth_kind=auth_kind,
                                auth_relays=auth_relays,
                                transmittal_kind = settings.TRANSMITTAL_KIND,
                                transmittal_relays=settings.TRANSMITTAL_RELAYS,
                                name=acorn_obj.handle,
                                scope=scope 

                               
                            )
        

        print(f"generated nauth: {detail}")
      
    except Exception as exc:
        detail = "Not created"

    return {"status": status, "detail": detail}

@router.post("/transmitxxx", tags=["safebox", "protected"])
async def transmit_records(        request: Request, 
                                        transmit_consultation: transmitConsultation,
                                        acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """ transmit consultation retreve 32227 records from issuing wallet and send as as 32225 records to nprofile recipient recieving wallet """
    #FIXME This functio should be deprecated
    status = "OK"
    detail = "Nothing yet"
    transmit_consultation.originating_kind = 32227
    transmit_consultation.final_kind = 32225

    


    try:


        parsed_nauth = parse_nauth(transmit_consultation.nauth)
        pubhex = parsed_nauth['values']['pubhex']
        npub_recipient = hex_to_npub(pubhex)
        nonce = parsed_nauth['values']['nonce']
        auth_kind = parsed_nauth['values']['auth_kind']
        auth_relays = parsed_nauth['values']['auth_relays']
        transmittal_pubhex = parsed_nauth['values']['transmittal_pubhex']
        transmittal_npub = hex_to_npub(transmittal_pubhex)
        transmittal_kind = parsed_nauth['values']['transmittal_kind']
        transmittal_relays = parsed_nauth['values']['transmittal_relays']

        # print(f" session nonce {safebox_found.session_nonce} {nonce}")
        #TODO Need to figure out session nonce when authenticating from other side
        # Need to update somewhere in the process leave out for now
        # if safebox_found.session_nonce != nonce:
        #     raise Exception("Invalid session!")

        # acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
        # await acorn_obj.load_data()
        records_to_transmit = await acorn_obj.get_user_records(record_kind=transmit_consultation.originating_kind)
        for each_record in records_to_transmit:
            print(f"transmitting: {each_record['tag']} {each_record['payload']}")

            record_obj = { "tag"   : [each_record['tag']],
                            "type"  : str(transmit_consultation.final_kind),
                            "payload": each_record['payload']
                          }
            print(f"record obj: {record_obj}")
            # await acorn_obj.secure_dm(npub,json.dumps(record_obj), dm_relays=relay)
            # 32227 are transmitted as kind 1060
            
            msg_out = await acorn_obj.secure_transmittal(transmittal_npub,json.dumps(record_obj), dm_relays=transmittal_relays,kind=transmittal_kind)

        detail = f"Successful"
        
    except Exception as e:
        status = "ERROR"
        detail = f"Error: {e}"
    

    return {"status": status, "detail": detail}  

@router.post("/acceptincomingrecord", tags=["safebox", "protected"])
async def accept_incoming_record(       request: Request, 
                                        incoming_record: incomingRecord,
                                        access_token: str = Cookie(None)
                    ):
    """ accept incoming NPI-17 1060 health record and store as a 32225 record"""

    status = "OK"
    detail = "Nothing yet"
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
        
    except Exception as exc:
        response = RedirectResponse(url="/", status_code=302)
        return response
    


    try:
        parsed_result = parse_nauth(incoming_record.nauth)
        npub_initiator = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values']['nonce']
        auth_kind = parsed_result['values'].get("auth_kind", settings.AUTH_KIND)
        auth_relays = parsed_result['values'].get("auth_relays", settings.AUTH_RELAYS)
        transmittal_kind = parsed_result['values'].get("transmittal_kind", settings.TRANSMITTAL_KIND)
        transmittal_relays = parsed_result['values'].get("transmittal_relays",settings.TRANSMITTAL_RELAYS)

        acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
        await acorn_obj.load_data()
        
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
                record_name = f"{each_record['tag'][0][0]} {each_record['created_at']}" 
                record_value = each_record['payload']
                await acorn_obj.put_record(record_name=record_name, record_value=record_value, record_kind=32225)
                
                detail = f"Matched record {incoming_record.id} accepted!"

        
        
    except Exception as e:
        status = "ERROR"
        detail = f"Error: {e}"
    

    return {"status": status, "detail": detail}  


@router.post("/requestnfcpayment", tags=["safebox", "protected"])
async def request_nfc_payment( request: Request, 
                                payment_token: paymentByToken,
                                acorn_obj: Acorn = Depends(get_acorn)
                    ):
   

    k = Keys(config.SERVICE_NSEC) # This is for the trusted service

    status = "PENDING"
    detail = "Request accepted. Waiting for payment settlement..."
    cli_quote: cliQuote
   
    nfc_ecash_clearing = settings.NFC_ECASH_CLEARING
    
    token_to_use = payment_token.payment_token
    
    # token_split = token_to_use.split(':')
    parsed_nembed = parse_nembed_compressed(token_to_use)
    host = parsed_nembed["h"]   
    vault_token = parsed_nembed["k"]

    print(f"payment token: {payment_token}")

    if payment_token.currency == "SAT":
        sat_amount = int(payment_token.amount)
    else:
        local_currency = await get_currency_rate(payment_token.currency.upper())
        print(local_currency.currency_rate)
        sat_amount = int(payment_token.amount* 1e8 // local_currency.currency_rate)
    
    if sat_amount > 0:        
        final_amount = sat_amount
    else:
        final_amount = int(parsed_nembed.get("a", 21))
    
    # This is to confirm that the originator is trusted
    sig = sign_payload(vault_token, k.private_key_hex())
    pubkey = k.public_key_hex()
    headers = { "Content-Type": "application/json"}
    vault_url = f"https://{host}/.well-known/nfcvaultrequestpayment"
    print(f"accept token:  {vault_url} {vault_token} {final_amount} sats")

    status_url = f"https://{host}/.well-known/card-status"
    status_payload = {"token": vault_token, "pubkey": pubkey, "sig": sig}
    async with httpx.AsyncClient(timeout=10.0) as client:
        status_resp = await client.post(url=status_url, json=status_payload, headers=headers)
        if status_resp.status_code != 200:
            detail_msg = "Card validation failed"
            try:
                detail_msg = status_resp.json().get("detail", detail_msg)
            except Exception:
                pass
            return {"status": "ERROR", "detail": detail_msg}

    if nfc_ecash_clearing:
        print("do ecash clearing")
        detail = "NFC ecash payment request accepted. Waiting for completion...";
        submit_data = { "ln_invoice": None, 
                        "token": vault_token, 
                        "amount": final_amount,
                        "tendered_amount": payment_token.amount,
                        "tendered_currency": payment_token.currency,                    
                        "pubkey": pubkey, 
                        "nfc_ecash_clearing": nfc_ecash_clearing,
                        "recipient_pubkey": acorn_obj.pubkey_hex,
                        "relays": settings.RELAYS,
                        "sig": sig, 
                        "comment": payment_token.comment  
                        }
        #FIXME Need to get relays to listen
        pass
        settings_url = f"https://{host}/.well-known/settings"
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url=settings_url)
            response.raise_for_status()
            response_json = response.json()
        print(response_json)
        ecash_relays = response_json.get("ecash_relays", settings.ECASH_RELAYS)
        async def _notify(payload: dict):
            await notify_user(acorn_obj.pubkey_bech32, payload)

        task = asyncio.create_task(
            handle_ecash(acorn_obj=acorn_obj, relays=ecash_relays, notify_callback=_notify)
        )

    else:
        print("do lightning clearing")
        
        cli_quote = await asyncio.to_thread(acorn_obj.deposit, amount=final_amount, mint=HOME_MINT)
      

        # need to send off to the vault for processing
        submit_data = { "ln_invoice": cli_quote.invoice, 
                        "token": vault_token, 
                        "amount": final_amount,
                        "tendered_amount": payment_token.amount,
                        "tendered_currency": payment_token.currency,                    
                        "pubkey": pubkey, 
                        "nfc_ecash_clearing": nfc_ecash_clearing,
                        "sig": sig, 
                        "comment": payment_token.comment  
                        }
        print(f"data: {submit_data}")
       
        # add in the polling task here
        async def _watch_lightning_settlement() -> None:
            try:
                settled = await handle_payment(
                    acorn_obj=acorn_obj,
                    cli_quote=cli_quote,
                    amount=final_amount,
                    tendered_amount=payment_token.amount,
                    tendered_currency=payment_token.currency,
                    mint=HOME_MINT,
                    comment=payment_token.comment,
                )
                if settled:
                    await notify_user(
                        acorn_obj.pubkey_bech32,
                        {
                            "status": "OK",
                            "action": "nfc_token",
                            "detail": (
                                f"Tendered Amount {payment_token.amount} {payment_token.currency} | "
                                f"Credited {final_amount} sats | Payment complete"
                            ),
                            "balance": acorn_obj.balance,
                        },
                    )
                else:
                    await notify_user(
                        acorn_obj.pubkey_bech32,
                        {
                            "status": "ERROR",
                            "action": "nfc_token",
                            "detail": "Payment not confirmed before timeout.",
                            "balance": acorn_obj.balance,
                        },
                    )
            except Exception as exc:
                logger.exception("NFC lightning settlement watcher failed")
                await notify_user(
                    acorn_obj.pubkey_bech32,
                    {
                        "status": "ERROR",
                        "action": "nfc_token",
                        "detail": f"Payment processing error: {exc}",
                        "balance": acorn_obj.balance,
                    },
                )

        asyncio.create_task(_watch_lightning_settlement())

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url=vault_url, json=submit_data, headers=headers)
            response.raise_for_status()
            response_json = response.json()
    except httpx.TimeoutException:
        return {"status": "ERROR", "detail": "NFC vault request timed out."}
    except httpx.HTTPStatusError as exc:
        detail_msg = f"NFC vault returned HTTP {exc.response.status_code}."
        try:
            detail_msg = exc.response.json().get("detail", detail_msg)
        except ValueError:
            if exc.response.text:
                detail_msg = exc.response.text
        return {"status": "ERROR", "detail": detail_msg}
    except httpx.RequestError:
        return {"status": "ERROR", "detail": "NFC vault network error."}
    except ValueError:
        return {"status": "ERROR", "detail": "NFC vault returned invalid response."}

    print(response_json)
    response_status = response_json.get("status", "ERROR")
    response_detail = response_json.get("detail", detail)
    if response_status == "OK":
        return {"status": "PENDING", "detail": detail}
    return {
        "status": response_status,
        "detail": response_detail,
    }  

@router.post("/paytonfctag", tags=["safebox", "protected"])
async def pay_to_nfc_tag( request: Request, 
                                nfc_pay_out_request: nfcPayOutRequest,
                                acorn_obj: Acorn = Depends(get_acorn)
                    ):
    status = "OK"
    detail = "this is from safebox /paytonfctag"
    nfc_ecash_clearing = settings.NFC_ECASH_CLEARING
    k = Keys(config.SERVICE_NSEC)
    # Forward request with amount to get invoice
    print(f"nembed: {nfc_pay_out_request.nembed}, amount: {nfc_pay_out_request.amount} comment: {nfc_pay_out_request.comment}")

    parsed_nembed = parse_nembed_compressed(nfc_pay_out_request.nembed)
    host = parsed_nembed["h"]
    vault_token = parsed_nembed["k"]
    amount_tag = parsed_nembed["a"]

    # Need to do currency conversion here

    

    if nfc_pay_out_request.currency == "SAT":
        sat_amount = int(nfc_pay_out_request.amount)
    else:
        local_currency = await get_currency_rate(nfc_pay_out_request.currency.upper())
        print(local_currency.currency_rate)
        sat_amount = int(nfc_pay_out_request.amount* 1e8 // local_currency.currency_rate)
    
    if sat_amount > 0:        
        final_amount = sat_amount
    else:
        final_amount = int(parsed_nembed.get("a", 21))
    

    final_amount = sat_amount
    if final_amount == 0:
        final_amount = amount_tag



    vault_url = f"https://{host}/.well-known/nfcpayout"
    headers = { "Content-Type": "application/json"}
    sig = sign_payload(vault_token, k.private_key_hex())
    pubkey = k.public_key_hex()
    nfc_comment = nfc_pay_out_request.comment

    status_url = f"https://{host}/.well-known/card-status"
    status_payload = {"token": vault_token, "pubkey": pubkey, "sig": sig}
    async with httpx.AsyncClient(timeout=10.0) as client:
        status_resp = await client.post(url=status_url, json=status_payload, headers=headers)
        if status_resp.status_code != 200:
            detail_msg = "Card validation failed"
            try:
                detail_msg = status_resp.json().get("detail", detail_msg)
            except Exception:
                pass
            return {"status": "ERROR", "detail": detail_msg}

    if nfc_ecash_clearing:
        print("do nfc ecash clearing")
       

        submit_data = { "token": vault_token, 
                        "amount": final_amount,                        
                        "tendered_amount": nfc_pay_out_request.amount,
                        "tendered_currency": nfc_pay_out_request.currency,
                        "comment": nfc_comment, 
                        "nfc_ecash_clearing": nfc_ecash_clearing,
                        "sig":sig, "pubkey":pubkey }

        # put this in a task
        asyncio.create_task(task_to_send_along_ecash(acorn_obj=acorn_obj, vault_url=vault_url,submit_data=submit_data,headers=headers))



    else:    

        submit_data = { "token": vault_token, 
                        "amount": final_amount, 
                        "tendered_amount": nfc_pay_out_request.amount,
                        "tendered_currency": nfc_pay_out_request.currency,
                        "comment": nfc_comment, 
                        "nfc_ecash_clearing": nfc_ecash_clearing,
                        "sig":sig, "pubkey":pubkey }

        print(f"vault: {vault_url} submit data: {submit_data}" )

        # Put this into a task
        task1 = asyncio.create_task(task_pay_to_nfc_tag(
            acorn_obj=acorn_obj,
            vault_url=vault_url,
            submit_data=submit_data,
            headers=headers,
            nfc_pay_out_request=nfc_pay_out_request,
            final_amount=final_amount
        ))

    ###


    detail = f"Payment of {nfc_pay_out_request.amount} {nfc_pay_out_request.currency} sent."

    return {"status": status, "detail": detail, "comment": nfc_pay_out_request.comment} 


@router.get("/balance", tags=["public", "hx"])
async def hx_balance(request: Request,
                        acorn_obj: Acorn= Depends(get_acorn)):
    
            await acorn_obj.load_data()
            
            return HTMLResponse(f"Balance: {acorn_obj.balance}")

@router.get("/requestqr", tags=["public", "hx"])
async def hx_request_qr(    request: Request,
                            amount: float = Query(...), 
                            select_currency: str = Query(...), 
                            description: str = Query(...),
                            acorn_obj: Acorn = Depends(get_acorn)):
            await acorn_obj.load_data()

            with Session(engine) as session:  
                statement = select(RegisteredSafebox).where(RegisteredSafebox.npub==acorn_obj.pubkey_bech32)
                safeboxes = session.exec(statement)
                safebox_found = safeboxes.first() 

            if safebox_found.custom_handle:
                final_handle = safebox_found.custom_handle
            else:
                final_handle = safebox_found.handle
    
            final_address = f"{final_handle}__{amount}__{select_currency}__{description}@{request.url.hostname}"
            final_url, final_lnurl= lightning_address_to_lnurl(final_address)
            # final_qr = final_address
            final_qr = f"lightning:{final_lnurl}"



            final_txt = f"""<img id=\"request\" src=\"/safebox/qr/{final_qr}\"> <br><br>
                        Request for {amount} {select_currency} for {final_handle}@{request.url.hostname}
                        <br> {final_lnurl} {final_url}
                        """
           
            
            return HTMLResponse(final_txt)

@router.post("/attestationowner", tags=["safebox"])
async def attest_safebox(   request: Request, 
                            attestation_owner:attestationOwner, 
                            acorn_obj: Acorn = Depends(get_acorn)): 
     
     
    print(f"attestation owner: {attestation_owner}")
    try:
        owner_k = Keys(priv_k=attestation_owner.owner_nsec)        
        detail = f"Public key: {owner_k.public_key_bech32()}"
        await acorn_obj.set_owner_data(npub=owner_k.public_key_bech32())
    except Exception as e:
        status = "ERROR"
        detail = "Cannot create key"
        return {"status": status, "detail": detail}

    content = f"Npub holder: {owner_k.public_key_bech32()} has attested ownership of safebox: {acorn_obj.pubkey_bech32}"

    tags = [    ["d", f"{acorn_obj.pubkey_bech32}:safebox-under-control"],
                ["p", f"{acorn_obj.pubkey_hex}"],
                ["v", "valid"]

        ]
    async with ClientPool(settings.RELAYS) as c:  
      

        n_msg = Event(kind=31871,
                      tags=tags,
                    content=content,
                    pub_key=owner_k.public_key_hex())
        n_msg.sign(owner_k.private_key_hex())

        c.publish(n_msg)

    status = "Ok"    
    detail = f"{content}"
    
    
    return {"status": status, "detail": detail}

@router.post("/publishsignedevent", tags=["public"])
async def publish_signed_event( request: Request, 
                                signed_event: signedEvent,
                                acorn_obj: Acorn = Depends(get_acorn)
                                ): 

    status = "Ok"    
    detail = f"published event"
    print(f"signed event {signed_event.signed_event}")
    event_to_publish = Event().load(signed_event.signed_event)
    print(f"{event_to_publish.is_valid()}")
    async with ClientPool(settings.RELAYS) as c: 
        c.publish(event_to_publish)
    
    owner_key = Keys(pub_k=event_to_publish.pub_key)
    print(f"owner key: {owner_key.public_key_bech32()}")
    await acorn_obj.set_owner_data(npub=owner_key.public_key_bech32())

    return {"status": status, "detail": detail} 
