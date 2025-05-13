from fastapi import FastAPI, WebSocket, HTTPException, Depends, Request, APIRouter, Response, Form, Header, Cookie
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
from monstr.util import util_funcs


from app.utils import create_jwt_token, fetch_safebox,extract_leading_numbers, fetch_balance, db_state_change, create_nprofile_from_hex, npub_to_hex, validate_local_part, parse_nostr_bech32, hex_to_npub, create_naddr_from_npub,create_nprofile_from_npub, generate_nonce, create_nauth_from_npub, create_nauth, parse_nauth, get_safebox, get_acorn
from sqlmodel import Field, Session, SQLModel, create_engine, select
from app.appmodels import RegisteredSafebox, CurrencyRate, lnPayAddress, lnPayInvoice, lnInvoice, ecashRequest, ecashAccept, ownerData, customHandle, addCard, deleteCard, updateCard, transmitConsultation, incomingRecord
from app.config import Settings
from app.tasks import service_poll_for_payment, invoice_poll_for_payment
from app.rates import get_currency_rate

import logging, jwt

HOME_MINT = "https://mint.nimo.cash"
MINTS = ['https://mint.nimo.cash']
settings = Settings()

templates = Jinja2Templates(directory="app/templates")


router = APIRouter()

engine = create_engine(settings.DATABASE)
# SQLModel.metadata.create_all(engine,checkfirst=True)


##########################
# Functions that need be part part of the module
async def listen_for_request(acorn_obj: Acorn, kind: int = 1060,since_now:int=None, relays: List=None):
   
    
    

    records_out = await acorn_obj.get_user_records(record_kind=kind, since=since_now, relays=relays)
    
    
    return records_out[0]["payload"]


#################################

@router.post("/login", tags=["safebox"])
async def login(request: Request, access_key: str = Form()):


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
                return templates.TemplateResponse(  "welcome.html", 
                                        {   "request": request, 
                                            "title": "Welcome Page", 
                                            "branding": settings.BRANDING,
                                            "branding_message": settings.BRANDING_RETRY})
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
                
                return templates.TemplateResponse(  "welcome.html", 
                                        {   "request": request, 
                                            "title": "Welcome Page", 
                                            "branding": settings.BRANDING,
                                            "branding_message": settings.BRANDING_RETRY})
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
        secure=False,  # Set to True in production to enforce HTTPS
        samesite="Lax",  # Protect against CSRF
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

@router.get("/access", tags=["safebox", "protected"])
async def protected_route(    request: Request, 
                        onboard: bool = False, 
                        action_mode:str=None, 
                        action_data: str = None,
                        action_amount: int = None,
                        action_comment: str = None,
                        acorn_obj = Depends(get_acorn)
                    ):

    if not acorn_obj:
        return RedirectResponse(url="/")


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
        except:
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
                                            "branding": settings.BRANDING,
                                            "onboard": onboard,
                                            "action_mode": action_mode,
                                            "action_data": action_data,
                                            "action_amount": action_amount,
                                            "action_comment": action_comment

                                        })
    

@router.post("/payaddress", tags=["protected"])
async def ln_pay_address(   request: Request, 
                            ln_pay: lnPayAddress,
                            acorn_obj: Acorn = Depends(get_acorn)):
    msg_out ="No payment"

    if ln_pay.currency == "SAT":
        sat_amount = int(ln_pay.amount)
    else:
        local_currency = await get_currency_rate(ln_pay.currency.upper())
        print(local_currency.currency_rate)
        sat_amount = int(ln_pay.amount* 1e8 // local_currency.currency_rate)

    # check to see if address is local only  

    if '@' not in ln_pay.address:
        pass
        final_address = f"{ln_pay.address.strip().lower()}@{request.url.hostname}"
    else:
        final_address = ln_pay.address.strip().lower()

    try:
        

        msg_out, final_fees = await acorn_obj.pay_multi(amount=sat_amount,lnaddress=final_address,comment=ln_pay.comment)
        if settings.WALLET_SWAP_MODE:
            print("doing wallet swap")
            await acorn_obj.swap_multi_consolidate()
        await acorn_obj.add_tx_history(tx_type='D',amount=sat_amount,comment=ln_pay.comment, fees=final_fees)
    except Exception as e:
        return {f"detail": f"error {e}"}



    return {"detail": msg_out}

@router.post("/payinvoice", tags=["protected"])
async def ln_pay_invoice(   request: Request, 
                        ln_invoice: lnPayInvoice,
                        acorn_obj = Depends(get_acorn)):
    msg_out ="No payment"
    try:
        # safebox_found = await fetch_safebox(access_token=access_token)
        # acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
        # await acorn_obj.load_data()

        msg_out, final_fees = await  acorn_obj.pay_multi_invoice(lninvoice=ln_invoice.invoice, comment=ln_invoice.comment)
        decoded_invoice = bolt11.decode(ln_invoice.invoice)
       
        print(f"decoded invoice: {decoded_invoice}")
        amount = decoded_invoice.amount_msat//1000
        description = decoded_invoice.description

        await acorn_obj.add_tx_history(tx_type='D',amount=amount,comment=description)
       

    except Exception as e:
        return {f"detail": "error {e}"}


    
    return {"detail": msg_out}

@router.post("/issueecash", tags=["protected"])
async def issue_ecash(   request: Request, 
                        ecash_request: ecashRequest,
                        acorn_obj = Depends(get_acorn)):
    msg_out ="No payment"
    try:
        # safebox_found = await fetch_safebox(access_token=access_token)
        # acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
        # await acorn_obj.load_data()

        # msg_out = await  acorn_obj.pay_multi_invoice(lninvoice=ln_invoice.invoice, comment=ln_invoice.comment)
        msg_out = await acorn_obj.issue_token(ecash_request.amount)
    except Exception as e:
        return {    "status": "ERROR",
                    f"detail": "error {e}"}


    
    return {    "status": "OK",
                "detail": msg_out
            }

@router.post("/acceptecash", tags=["protected"])
async def accept_ecash(   request: Request, 
                        ecash_accept: ecashAccept,
                        acorn_obj = Depends(get_acorn)):
    msg_out ="No payment"
    try:
        # safebox_found = await fetch_safebox(access_token=access_token)
        # acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
        # await acorn_obj.load_data()       
        
        msg_out = await acorn_obj.accept_token(ecash_accept.ecash_token)
    except Exception as e:
        return {    "status": "ERROR",
                    "detail": f"error {e}"}


    
    return {    "status": "OK",
                "detail": msg_out
            }

@router.post("/invoice", tags=["protected"])
async def ln_invoice_payment(   request: Request, 
                        ln_invoice: lnInvoice,
                        access_token: str = Cookie(None)):
    msg_out ="No payment"
    if ln_invoice.currency == "SAT":
        sat_amount = int(ln_invoice.amount)
    else:
        local_currency = await get_currency_rate(ln_invoice.currency.upper())
        print(local_currency.currency_rate)
        sat_amount = int(ln_invoice.amount* 1e8 // local_currency.currency_rate)
    
    try:
        safebox_found = await fetch_safebox(access_token=access_token)

        
    except Exception as e:
        return {f"status": "error {e}"}
    

    acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    await acorn_obj.load_data()
    cli_quote = acorn_obj.deposit(amount=sat_amount )   


    task2 = asyncio.create_task(invoice_poll_for_payment(acorn_obj=acorn_obj, safebox_found=safebox_found,quote=cli_quote.quote, amount=sat_amount, mint=HOME_MINT))
    
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
        
    except:
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

@router.get("/txhistory", tags=["safebox", "protected"])
async def my_tx_history(    request: Request,
                                
                            access_token: str = Cookie(None)
                    ):
    """Protected access to private data stored in home relay"""
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
    except:
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

@router.get("/healthconsult", tags=["safebox", "protected"])
async def do_health_consult(      request: Request,
                                private_mode:str = "consult", 
                                kind:int = 32227,   
                                nprofile:str = None, 
                                nauth: str = None,                            
                                acorn_obj = Depends(get_acorn)
                    ):
    """Protected access to consulting recods in home relay"""
    nprofile_parse = None
    auth_msg = None


    user_records = await acorn_obj.get_user_records(record_kind=kind)
    
    if nprofile:
        nprofile_parse = parse_nostr_bech32(nprofile)
        pass

    if nauth:
        
        print(f"nauth from do consult {nauth}")


        parsed_result = parse_nauth(nauth)
        npub_initiator = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values']['nonce']
        auth_kind = parsed_result['values'].get("auth_kind", settings.AUTH_KIND)
        auth_relays = parsed_result['values'].get("auth_relays", settings.AUTH_RELAYS)
        transmittal_kind = parsed_result['values'].get("transmittal_kind", settings.TRANSMITTAL_KIND)
        transmittal_relays = parsed_result['values'].get("transmittal_relays",settings.TRANSMITTAL_RELAYS)
        scope = parsed_result['values'].get("scope")
    
        #TODO  transmittal npub from nauth

        auth_msg = create_nauth(    npub=acorn_obj.pubkey_bech32,
                                    nonce=nonce,
                                    auth_kind= auth_kind,
                                    auth_relays=auth_relays,
                                    transmittal_npub=npub_initiator,
                                    transmittal_kind=transmittal_kind,
                                    transmittal_relays=transmittal_relays,
                                    name=acorn_obj.handle,
                                    scope='transmit',
                                    grant=scope
        )

        print(f"do consult initiator npub: {npub_initiator} and nonce: {nonce} auth relays: {auth_kind} auth kind: {auth_kind} transmittal relays: {transmittal_relays} transmittal kind: {transmittal_kind}")

        
        # send the recipient nauth message
        msg_out = await acorn_obj.secure_transmittal(nrecipient=npub_initiator,message=auth_msg,dm_relays=auth_relays,kind=auth_kind)

    else:
       pass
    

    return templates.TemplateResponse(  "healthconsult.html", 
                                        {   "request": request,
                                           
                                            "user_records": user_records,
                                            "record_kind": kind,
                                            "private_mode": private_mode,
                                            "client_nprofile": nprofile,
                                            "client_nprofile_parse": nprofile_parse,
                                            "client_nauth": auth_msg

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
    except:
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
    nauth_response = None
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
    except:
        response = RedirectResponse(url="/", status_code=302)
        return response
    
    acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    await acorn_obj.load_data()
    try:
        health_records = await acorn_obj.get_user_records(record_kind=32225 )
    except:
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
    except:
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
    except:
        response = RedirectResponse(url="/", status_code=302)
        return response
    
    

    return templates.TemplateResponse(  "ecash.html", 
                                        {   "request": request,
                                            "safebox": safebox_found 

                                        })


@router.get("/dangerzone", tags=["safebox", "protected"])
async def my_danger_zone(       request: Request, 
                        access_token: str = Cookie(None)
                    ):
    """Protected access to danger zone"""
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
    except:
        response = RedirectResponse(url="/", status_code=302)
        return response
    
    msg_out = "To be implemented!"

    return templates.TemplateResponse(  "dangerzone.html", 
                                        {   "request": request,
                                            "safebox": safebox_found,
                                            "currencies": settings.SUPPORTED_CURRENCIES 

                                        })


@router.get("/displaycard", tags=["safebox", "protected"])
async def display_card(     request: Request, 
                            card: str = None,
                            kind: int = 37375,
                            action_mode: str = None,
                            acorn_obj = Depends(get_acorn)
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


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, access_token=Cookie()):

    await websocket.accept()

    # access_token = websocket.cookies.get("access_token")
    try:
       
       safebox_found = await fetch_safebox(access_token=access_token)
    except:
        await websocket.close(code=1008)  # Policy violation
        return


    starting_balance = safebox_found.balance
    new_balance = starting_balance
    message = "All payments up to date!"
    status = "SAME"


    while True:
        try:
            await db_state_change()
            
            # data = await websocket.receive_text()
            # print(f"message received: {data}")
            # await websocket.send_text(f"message received {safebox_found.handle} from safebox: {data}")
            
            
            new_balance = await fetch_balance(safebox_found.id)
                


            if new_balance > starting_balance:
                message = f"Payment received! {new_balance-starting_balance} sats."
                status = "RECD"

            elif new_balance < starting_balance:
                message = f"Payment sent! {starting_balance-new_balance} sats."
                status = "SENT"

            elif new_balance == starting_balance:
                message = f"Payment Ready."
                status = "OK"

            fiat_currency = await get_currency_rate(safebox_found.currency_code)
            # currency_code  = fiat_currency.currency_code
            currency_rate = fiat_currency.currency_rate
            currency_symbol = fiat_currency.currency_symbol
            
            # fiat_balance = f"{currency_symbol}{"{:.2f}".format(currency_rate * new_balance / 1e8)} {safebox_found.currency_code}"
            fiat_balance = f"{currency_symbol}{(currency_rate * new_balance / 1e8):.2f} {safebox_found.currency_code}"
            await websocket.send_json({"balance":new_balance,"fiat_balance":fiat_balance, "message": message, "status": status})
            starting_balance = new_balance
          
            
           
            
        
        except Exception as e:
            print(f"Websocket message: {e}")
            break
        
        
        
    print("websocket connection closed")

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
            except:
                client_nauth=None
            

            
            # parsed_nauth = parse_nauth(client_nauth)
            # name = parsed_nauth['name']
            # print(f"client nauth {client_nauth}")
            

            if client_nauth != nauth_old: 
                parsed_nauth = parse_nauth(client_nauth)
                transmittal_kind = parsed_nauth['values'].get('transmittal_kind')
                transmittal_relays = parsed_nauth['values'].get('transmittal_relays')
                nprofile = {'nauth': client_nauth, 'name': 'safebox user', 'transmittal_kind': transmittal_kind, "transmittal_relays": transmittal_relays}
                print(f"send {client_nauth}") 
                await websocket.send_json(nprofile)
                nauth_old = client_nauth
                break
           
        
        except Exception as e:
            print(f"Websocket message: {e}")
            break
        
        await asyncio.sleep(5)
        
        
    print("websocket connection closed")

@router.get("/getrecords", tags=["safebox", "protected"])
async def get_records(      request: Request, 
                            kind: str = 37375,
                            access_token: str = Cookie(None)
                    ):
    """Protected access to private data stored in home relay"""
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
        
    except:
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
        
    except:
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
        
    except:
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
        
    except:
        response = RedirectResponse(url="/", status_code=302)
        return response
    
    try:
        acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
        await acorn_obj.load_data()
        msg_out = await acorn_obj.delete_wallet_info(label=delete_card.title, record_kind=delete_card.kind)
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
        
    except:
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
        except:
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
    except:
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
    except:
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
      
    except:
        detail = "Not created"

    return {"status": status, "detail": detail}

@router.post("/transmit", tags=["safebox", "protected"])
async def transmit_records(        request: Request, 
                                        transmit_consultation: transmitConsultation,
                                        acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """ transmit consultation retreve 32227 records from issuing wallet and send as as 32225 records to nprofile recipient recieving wallet """

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
        
    except:
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


