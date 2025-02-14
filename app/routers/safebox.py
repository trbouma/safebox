from fastapi import FastAPI, WebSocket, HTTPException, Depends, Request, APIRouter, Response, Form, Header, Cookie
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, StreamingResponse

from pydantic import BaseModel
from typing import Optional
from fastapi.templating import Jinja2Templates
import asyncio,qrcode, io, urllib

from datetime import datetime, timedelta, timezone
from safebox.acorn import Acorn
from time import sleep
import json
from monstr.util import util_funcs


from app.utils import create_jwt_token, fetch_safebox,extract_leading_numbers, fetch_balance, db_state_change, create_nprofile_from_hex, npub_to_hex, validate_local_part, parse_nostr_bech32, hex_to_npub, create_naddr_from_npub,create_nprofile_from_npub, generate_nonce, create_nauth_from_npub, create_nauth, parse_nauth
from sqlmodel import Field, Session, SQLModel, create_engine, select
from app.appmodels import RegisteredSafebox, CurrencyRate, lnPayAddress, lnPayInvoice, lnInvoice, ecashRequest, ecashAccept, ownerData, customHandle, addCard, deleteCard, updateCard, transmitConsultation, incomingRecord
from app.config import Settings
from app.tasks import service_poll_for_payment, invoice_poll_for_payment

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
async def listen_for_request(acorn_obj: Acorn, kind: int = 1060,since_now:int=None):
   
    
    

    records_out = await acorn_obj.get_user_records(record_kind=kind, since=since_now)
    
    
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
                        access_token: str = Cookie(None)
                    ):
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
    except:
        response = RedirectResponse(url="/", status_code=302)
        return response
        
    if safebox_found.custom_handle:
        lightning_address = f"{safebox_found.custom_handle}@{request.url.hostname}"
    else:
        lightning_address = f"{safebox_found.handle}@{request.url.hostname}"
        
    #TODO Update balance here

    print(f"onboard {onboard} action_mode {action_mode} acquire_data: {action_data}")
    acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
    await acorn_obj.load_data()
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.handle ==safebox_found.handle)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.one()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            raise ValueError("Could not find safebox!")
        statement = select(CurrencyRate).where(CurrencyRate.currency_code==acorn_obj.local_currency)
        currencies = session.exec(statement)
        # currency_found = currencies.first()
        currency_found=None
        if currency_found:
            currency_code = acorn_obj.local_currency
            currency_rate = currency_found.currency_rate
        else:
            currency_code = "SAT"
            currency_rate = 1e8
       

        safebox_found.balance = acorn_obj.balance
        session.add(safebox_found)
        session.commit()

    # Token is valid, proceed
    return templates.TemplateResponse(  "access.html", 
                                        {   "request": request, 
                                            "title": "Welcome Page", 
                                            "message": "Welcome to Safebox Web!", 
                                            "safebox":acorn_obj, 
                                            "currency_code": currency_code,
                                            "currency_rate": currency_rate,
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
                        access_token: str = Cookie(None)):
    msg_out ="No payment"
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
        acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
        await acorn_obj.load_data()
        msg_out = await acorn_obj.pay_multi(amount=ln_pay.amount,lnaddress=ln_pay.address,comment=ln_pay.comment)
    except Exception as e:
        return {f"detail": f"error {e}"}

    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.handle ==safebox_found.handle)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.one()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            raise ValueError("Could not find safebox!")
    
       

        safebox_found.balance = acorn_obj.balance
        session.add(safebox_found)
        session.commit()

    return {"detail": msg_out}

@router.post("/payinvoice", tags=["protected"])
async def ln_pay_invoice(   request: Request, 
                        ln_invoice: lnPayInvoice,
                        access_token: str = Cookie(None)):
    msg_out ="No payment"
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
        acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
        await acorn_obj.load_data()

        msg_out = await  acorn_obj.pay_multi_invoice(lninvoice=ln_invoice.invoice, comment=ln_invoice.comment)
    except Exception as e:
        return {f"detail": "error {e}"}

    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.handle ==safebox_found.handle)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.one()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            raise ValueError("Could not find safebox!")
    
       

        safebox_found.balance = acorn_obj.balance
        session.add(safebox_found)
        session.commit()
    
    return {"detail": msg_out}

@router.post("/issueecash", tags=["protected"])
async def issue_ecash(   request: Request, 
                        ecash_request: ecashRequest,
                        access_token: str = Cookie(None)):
    msg_out ="No payment"
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
        acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
        await acorn_obj.load_data()

        # msg_out = await  acorn_obj.pay_multi_invoice(lninvoice=ln_invoice.invoice, comment=ln_invoice.comment)
        msg_out = await acorn_obj.issue_token(ecash_request.amount)
    except Exception as e:
        return {    "status": "ERROR",
                    f"detail": "error {e}"}

    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.handle ==safebox_found.handle)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.one()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            raise ValueError("Could not find safebox!")
    
       
        #FIXME I might need the session add
        safebox_found.balance = acorn_obj.balance
        session.add(safebox_found)
        session.commit()
    
    return {    "status": "OK",
                "detail": msg_out
            }

@router.post("/acceptecash", tags=["protected"])
async def accept_ecash(   request: Request, 
                        ecash_accept: ecashAccept,
                        access_token: str = Cookie(None)):
    msg_out ="No payment"
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
        acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
        await acorn_obj.load_data()

       
        
        msg_out = await acorn_obj.accept_token(ecash_accept.ecash_token)
    except Exception as e:
        return {    "status": "ERROR",
                    "detail": f"error {e}"}

    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.handle ==safebox_found.handle)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.one()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            raise ValueError("Could not find safebox!")
    
       

        safebox_found.balance = acorn_obj.balance
        session.add(safebox_found)
        session.commit()
    
    return {    "status": "OK",
                "detail": msg_out
            }

@router.post("/invoice", tags=["protected"])
async def ln_invoice_payment(   request: Request, 
                        ln_invoice: lnInvoice,
                        access_token: str = Cookie(None)):
    msg_out ="No payment"
    try:
        safebox_found = await fetch_safebox(access_token=access_token)

        
    except Exception as e:
        return {f"status": "error {e}"}
    

    acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    await acorn_obj.load_data()
    cli_quote = acorn_obj.deposit(amount=ln_invoice.amount )   

    




    task2 = asyncio.create_task(invoice_poll_for_payment(safebox_found=safebox_found,quote=cli_quote.quote, amount=ln_invoice.amount, mint=HOME_MINT))
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
    user_records = await acorn_obj.get_user_records(record_kind=kind)
    
    referer = urllib.parse.urlparse(request.headers.get("referer")).path

    return templates.TemplateResponse(  "privatedata.html", 
                                        {   "request": request,
                                            "safebox": safebox_found ,
                                            "user_records": user_records,
                                            "private_mode": private_mode,
                                            "referer": referer
                                            })


@router.get("/healthconsult", tags=["safebox", "protected"])
async def do_health_consult(      request: Request,
                                private_mode:str = "consult", 
                                kind:int = 32227,   
                                nprofile:str = None, 
                                nauth: str = None,                            
                                access_token: str = Cookie(None)
                    ):
    """Protected access to consulting recods in home relay"""
    nprofile_parse = None
    auth_msg = None

    try:
        safebox_found = await fetch_safebox(access_token=access_token)
    except:
        response = RedirectResponse(url="/", status_code=302)
        return response
    
    acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    await acorn_obj.load_data()
    user_records = await acorn_obj.get_user_records(record_kind=kind)
    
    if nprofile:
        nprofile_parse = parse_nostr_bech32(nprofile)
        pass

    if nauth:
        print("nauth")


        parsed_result = parse_nauth(nauth)
        npub_recipient = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values']['nonce']
        auth_kind = parsed_result['values'].get("auth_kind")
        auth_relays = parsed_result['values'].get("auth_relays")
        transmittal_kind = parsed_result['values'].get("transmittal_kind")
        transmittal_relays = parsed_result['values'].get("transmittal_relays")
  
        print(f"requesting npub: {npub_recipient} and nonce: {nonce} auth relays: {auth_kind} auth kind: {auth_kind} transmittal relays: {transmittal_relays} transmittal kind: {transmittal_kind}")

        
        auth_msg = create_nauth(    npub=npub_recipient,
                                    nonce=nonce,
                                    auth_kind= auth_kind,
                                    auth_relays=auth_relays,
                                    transmittal_kind=transmittal_kind,
                                    transmittal_relays=transmittal_relays,
                                    name=safebox_found.handle
        )
        
        # send the recipient nauth message
        msg_out = await acorn_obj.secure_transmittal(nrecipient=npub_recipient,message=auth_msg,dm_relays=auth_relays,transmittal_kind=settings.AUTH_KIND)
    

    return templates.TemplateResponse(  "healthconsult.html", 
                                        {   "request": request,
                                            "safebox": safebox_found ,
                                            "user_records": user_records,
                                            "record_kind": kind,
                                            "private_mode": private_mode,
                                            "client_nprofile": nprofile,
                                            "client_nprofile_parse": nprofile_parse,
                                            "client_nauth": auth_msg

                                        })


@router.get("/inbox", tags=["safebox", "protected"])
async def get_inbox(      request: Request,
                                private_mode:str = "consult", 
                                kind:int = 1060,   
                                nprofile:str = None,   
                                naddr: str = None, 
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
    # since = int((datetime.now(timezone.utc)-timedelta(hours=24)).timestamp())
    user_records = await acorn_obj.get_user_records(record_kind=kind)
    
    
    if nprofile:
        nprofile_parse = parse_nostr_bech32(nprofile)
        pass
    
    if naddr:
        print("naddr")
        parsed_result = parse_nostr_bech32(naddr)
        npub = hex_to_npub(parsed_result['values']['pubhex'])
        print(f"requesting npub: {npub}")
        # auth_msg = f"patient: {safebox_found.handle}{ safebox_found.npub} from"
        # msg_out = await acorn_obj.secure_transmittal(nrecipient=npub,message=auth_msg,dm_relays=[safebox_found.home_relay],transmittal_kind=1061)
        # now need to calculate client_nprofile to send
        client_nprofile = create_nprofile_from_npub(acorn_obj.pubkey_bech32, [acorn_obj.home_relay])
        
        auth_msg = client_nprofile
        msg_out = await acorn_obj.secure_transmittal(nrecipient=npub,message=auth_msg,dm_relays=[safebox_found.home_relay],transmittal_kind=settings.AUTH_KIND)

    if nauth:
        
        print("nauth")
        # parsed_result = parse_nauth(nauth)
        # npub = hex_to_npub(parsed_result['values']['pubhex'])
        # nonce = parsed_result['values']['nonce']
        # auth_kind = parsed_result['values'].get("auth_kind")
        # auth_relays = parsed_result['values'].get("auth_relays")
        # transmittal_kind = parsed_result['values'].get("transmittal_kind")
        # transmittal_relays = parsed_result['values'].get("transmittal_relays")
        

    return templates.TemplateResponse(  "inbox.html", 
                                        {   "request": request,
                                            "safebox": safebox_found ,
                                            "user_records": user_records,
                                            "record_kind": kind,
                                            "private_mode": private_mode,
                                            "nprofile": nprofile,
                                            "nprofile_parse": nprofile_parse

                                        })

@router.get("/health", tags=["safebox", "protected"])
async def my_health_data(       request: Request, 
                                nauth: str = None,
                                nonce: str = None,
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
    try:
        health_records = await acorn_obj.get_user_records(record_kind=32225 )
    except:
        health_records = None

    if nauth:
        
        print("nauth")
        # parsed_result = parse_nostr_bech32(nauth)
        # npub = hex_to_npub(parsed_result['values']['pubhex'])
        # nonce = parsed_result['values']['nonce']
        # auth_kind = parsed_result['values'].get("kind")        
        # relays = parsed_result['values'].get("relay")
        # transmittal_relays = parsed_result['values'].get("transmitta_relay")
        # transmittal_kind = parsed_result['values'].get("transmittal_kind")

        parsed_result = parse_nauth(nauth)
        npub = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values']['nonce']
        auth_kind = parsed_result['values'].get("auth_kind")
        auth_relays = parsed_result['values'].get("auth_relays")
        transmittal_kind = parsed_result['values'].get("transmittal_kind")
        transmittal_relays = parsed_result['values'].get("transmittal_relays")
    

        

        print(f"requesting npub: {npub} and nonce: {nonce} auth relays: {auth_kind} auth kind: {auth_kind} transmittal relays: {transmittal_relays} transmittal kind: {transmittal_kind}")
        # auth_msg = f"patient: {safebox_found.handle}{ safebox_found.npub} from"
        # msg_out = await acorn_obj.secure_transmittal(nrecipient=npub,message=auth_msg,dm_relays=[safebox_found.home_relay],transmittal_kind=1061)
        # now need to calculate client_nprofile to send
        # auth_msg = create_nprofile_from_npub(acorn_obj.pubkey_bech32, [acorn_obj.home_relay])
        # auth_msg = create_nauth_from_npub(npub_bech32=acorn_obj.pubkey_bech32,relays=[acorn_obj.home_relay],nonce=nonce,kind=auth_kind)
        
        auth_msg = create_nauth(    npub=acorn_obj.pubkey_bech32,
                                    nonce=nonce,
                                    auth_kind= auth_kind,
                                    auth_relays=auth_relays,
                                    transmittal_kind=transmittal_kind,
                                    transmittal_relays=transmittal_relays,
                                    name=safebox_found.handle
        )
        
        # send the recipient nauth message
        msg_out = await acorn_obj.secure_transmittal(nrecipient=npub,message=auth_msg,dm_relays=auth_relays,transmittal_kind=settings.AUTH_KIND)
    
    return templates.TemplateResponse(  "healthdata.html", 
                                        {   "request": request,
                                            "safebox": safebox_found,
                                            "health_records": health_records ,
                                            "nauth": nauth

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
                                            "safebox": safebox_found 

                                        })


@router.get("/displaycard", tags=["safebox", "protected"])
async def display_card(     request: Request, 
                            card: str = None,
                            kind: int = 37375,
                            action_mode: str = None,
                            access_token: str = Cookie(None)
                    ):
    """Protected access to updating the card"""
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
    except:
        response = RedirectResponse(url="/", status_code=302)
        return response
    
    if action_mode == 'edit':
        acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
        await acorn_obj.load_data()
        record = await acorn_obj.get_record(record_name=card, record_kind=kind)
        
        content = record["payload"]
    elif action_mode =='add':
        card = ""
        content =""
    
    referer = urllib.parse.urlparse(request.headers.get("referer")).path

    return templates.TemplateResponse(  "card.html", 
                                        {   "request": request,
                                            "safebox": safebox_found,
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

            
            await websocket.send_json({"balance":new_balance, "message": message, "status": status})
            starting_balance = new_balance
          
            
           
            
        
        except Exception as e:
            print(f"Websocket message: {e}")
            break
        
        
        
    print("websocket connection closed")

@router.websocket("/wsrequesttransmittal")
async def websocket_requesttransmittal(websocket: WebSocket, access_token=Cookie()):

    await websocket.accept()

    try:
       
       safebox_found = await fetch_safebox(access_token=access_token)
    except:
        await websocket.close(code=1008)  # Policy violation
        return

    acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    await acorn_obj.load_data()

    naddr = safebox_found.npub
    nauth_old = None
    # since_now = None
    since_now = int(datetime.now(timezone.utc).timestamp())

    while True:
        try:
            await acorn_obj.load_data()
            try:
                client_nauth = await listen_for_request(acorn_obj=acorn_obj,kind=settings.AUTH_KIND, since_now=since_now)
            except:
                client_nauth=None
            

            
            # parsed_nauth = parse_nauth(client_nauth)
            # name = parsed_nauth['name']
            # print(f"client nauth {client_nauth}")
            

            if client_nauth != nauth_old: 
                nprofile = {'nauth': client_nauth, 'name': 'safebox user'}
                print(f"send {client_nauth}") 
                await websocket.send_json(nprofile)
                nauth_old = client_nauth
           
        
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
    
    try:
        acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
        await acorn_obj.load_data()
        await acorn_obj.put_record(record_name=update_card.title,record_value=update_card.content, record_kind=update_card.kind)
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
                            access_token: str = Cookie(None)
                    ):
    #TODO confirm this function 
    """Protected access to private data stored in home relay"""
    status = "OK"
    msg_out =""
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
        
    except:
        response = RedirectResponse(url="/", status_code=302)
        return response
    
    if owner_data.local_currency:
        owner_data.local_currency = owner_data.local_currency.upper().strip()
        if owner_data.local_currency not in settings.SUPPORTED_CURRENCIES:
            return {"status": "ERROR", "detail": "Not a supported currency!" }
    
    try:
        acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
        await acorn_obj.load_data()   
        await acorn_obj.set_owner_data(local_currency=owner_data.local_currency, npub=owner_data.npub)
        msg_out = "successful"
    except:
        return {"status": "ERROR", "detail": "Owner update error, maybe bad npub format?" }
   
            
    if owner_data.npub:
            
        try:

            await acorn_obj.set_owner_data(npub=owner_data.npub)
            with Session(engine) as session:                 
                safebox_found.owner = owner_data.npub
                session.add(safebox_found)
                session.commit() 
            
                

        except Exception as e:
            msg_out = f"Error: {e}"
            status = "ERROR"
         
        msg_out = msg_out + " successfully added owner to safebox register!"


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
  
    # pub_hex_to_use = acorn_obj.pubkey_hex
    npub_to_use = acorn_obj.pubkey_bech32
    nonce = generate_nonce()
    print(f"nonce: {nonce}")
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.access_key==safebox_found.access_key)
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
                                name=acorn_obj.handle 

                               
                            )
        

        print(f"nauth: {detail}")
      
    except:
        detail = "Not created"

    return {"status": status, "detail": detail}

@router.post("/transmit", tags=["safebox", "protected"])
async def transmit_records(        request: Request, 
                                        transmit_consultation: transmitConsultation,
                                        access_token: str = Cookie(None)
                    ):
    """ transmit consultation retreve 32227 records from issuing wallet and send as as 32225 records to nprofile recipient recieving wallet """

    status = "OK"
    detail = "Nothing yet"
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
        
    except:
        response = RedirectResponse(url="/", status_code=302)
        return response
    


    try:
        # nprofile_parse = parse_nostr_bech32(transmit_consultation.nauth)        
        # print(nprofile_parse)
        # pubhex = nprofile_parse['values']['pubhex']
        # npub = hex_to_npub(pubhex)
        # relay = pubhex = nprofile_parse['values']['relay']
        # kind = nprofile_parse['values']['kind']
        # print(f"transmit to: {npub} {relay}")

        parsed_nauth = parse_nauth(transmit_consultation.nauth)
        pubhex = parsed_nauth['values']['pubhex']
        npub = hex_to_npub(pubhex)
        nonce = parsed_nauth['values']['nonce']
        auth_kind = parsed_nauth['values']['auth_kind']
        auth_relays = parsed_nauth['values']['auth_relays']
        transmittal_kind = parsed_nauth['values']['transmittal_kind']
        transmittal_relays = parsed_nauth['values']['transmittal_relays']

        print(f" session nonce {safebox_found.session_nonce} {nonce}")
        #TODO Need to figure out session nonce when authenticating from other side
        # Need to update somewhere in the process leave out for now
        # if safebox_found.session_nonce != nonce:
        #     raise Exception("Invalid session!")

        acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
        await acorn_obj.load_data()
        records_to_transmit = await acorn_obj.get_user_records(record_kind=transmit_consultation.kind)
        for each_record in records_to_transmit:
            print(f"transmitting: {each_record['tag']} {each_record['payload']}")

            record_obj = { "tag"   : [each_record['tag']],
                            "type"  : str(transmit_consultation.kind),
                            "payload": each_record['payload']
                          }
            print(f"record obj: {record_obj}")
            # await acorn_obj.secure_dm(npub,json.dumps(record_obj), dm_relays=relay)
            # 32227 are transmitted as kind 1060
            
            await acorn_obj.secure_transmittal(npub,json.dumps(record_obj), dm_relays=transmittal_relays,transmittal_kind=transmittal_kind)

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


        acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
        await acorn_obj.load_data()
        
        records_to_accept = await acorn_obj.get_user_records(record_kind=incoming_record.kind)
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


