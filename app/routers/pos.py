from fastapi import FastAPI,  HTTPException, Depends, Request, APIRouter, Response, Form, Header, Cookie, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, StreamingResponse

from pydantic import BaseModel
from typing import Optional, List
from fastapi.templating import Jinja2Templates
import asyncio,qrcode, io, urllib

from datetime import datetime, timedelta, timezone
from safebox.acorn import Acorn
from time import sleep
import json
from monstr.util import util_funcs
from monstr.encrypt import Keys
import ipinfo
import requests


from app.utils import create_jwt_token, fetch_safebox,extract_leading_numbers, fetch_balance, db_state_change, create_nprofile_from_hex, npub_to_hex, validate_local_part, parse_nostr_bech32, hex_to_npub, get_acorn,create_naddr_from_npub,create_nprofile_from_npub, generate_nonce, create_nauth_from_npub, create_nauth, parse_nauth, fetch_access_token, fetch_safebox_by_access_key, parse_nembed_compressed, sign_payload, fetch_safebox_by_handle
from sqlmodel import Field, Session, SQLModel, create_engine, select
from app.appmodels import RegisteredSafebox, CurrencyRate, lnPayAddress, lnPayInvoice, lnInvoice, ecashRequest, ecashAccept, ownerData, customHandle, addCard, deleteCard, updateCard, transmitConsultation, incomingRecord
from app.config import Settings, ConfigWithFallback
from app.tasks import service_poll_for_payment, invoice_poll_for_payment
from app.appmodels import lnPOSInvoice, lnPOSInfo
from app.rates import get_currency_rate
from app.tasks import handle_payment, handle_ecash

import logging, jwt
import time



settings = Settings()
config = ConfigWithFallback()

templates = Jinja2Templates(directory="app/templates")


router = APIRouter()

engine = create_engine(settings.DATABASE)



@router.get("/", tags=["pos"]) 
async def pos_main (    request: Request, 
                        acorn_obj = Depends(get_acorn)
                    ):
    
    return templates.TemplateResponse("pos.html", {"request": request, "expression": ""})

@router.post("/calculate", response_class=HTMLResponse)
async def calculate(request: Request, expression: str = Form(...)):
    try:
        # WARNING: `eval` should be avoided or sandboxed in production
        result = eval(expression)
    except Exception:
        result = "Error"
    return templates.TemplateResponse("result.html", {"request": request, "expression": str(result)})

@router.post("/accesstoken", tags=["pos"])
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


@router.post("/invoice", tags=["pos"])
async def ln_invoice_payment(   request: Request, 
                        ln_invoice: lnPOSInvoice
                        ):
    
    safebox_found = await fetch_safebox(access_token=ln_invoice.access_token)
    acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
    await acorn_obj.load_data()
    msg_out ="No payment"

    if ln_invoice.currency == "SAT":
        sat_amount = int(ln_invoice.amount)
    else:
        local_currency = await get_currency_rate(ln_invoice.currency.upper())
        print(local_currency.currency_rate)
        sat_amount = int(ln_invoice.amount* 1e8 // local_currency.currency_rate)
    
    

    cli_quote = acorn_obj.deposit(amount=sat_amount, mint=settings.HOME_MINT )   

    task = asyncio.create_task(handle_payment(acorn_obj=acorn_obj,cli_quote=cli_quote, amount=sat_amount, tendered_amount= ln_invoice.amount, tendered_currency= ln_invoice.currency, comment=ln_invoice.comment, mint=settings.HOME_MINT))

   
    
    return {"status": "ok", "invoice": cli_quote.invoice}

@router.post("/info", tags=["pos"])
async def info(   request: Request, 
                        ln_pos: lnPOSInfo
                        ):
    
    try:
        safebox_found = await fetch_safebox(access_token=ln_pos.access_token)
        acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
        await acorn_obj.load_data()
    except:
        return {"status": "ERROR", "detail": "Not found"}
       
    
    return {    "status": "OK", 
                "detail": "Found", 
                "handle": acorn_obj.handle,
                "balance": acorn_obj.balance}


@router.websocket("/ws")
async def websocket_endpoint(   websocket: WebSocket 
                             ):

    acorn_obj: Acorn = None
    await websocket.accept()

    await websocket.send_json({ "status":"OK",
                                "action": "init",
                                "detail":"Please connect to safebox!"})
    try:
        while True:
            data = await websocket.receive_text()  # raw message
            try:
                message = json.loads(data)  # parse JSON
                logging.info(f"Received message: {message}")
                print(f"Received message: {message}")



                # Example: handle specific message types
                if message.get("action") == "access_key":
                    access_key = message.get("value")
                    print("access key!")
                    

                    try:
                        safebox_found = await fetch_safebox_by_access_key(access_key=access_key)
                        acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
                        await acorn_obj.load_data()
                        await websocket.send_json({"status": "OK", "action": "access_key", "detail": f"Connected to: {acorn_obj.handle}"})
                    except:
                        await websocket.send_json({"status": "ERROR", "detail": "Not found"})
                    
                elif message.get("action") == "access_token":
                    access_token = message.get("value")
                    print("access token")
                    pass
                    try:
                        safebox_found = await fetch_safebox(access_token=access_token)
                        acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
                        await acorn_obj.load_data()
                        await websocket.send_json({"status": "OK", "action": "access_token", "detail": f"Logged in as: {acorn_obj.handle}"})
                    except:
                        await websocket.send_json({"status": "ERROR", "detail": "Not found"})
                
                elif message.get("action") == "handle":
                    handle = message.get("value")
                    print("handle")
                    pass
                    try:
                        safebox_found = await fetch_safebox_by_handle(handle=handle)
                        acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
                        await acorn_obj.load_data()
                        await websocket.send_json({"status": "OK", "action": "handle", "detail": f"Logged in as: {acorn_obj.handle}"})
                    except:
                        await websocket.send_json({"status": "ERROR", "detail": "Not found"})
                    
                elif message.get("action") == "get_balance":
                    if acorn_obj:
                        await acorn_obj.load_data()
                        await websocket.send_json({"status": "OK", "action": "get_balance", "detail": acorn_obj.balance})
                    else:
                        await websocket.send_json({"status": "ERROR", "detail": "Not found"})

                elif message.get("action") == "nfc_token":
                    nfc_token = message.get("value")
                    nfc_amount = message.get("amount")
                    nfc_currency = message.get("currency")
                    nfc_comment = message.get("comment")
                    nfc_pin = message.get("pin")
                    parsed_nembed = parse_nembed_compressed(nfc_token)

                    
                    await websocket.send_json({"status": "OK", "action": "nfc_token", "detail": "Processing payment..."})
                    if nfc_currency == "SAT":
                        sat_amount = int(nfc_amount)
                    else:
                        local_currency = await get_currency_rate(nfc_currency.upper())
                        print(local_currency.currency_rate)
                        sat_amount = int(nfc_amount* 1e8 // local_currency.currency_rate)
    
                    if sat_amount > 0:        
                        final_amount = sat_amount
                    else:
                        final_amount = int(parsed_nembed.get("a", 21))
                    
                    print(f"nfc_token: {nfc_token} {nfc_amount}/{sat_amount} {nfc_currency} {parsed_nembed}")

                    k = Keys(config.SERVICE_NSEC) # This is for the trusted service
                    host = parsed_nembed["h"]   
                    vault_token = parsed_nembed["k"]
                    # This is to confirm that the originator is trusted
                    sig = sign_payload(vault_token, k.private_key_hex())
                    pubkey = k.public_key_hex()
                    headers = { "Content-Type": "application/json"}
                    vault_url = f"https://{host}/.well-known/nfcvaultrequestpayment"
                    print(f"accept token:  {vault_url} {vault_token} {final_amount} sats pin:{nfc_pin}")
                    nfc_ecash_clearing = True
                    submit_data = { "ln_invoice": None, 
                        "token": vault_token, 
                        "amount": final_amount,
                        "tendered_amount": nfc_amount,
                        "tendered_currency": nfc_currency,                    
                        "pubkey": pubkey, 
                        "nfc_ecash_clearing": nfc_ecash_clearing,
                        "recipient_pubkey": acorn_obj.pubkey_hex,
                        "relays": settings.RELAYS,
                        "sig": sig, 
                        "comment": nfc_comment  
                        }
                    task = asyncio.create_task(handle_ecash(acorn_obj=acorn_obj))
                    response = requests.post(url=vault_url, json=submit_data, headers=headers)        
                    print(response.json())
                    await websocket.send_json({"status": "OK", "action": "nfc_token", "detail": f"Payment being sent to {acorn_obj.handle}!"})
                    



                else:
                    await websocket.send_json({"error": "unknown action"})

            except json.JSONDecodeError:
                await websocket.send_text("Invalid JSON format")

    except WebSocketDisconnect:
        logging.info("WebSocket disconnected")
    
    