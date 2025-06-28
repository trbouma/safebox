from fastapi import Request, APIRouter, Depends, Response, Form, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import StreamingResponse

from pydantic import BaseModel
import random
import string
import asyncio
from datetime import timedelta
import qrcode, io, urllib, json
import hashlib

from sqlmodel import Field, Session, SQLModel, create_engine, select, update
from argon2 import PasswordHasher
import requests

from monstr.encrypt import Keys, NIP44Encrypt, NIP4Encrypt
from monstr.event.event import Event
from monstr.client.client import Client, ClientPool
from safebox.acorn import Acorn

from app.appmodels import RegisteredSafebox, PaymentQuote, recoverIdentity, nwcVault, nfcPayOutVault, proofVault, offerVault
from safebox.models import cliQuote
from app.tasks import service_poll_for_payment, handle_payment
from app.utils import ( create_jwt_token, 
                        send_zap_receipt, 
                        recover_nsec_from_seed, 
                        format_relay_url, 
                        generate_new_identity,
                        generate_pnr,
                        get_acorn,
                        get_acorn_by_npub,
                        sign_payload,
                        verify_payload)

from app.config import Settings

settings = Settings()
templates = Jinja2Templates(directory="app/templates")
password_hasher = PasswordHasher()

# RELAYS = ['wss://relay.getsafebox.app']
RELAYS = settings.RELAYS

MINTS = settings.MINTS
# HOME_RELAY = 'wss://relay.getsafebox.app'
LOGGING_LEVEL = 10
HOME_MINT = settings.HOME_MINT


service_key_obj = Keys(priv_k=settings.SERVICE_SECRET_KEY)

engine = create_engine(settings.DATABASE)
# SQLModel.metadata.create_all(engine, checkfirst=True)


def generate_short_code(length: int = 12) -> str:
    """Generate a simple random short code of given length."""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

router = APIRouter()


   
@router.get("/info", tags=["lnaddress"])
def get_info(request: Request):
    

        

    return {"detail": request.url.hostname}

@router.get("/.well-known/lnurlp/{name}")
def ln_resolve(request: Request, name: str = None, amount: int = None):
    match = False
    ln_callback = f"https://{request.url.hostname}/lnpay/{name}"
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.handle ==name)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
        if safebox_found:
            out_name = safebox_found.handle
            match = True
        else:
            # check for custom handle
            statement = select(RegisteredSafebox).where(RegisteredSafebox.custom_handle ==name)
            safeboxes = session.exec(statement)
            safebox_found = safeboxes.first()
            if safebox_found:
                out_name = safebox_found.handle
                match = True
            if not match:
                raise HTTPException(status_code=404, detail=f"{name} not found")

    ln_response = {     "callback": ln_callback,
                        "minSendable": 1000,
                        "maxSendable": 210000000,
                        "metadata": f"[[\"text/plain\", \"Send Payment to: {name}\"]]",
                        "commentAllowed": 60,                        
                        "allowsNostr" :True,
                        "safebox": True,
                        "nostrPubkey" :     service_key_obj.public_key_hex(),
                        "tag": "payRequest"

                  

    }

    print(request.base_url) 

    return ln_response

@router.get("/lnpay/{name}")
async def ln_pay( amount: float,
            request: Request, 
            name: str,
            nonce: str | None = None,
            comment: str | None = None,
            nostr: str | None = None,
            currency: str | None = None, 
            __n: str | None = None,
            lninvoice: bool = False

            
            ):
    match = False
    sat_amount = int(amount//1000)

    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.handle ==name)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
        if safebox_found:
            out_name = safebox_found.handle

            match = True
        else:
            # check for custom handle
            statement = select(RegisteredSafebox).where(RegisteredSafebox.custom_handle ==name)
            safeboxes = session.exec(statement)
            safebox_found = safeboxes.first()
            if safebox_found:
                out_name = safebox_found.handle

                match = True
        if not match:
                raise HTTPException(status_code=404, detail=f"{name} not found")

    # Update the cache amout   
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.handle ==safebox_found.handle)
        safeboxes = session.exec(statement)
        safebox_update = safeboxes.first()
        safebox_update.balance = safebox_update.balance + sat_amount
        session.add(safebox_update)
        session.commit()

    # Check to see if this a non-custodial safebox
    # If this is the case then accept the payment using service acorn and send the funds
    # via a NIP 17 message to the destination       
    if safebox_found.nsec == None:
        # This is a non-custodial safebox
       
        acorn_obj = Acorn(nsec=settings.SERVICE_SECRET_KEY, relays=RELAYS, mints=MINTS, home_relay=settings.HOME_RELAY, logging_level=settings.LOGGING_LEVEL)
        await acorn_obj.load_data(force_profile_creation=True)
        message = "Payment being sent as a non-custodial payment..."
    
    else:
        acorn_obj = Acorn(nsec=safebox_found.nsec, relays=RELAYS, mints=MINTS, home_relay=safebox_found.home_relay, logging_level=LOGGING_LEVEL)
        await acorn_obj.load_data()
        message = "Payment being sent..."
    
    

    
    cli_quote = acorn_obj.deposit(sat_amount)  
    task = asyncio.create_task(handle_payment(acorn_obj=acorn_obj,cli_quote=cli_quote, amount=sat_amount, mint=HOME_MINT, nostr=nostr, comment=comment))
   
    print(f"current balance is: {acorn_obj.balance}, home relay: {acorn_obj.home_relay}")

   

    success_obj = {     "tag": "message",
                            "message" : message  }

    

    return  {   "pr": cli_quote.invoice,
                "hash": None,
                "routes": [],
                "successAction": success_obj
            } 

    

@router.post("/.well-known/nwcvault", tags=["public"])
async def nwc_vault(request: Request, nwc_vault: nwcVault):
    status = "OK"
    detail = None

   # First, check to see if signature checks out
    if verify_payload(nwc_vault.token, nwc_vault.sig, nwc_vault.pubkey):
        print("Payload is verified!")
 

    k  = Keys(settings.SERVICE_SECRET_KEY)
    my_enc = NIP44Encrypt(k)
    my_enc_NIP4 = NIP4Encrypt(k)
    token_secret = my_enc.decrypt(nwc_vault.token, for_pub_k=k.public_key_hex())
    print(f"token secret {token_secret}")
    k_nwc = Keys(token_secret)
    print(f"send {nwc_vault.ln_invoice} invoice to: {k_nwc.public_key_hex()}")

    pay_instruction = {
    "method": "pay_invoice",
    "params": { 
        "invoice": nwc_vault.ln_invoice,
        "comment": nwc_vault.comment,
        "tendered_amount": nwc_vault.tendered_amount,
        "tendered_currency": nwc_vault.tendered_currency 
            }
        }
    
    payload_encrypt = my_enc_NIP4.encrypt(plain_text=json.dumps(pay_instruction),to_pub_k=k_nwc.public_key_hex())
        
    async with ClientPool(settings.NWC_RELAYS) as c:
                
        #FIXME kind
        n_msg = Event(kind=23194,
                    content=payload_encrypt,
                    pub_key=k.public_key_hex(),
                    tags = [["p",k_nwc.public_key_hex()]]
                    )

        n_msg.sign(k.private_key_hex())
        
        c.publish(n_msg)
        print(f"published to nwc")
        await asyncio.sleep(0.2)


    return {"status": status, "detail": detail}

@router.post("/.well-known/proof", tags=["public"])
async def proof_vault(request: Request, proof_vault: proofVault):
    status = "OK"
    detail = None

   # First, check to see if signature checks out
    if verify_payload(proof_vault.token, proof_vault.sig, proof_vault.pubkey):
        print("Payload is verified!")
 

    k  = Keys(settings.SERVICE_SECRET_KEY)
    my_enc = NIP44Encrypt(k)
    my_enc_NIP4 = NIP4Encrypt(k)
    token_secret = my_enc.decrypt(proof_vault.token, for_pub_k=k.public_key_hex())
    print(f"token secret {token_secret}")
    k_nwc = Keys(token_secret)
    # print(f"send {nwc_vault.ln_invoice} invoice to: {k_nwc.public_key_hex()}")

    wallet_instruction = {
    "method": "present_record",
    "params": { 
        "nauth": proof_vault.nauth,
        "label": proof_vault.label

            }
        }
    
    payload_encrypt = my_enc_NIP4.encrypt(plain_text=json.dumps(wallet_instruction),to_pub_k=k_nwc.public_key_hex())
        
    async with ClientPool(settings.NWC_RELAYS) as c:
                
        #FIXME kind
        n_msg = Event(kind=23194,
                    content=payload_encrypt,
                    pub_key=k.public_key_hex(),
                    tags = [["p",k_nwc.public_key_hex()]]
                    )

        n_msg.sign(k.private_key_hex())
        
        c.publish(n_msg)
        print(f"published to nwc")
        await asyncio.sleep(0.2)


    return {"status": status, "detail": detail}

@router.post("/.well-known/offer", tags=["public"])
async def offer_vault(request: Request, offer_vault: offerVault):
    status = "OK"
    detail = None

   # First, check to see if signature checks out
    if verify_payload(offer_vault.token, offer_vault.sig, offer_vault.pubkey):
        print("Payload is verified!")
 

    k  = Keys(settings.SERVICE_SECRET_KEY)
    my_enc = NIP44Encrypt(k)
    my_enc_NIP4 = NIP4Encrypt(k)
    token_secret = my_enc.decrypt(offer_vault.token, for_pub_k=k.public_key_hex())
    print(f"token secret {token_secret}")
    k_nwc = Keys(token_secret)
    # print(f"send {nwc_vault.ln_invoice} invoice to: {k_nwc.public_key_hex()}")

    wallet_instruction = {
    "method": "offer_record",
    "params": { 
        "nauth": offer_vault.nauth
        

            }
        }
    
    payload_encrypt = my_enc_NIP4.encrypt(plain_text=json.dumps(wallet_instruction),to_pub_k=k_nwc.public_key_hex())
        
    async with ClientPool(settings.NWC_RELAYS) as c:
                
        #FIXME kind
        n_msg = Event(kind=23194,
                    content=payload_encrypt,
                    pub_key=k.public_key_hex(),
                    tags = [["p",k_nwc.public_key_hex()]]
                    )

        n_msg.sign(k.private_key_hex())
        
        c.publish(n_msg)
        print(f"published to nwc")
        await asyncio.sleep(0.2)


    return {"status": status, "detail": detail}

@router.post("/.well-known/nfcpayout", tags=["public"])
async def nfc_pay_out(request: Request, nfc_pay_out: nfcPayOutVault):
    status = "OK"
    detail = "This from lnaddress nfcpayout"

    # First, check to see if signature checks out
    if verify_payload(nfc_pay_out.token, nfc_pay_out.sig, nfc_pay_out.pubkey):
        print("NFC Pay Out Payload is verified!")

    
    k  = Keys(settings.SERVICE_SECRET_KEY)
    my_enc = NIP44Encrypt(k)
    my_enc_NIP4 = NIP4Encrypt(k)
    token_secret = my_enc.decrypt(nfc_pay_out.token, for_pub_k=k.public_key_hex())
    print(f"token secret {token_secret}")
    k_payout = Keys(token_secret)
    
    print(f"vault nfcpayout: {nfc_pay_out.token} amount: {nfc_pay_out.amount} comment: {nfc_pay_out.comment} to npub: {k_payout.public_key_bech32()}")


    # Need to instantiate right safebox to create invoice here and then spawn task to monitor payment
    print("instantiate right safebox")

    acorn_obj = await get_acorn_by_npub(k_payout.public_key_bech32())

    print(f"Balance of payout acorn {acorn_obj.handle} is {acorn_obj.balance}")
     
    cli_quote = acorn_obj.deposit(nfc_pay_out.amount)

    comment_to_log = f"\U0001F4B3 {nfc_pay_out.comment}"

    detail = f"Paid to {acorn_obj.handle}"
    
    # create task to monitor payment
    task = asyncio.create_task(handle_payment(acorn_obj=acorn_obj,cli_quote=cli_quote, amount=nfc_pay_out.amount, tendered_amount=nfc_pay_out.tendered_amount,tendered_currency=nfc_pay_out.tendered_currency, comment=comment_to_log, mint=HOME_MINT))

   

    return {"status": status, "detail": detail, "comment": comment_to_log,"invoice": cli_quote.invoice, "payee": acorn_obj.handle }
    
@router.post("/onboard/{onboard_code}", tags=["lnaddress", "public"])
async def onboard_safebox(  request: Request, 
                            invite_code:str = Form(), 
                            non_custodial:bool = Form(False) ):
    
    if invite_code.lower().strip() not in settings.INVITE_CODES:
        message = "Looks like you need an invite code!"
        return templates.TemplateResponse(  "welcome.html", 
                                        {   "request": request, 
                                            "title": "Welcome Page", 
                                            "branding": settings.BRANDING,
                                            "branding_message": message})
    
    
    print(f"non-custodial {non_custodial}")
    private_key = Keys()
    
    print(invite_code)
    
    NSEC = private_key.private_key_bech32()

    # Use settings.HOME_RELAY for new safebox
    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS, mints=MINTS, home_relay=settings.HOME_RELAY, logging_level=LOGGING_LEVEL)
    nsec_new = await acorn_obj.create_instance()
    await acorn_obj.load_data()

    medical_emergency_info = settings.EMERGENCY_INFO
    
    await acorn_obj.put_record("medical emergency card", medical_emergency_info)
    profile_info = acorn_obj.get_profile()

    hex_secret = hashlib.sha256(acorn_obj.privkey_hex.encode()).hexdigest()

    if non_custodial:
        nsec = None
        access_key = None
    else:
        nsec = acorn_obj.privkey_bech32
        access_key = acorn_obj.access_key

    register_safebox = RegisteredSafebox(   handle=acorn_obj.handle,
                                            npub=acorn_obj.pubkey_bech32,
                                            nsec=nsec,
                                            home_relay=acorn_obj.home_relay,
                                            onboard_code=invite_code,
                                            access_key=access_key,
                                            emergency_code= generate_pnr(),
                                            nwc_secret=hex_secret
                                            )
    
    with Session(engine) as session:
        session.add(register_safebox)
        session.commit()



        # Create JWT token

    if non_custodial:
        access_token_value = acorn_obj.privkey_bech32
    else:   
        access_token_value = acorn_obj.access_key

    access_token = create_jwt_token({"sub": access_token_value}, expires_delta=timedelta(weeks=settings.TOKEN_EXPIRES_WEEKS, hours=settings.TOKEN_EXPIRES_HOURS))

    # Create response with JWT as HttpOnly cookie
    # response = RedirectResponse(url="/safebox/access", status_code=302)
    response = RedirectResponse(url="/safebox/access?onboard=true", status_code=302)
    # response = JSONResponse({"message": "Login successful"})
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,  # Prevent JavaScript access
        
        secure=True,  # Set to True in production to enforce HTTPS
        samesite="Lax",  # Protect against CSRF
    )
    
    return response  

@router.get("/invite", response_class=HTMLResponse, tags=["public"]) 
async def invite_friend(request: Request, onboard_code: str):  
        onboard_code=onboard_code.strip().lower()
        return templates.TemplateResponse( "invite.html", {"request": request, "title": "Welcome Page", "message": "You're Invited!", "onboard_code": onboard_code})

    

@router.get("/inviteqr/{friend_referral}", tags=["public"])
def create_inviteqr(request: Request, friend_referral: str):

    qr_text = f"{request.base_url}friend/{friend_referral}"      
    img = qrcode.make(qr_text)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0) # important here!
    return StreamingResponse(buf, media_type="image/jpeg")

@router.get("/friend/{friend_handle}", tags=["lnaddress", "public"])
async def onboard_friend(   request: Request, 
                            friend_handle:str,
                            acorn_obj: Acorn = Depends(get_acorn) ):
    
    if acorn_obj:
        response = RedirectResponse(url="/safebox/access", status_code=302)
        return response
    
    
    private_key = Keys()
    
  
    
    NSEC = private_key.private_key_bech32()

    # Use settings.HOME_RELAY for new safebox
    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS, mints=MINTS, home_relay=settings.HOME_RELAY, logging_level=LOGGING_LEVEL)
  
    
    nsec_new = await acorn_obj.create_instance()
    # profile_info = acorn_obj.get_profile()
    await acorn_obj.load_data()
    nsec_hash = password_hasher.hash(nsec_new)
    nsec_verify = password_hasher.verify(nsec_hash,nsec_new)
    print(f"nsec hash is: {nsec_hash} {nsec_verify}")

    medical_emergency_info = settings.EMERGENCY_INFO

    await acorn_obj.put_record("medical emergency card", medical_emergency_info)

    hex_secret = hashlib.sha256(acorn_obj.privkey_hex.encode()).hexdigest()
    
    register_safebox = RegisteredSafebox(   handle=acorn_obj.handle,
                                            npub=acorn_obj.pubkey_bech32,
                                            nsec=acorn_obj.privkey_bech32,
                                            home_relay=acorn_obj.home_relay,
                                            onboard_code=friend_handle,
                                            access_key=acorn_obj.access_key,
                                            emergency_code= generate_pnr(),
                                            nwc_secret=hex_secret
                                           
                                            )
    
    with Session(engine) as session:
        session.add(register_safebox)
        session.commit()



        # Create JWT token
    access_token = create_jwt_token({"sub": acorn_obj.access_key}, expires_delta=timedelta(weeks=settings.TOKEN_EXPIRES_WEEKS, hours=settings.TOKEN_EXPIRES_HOURS))

    # Create response with JWT as HttpOnly cookie
    # response = RedirectResponse(url="/safebox/access", status_code=302)
    response = RedirectResponse(url="/safebox/access?onboard=true", status_code=302)
    # response = JSONResponse({"message": "Login successful"})
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,  # Prevent JavaScript access
        
        secure=True,  # Set to True in production to enforce HTTPS
        samesite="Lax",  # Protect against CSRF
    )
    
    return response  

@router.get("/recover", response_class=HTMLResponse, tags=["public"]) 
async def recover_page (request: Request):
        
    return templates.TemplateResponse( "recover.html", {"request": request, "title": "Welcome Page", "message": "You're Invited!" })

@router.post("/recoversafebox", tags=["public"])
async def recover_safebox(request: Request, recover: recoverIdentity):
    status = "OK"
    detail = "Not implemented"
    handle = "None"
    access_key = "None"
    mode = "None"
    onboard_code = "recovery"
    safebox_new: RegisteredSafebox
    
    
    try:
        nsec_recover = recover_nsec_from_seed(recover.seed_phrase)
        
        k = Keys(priv_k=nsec_recover)
        npub = k.public_key_bech32()
        nsec = k.private_key_bech32()
        detail = f"{npub} {nsec}"
        
    except:
        status = "ERROR"
        detail = "Not recovered"
        return {"status": status, "detail": detail}
    try:
        relay_url = format_relay_url(recover.home_relay)
    except ValueError as e:
        status = "ERROR"
        detail = f"Relay url not valid: {e}"
        return {"status": status, "detail": detail}

    new_handle, new_access_key = generate_new_identity()
    # Check to see if existing service identity exists
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.npub==npub)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
        if safebox_found:
            mode = "found"
           
            if recover.new_identity:
                handle = new_handle
                access_key = new_access_key
            else: 
                handle = safebox_found.handle
                access_key = safebox_found.access_key
            
            npub = safebox_found.npub
            nsec = safebox_found.nsec

        else:
            acorn_obj = Acorn(nsec=nsec_recover, relays=RELAYS, mints=MINTS, home_relay=relay_url, logging_level=LOGGING_LEVEL)
            try:
                await acorn_obj.load_data()
            except Exception as e:
                status = "ERROR"
                detail = f"{e}"
                return {"status": status, "detail": detail}

            mode = "new"
            if recover.new_identity:
                handle = new_handle
                access_key = new_access_key
            else: 
                handle = acorn_obj.handle
                access_key = acorn_obj.access_key
            npub = acorn_obj.pubkey_bech32
            nsec = acorn_obj.privkey_bech32  
            
            
        register_safebox = RegisteredSafebox(   handle=handle,
                                                    npub=npub,
                                                    nsec=nsec,
                                                    home_relay=relay_url,
                                                    onboard_code=onboard_code,
                                                    access_key=access_key
                                            )
        session.add(register_safebox)
        
        session.commit()

            # raise HTTPException(status_code=404, detail=f"{npub} not found")

    detail = f"Your {mode} handle: {handle} Your access key: {access_key}"

    return {"status": status, "detail": detail}



@router.post("/access", tags=["lnaddress"])
async def access_safebox(request: Request, access_key:str):
    
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.access_key==access_key)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            raise HTTPException(status_code=404, detail=f"{access_key} not found")


    acorn_obj = Acorn(nsec=safebox_found.nsec, home_relay=safebox_found.home_relay, mints=MINTS)
    await acorn_obj.load_data()

    return {"handle": safebox_found.handle,
            "npub": safebox_found.npub,
            "nsec": safebox_found.nsec,
            "balance": acorn_obj.balance
            }
           
          
            
     