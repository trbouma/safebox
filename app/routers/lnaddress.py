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

from sqlmodel import Field, Session, SQLModel, create_engine, select, update
from argon2 import PasswordHasher


from monstr.encrypt import Keys
from monstr.event.event import Event
from safebox.acorn import Acorn

from app.appmodels import RegisteredSafebox, PaymentQuote, recoverIdentity
from safebox.models import cliQuote
from app.tasks import service_poll_for_payment, handle_payment
from app.utils import create_jwt_token, send_zap_receipt, recover_nsec_from_seed, format_relay_url, generate_new_identity
from app.config import Settings

settings = Settings()
templates = Jinja2Templates(directory="app/templates")
password_hasher = PasswordHasher()

# RELAYS = ['wss://relay.getsafebox.app']
RELAYS = settings.RELAYS
# MINTS = ['https://mint.nimo.cash']
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
            


    acorn_obj = Acorn(nsec=safebox_found.nsec, relays=RELAYS, mints=MINTS, home_relay=safebox_found.home_relay, logging_level=LOGGING_LEVEL)
    await acorn_obj.load_data()
   
    print(f"current balance is: {acorn_obj.balance}, home relay: {acorn_obj.home_relay}")
    cli_quote = acorn_obj.deposit(sat_amount)


    # task = asyncio.create_task(acorn_obj.poll_for_payment(quote=cli_quote.quote, amount=sat_amount,mint=HOME_MINT))
    
    task = asyncio.create_task(handle_payment(acorn_obj=acorn_obj,cli_quote=cli_quote, amount=sat_amount, mint=HOME_MINT, nostr=nostr))

 




    success_obj = {     "tag": "message",
                            "message" : f"Payment sent to {name} for {int(amount//1000)} sats. The quote is: {cli_quote.quote} with {cli_quote.mint_url}"  }

    

    return  {   "pr": cli_quote.invoice,
                "hash": None,
                "routes": [],
                "successAction": success_obj
            } 

    return name


    
@router.post("/onboard/{onboard_code}", tags=["lnaddress", "public"])
async def onboard_safebox(request: Request, invite_code:str = Form() ):
    
    if invite_code.lower().strip() not in settings.INVITE_CODES:
        message = "Looks like you need an invite code!"
        return templates.TemplateResponse(  "welcome.html", 
                                        {   "request": request, 
                                            "title": "Welcome Page", 
                                            "branding": settings.BRANDING,
                                            "branding_message": message})
    
    
    
    private_key = Keys()
    
    print(invite_code)
    
    NSEC = private_key.private_key_bech32()

    # Use settings.HOME_RELAY for new safebox
    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS, mints=MINTS, home_relay=settings.HOME_RELAY, logging_level=LOGGING_LEVEL)
    nsec_new = await acorn_obj.create_instance()
    await acorn_obj.load_data()
    
    
    profile_info = acorn_obj.get_profile()

    register_safebox = RegisteredSafebox(   handle=acorn_obj.handle,
                                            npub=acorn_obj.pubkey_bech32,
                                            nsec=acorn_obj.privkey_bech32,
                                            home_relay=acorn_obj.home_relay,
                                            onboard_code=invite_code,
                                            access_key=acorn_obj.access_key
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
async def onboard_friend(request: Request, friend_handle:str ):
    

    
    
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

    register_safebox = RegisteredSafebox(   handle=acorn_obj.handle,
                                            npub=acorn_obj.pubkey_bech32,
                                            nsec=acorn_obj.privkey_bech32,
                                            home_relay=acorn_obj.home_relay,
                                            onboard_code=friend_handle,
                                            access_key=acorn_obj.access_key
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
           
          
            
     