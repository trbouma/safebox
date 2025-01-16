from fastapi import Request, APIRouter, Depends, Response, Form, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import StreamingResponse

from pydantic import BaseModel
import random
import string
import asyncio
from datetime import timedelta
import qrcode, io

from sqlmodel import Field, Session, SQLModel, create_engine, select

from monstr.encrypt import Keys
from safebox.acorn import Acorn

from app.appmodels import RegisteredSafebox, PaymentQuote
from safebox.models import cliQuote
from app.tasks import service_poll_for_payment, callback_done
from app.utils import create_jwt_token
from app.config import Settings

settings = Settings()
templates = Jinja2Templates(directory="app/templates")

RELAYS = ['wss://relay.openbalance.app']
MINTS = ['https://mint.nimo.cash']
# HOME_RELAY = 'wss://relay.openbalance.app'
LOGGING_LEVEL = 10
HOME_MINT = 'https://mint.nimo.cash'

engine = create_engine(settings.DATABASE)
SQLModel.metadata.create_all(engine)


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

    ln_callback = f"https://{request.url.hostname}/lnpay/{name}"
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.handle ==name)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            raise HTTPException(status_code=404, detail=f"{name} not found")

    ln_response = {     "callback": ln_callback,
                        "minSendable": 1000,
                        "maxSendable": 210000000,
                        "metadata": f"[[\"text/plain\", \"Send Payment to: {name}\"]]",
                        "commentAllowed": 60,
                        "allowsNostr" :True,
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

    sat_amount = int(amount//1000)

    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.handle ==name)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            raise HTTPException(status_code=404, detail=f"{name} not found")

    acorn_obj = Acorn(nsec=safebox_found.nsec, relays=RELAYS, mints=MINTS, home_relay=safebox_found.home_relay, logging_level=LOGGING_LEVEL)
    await acorn_obj.load_data()
   
    print(f"current balance is: {acorn_obj.balance}, home relay: {acorn_obj.home_relay}")
    cli_quote = acorn_obj.deposit(sat_amount)



    task = asyncio.create_task(acorn_obj.poll_for_payment(quote=cli_quote.quote, amount=sat_amount,mint=HOME_MINT))
    
    # do here with a wrapper
    task2 = asyncio.create_task(service_poll_for_payment(handle=safebox_found.handle,quote=cli_quote.quote, mint=HOME_MINT, amount=sat_amount))

    success_obj = {     "tag": "message",
                            "message" : f"Payment sent to {name} for {int(amount//1000)} sats. The quote is: {cli_quote.quote} with {cli_quote.mint_url}"  }

    

    return  {   "pr": cli_quote.invoice,
                "hash": None,
                "routes": [],
                "successAction": success_obj
            } 

    return name

@router.post("/create", tags=["lnaddress"])
async def create_safebox(request: Request, invite_code:str = Form()):
    
    private_key = Keys()
    
    if not invite_code or invite_code=="":
        invite_code = "test_user"

    print(invite_code)
    
    NSEC = private_key.private_key_bech32()

    # Use settings.HOME_RELAY
    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS, mints=MINTS, home_relay=settings.HOME_RELAY, logging_level=LOGGING_LEVEL)
    await acorn_obj.load_data()
    
    nsec_new = await acorn_obj.create_instance()
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
    access_token = create_jwt_token({"sub": acorn_obj.access_key}, expires_delta=timedelta(hours=1))

    # Create response with JWT as HttpOnly cookie
    response = RedirectResponse(url="/safebox/access?onboard=true", status_code=302)
    # response = JSONResponse({"message": "Login successful"})
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,  # Prevent JavaScript access
        max_age=3600,  # 1 hour
        secure=False,  # Set to True in production to enforce HTTPS
        samesite="Lax",  # Protect against CSRF
    )

    
 
    
    return response
    
@router.get("/onboard/{invite_code}", tags=["lnaddress", "public"])
async def onboard_safebox(request: Request, invite_code:str = 'alpha'):
    
    private_key = Keys()
    
    print(invite_code)
    
    NSEC = private_key.private_key_bech32()

    # Use settings.HOME_RELAY for new safebox
    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS, mints=MINTS, home_relay=settings.HOME_RELAY, logging_level=LOGGING_LEVEL)
    await acorn_obj.load_data()
    
    nsec_new = await acorn_obj.create_instance()
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
    access_token = create_jwt_token({"sub": acorn_obj.access_key}, expires_delta=timedelta(hours=8))

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
        return templates.TemplateResponse( "invite.html", {"request": request, "title": "Welcome Page", "message": "You're Invited!", "onboard_code": onboard_code})

@router.get("/inviteqr/{onboard_code}", tags=["public"])
def create_inviteqr(request: Request, onboard_code: str):

    qr_text = f"{request.base_url}onboard/{onboard_code}"      
    img = qrcode.make(qr_text)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0) # important here!
    return StreamingResponse(buf, media_type="image/jpeg")

@router.post("/access", tags=["lnaddress"])
async def acess_safebox(request: Request, access_key:str):
    
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
           
          
            
     