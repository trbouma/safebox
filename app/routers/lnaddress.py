from fastapi import Request, APIRouter, Depends, Response, Form, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import StreamingResponse
from pydantic import BaseModel
import random
import string
import asyncio
from datetime import timedelta

from sqlmodel import Field, Session, SQLModel, create_engine, select

from monstr.encrypt import Keys
from safebox.acorn import Acorn

from app.appmodels import RegisteredSafebox, PaymentQuote
from safebox.models import cliQuote
from app.tasks import poll_for_payment, callback_done
from app.utils import create_jwt_token
from app.config import Settings

settings = Settings()

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
    
    with Session(engine) as session:
        statement = select(PaymentQuote)
        payment_quotes = session.exec(statement)
        records = payment_quotes.fetchall()
        for record in records:
            try:
                # acorn_obj = Acorn(nsec=each.nsec, mints=[each.mint], home_relay=HOME_RELAY, relays=RELAYS)
                # acorn_obj = Acorn(nsec=each.nsec, relays=RELAYS, mints=MINTS, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
                # profile_out = acorn_obj.get_profile()
                print(f"record: {record}")
                nsec_test = 'nsec187nscru0596h0s2yuzutf83sp8jkwxjk8ag4tzxkugvg7e7wmdyqgk0ayq'
                acorn_obj = Acorn(nsec=record.nsec, mints=MINTS, home_relay=settings.HOME_RELAY, logging_level=LOGGING_LEVEL)
                print(acorn_obj.handle)
                acorn_obj.check_quote(record.quote,record.amount)
                
            except Exception as e:
                print(f"error: {e}")
        

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

 
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.handle ==name)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            raise HTTPException(status_code=404, detail=f"{name} not found")

    acorn_obj = Acorn(nsec=safebox_found.nsec, relays=RELAYS, mints=MINTS, home_relay=settings.HOME_RELAY, logging_level=LOGGING_LEVEL)
    await acorn_obj.load_data()
   
    print(f"current balance is: {acorn_obj.balance}, home relay: {acorn_obj.home_relay}")
    cli_quote = acorn_obj.deposit(amount//1000)



    task = asyncio.create_task(acorn_obj.poll_for_payment(quote=cli_quote.quote, amount=int(amount//1000),mint=HOME_MINT))
    

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
    
    print(invite_code)
    
    NSEC = private_key.private_key_bech32()


    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS, mints=MINTS, home_relay=settings.HOME_RELAY, logging_level=LOGGING_LEVEL)
    await acorn_obj.load_data()
    
    nsec_new = await acorn_obj.create_instance()
    profile_info = acorn_obj.get_profile()

    register_safebox = RegisteredSafebox(   handle=acorn_obj.handle,
                                            npub=acorn_obj.pubkey_bech32,
                                            nsec=acorn_obj.privkey_bech32,
                                            access_key=acorn_obj.access_key
                                            )
    
    with Session(engine) as session:
        session.add(register_safebox)
        session.commit()



        # Create JWT token
    access_token = create_jwt_token({"sub": acorn_obj.access_key}, expires_delta=timedelta(hours=1))

    # Create response with JWT as HttpOnly cookie
    response = RedirectResponse(url="/safebox/access", status_code=302)
    # response = JSONResponse({"message": "Login successful"})
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,  # Prevent JavaScript access
        max_age=3600,  # 1 hour
        secure=False,  # Set to True in production to enforce HTTPS
        samesite="Lax",  # Protect against CSRF
    )

    wallet_info = {"detail": request.url.hostname,
            "nsec": nsec_new,
            "npub": f"{acorn_obj.pubkey_bech32} ",
            "seed_phrase": acorn_obj.seed_phrase,
            "access_key": acorn_obj.access_key,
            "address": f"{acorn_obj.handle}@{request.url.hostname}",
          
            
            }
    print(wallet_info)
    
    return response
    
@router.get("/onboard/{invite_code}", tags=["lnaddress", "public"])
async def onboard_safebox(request: Request, invite_code:str = 'alpha'):
    
    private_key = Keys()
    
    print(invite_code)
    
    NSEC = private_key.private_key_bech32()


    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS, mints=MINTS, home_relay=settings.HOME_RELAY, logging_level=LOGGING_LEVEL)
    await acorn_obj.load_data()
    
    nsec_new = await acorn_obj.create_instance()
    profile_info = acorn_obj.get_profile()

    register_safebox = RegisteredSafebox(   handle=acorn_obj.handle,
                                            npub=acorn_obj.pubkey_bech32,
                                            nsec=acorn_obj.privkey_bech32,
                                            home_relay=settings.HOME_RELAY,
                                            onboard_code=invite_code,
                                            access_key=acorn_obj.access_key
                                            )
    
    with Session(engine) as session:
        session.add(register_safebox)
        session.commit()



        # Create JWT token
    access_token = create_jwt_token({"sub": acorn_obj.access_key}, expires_delta=timedelta(hours=8))

    # Create response with JWT as HttpOnly cookie
    response = RedirectResponse(url="/safebox/access", status_code=302)
    # response = JSONResponse({"message": "Login successful"})
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,  # Prevent JavaScript access
        
        secure=True,  # Set to True in production to enforce HTTPS
        samesite="Lax",  # Protect against CSRF
    )


    
    return response  
    

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


    acorn_obj = Acorn(nsec=safebox_found.nsec, home_relay=settings.HOME_RELAY, mints=MINTS)
    await acorn_obj.load_data()

    return {"handle": safebox_found.handle,
            "npub": safebox_found.npub,
            "nsec": safebox_found.nsec,
            "balance": acorn_obj.balance
            }
           
          
            
     