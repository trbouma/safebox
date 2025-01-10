from fastapi import Request, APIRouter, Depends, Response, Form, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import StreamingResponse
from pydantic import BaseModel
import random
import string
import asyncio

from sqlmodel import Field, Session, SQLModel, create_engine, select

from monstr.encrypt import Keys
from safebox.acorn import Acorn

from app.appmodels import RegisteredSafebox, PaymentQuote
from safebox.models import cliQuote
from app.tasks import poll_for_payment_x

# settings = Settings()

RELAYS = ['wss://relay.openbalance.app']
MINTS = ['https://mint.nimo.cash']
HOME_RELAY = 'wss://relay.openbalance.app'
LOGGING_LEVEL = 10
HOME_MINT = 'https://mint.nimo.cash'

engine = create_engine("sqlite:///data/database.db")
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
                acorn_obj = Acorn(nsec=record.nsec, mints=MINTS, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
                print(acorn_obj.handle)
                acorn_obj.check_quote(record.quote,record.amount)
                
            except Exception as e:
                print(f"error: {e}")
        

    return {"detail": request.url.hostname}

@router.get("/.well-known/lnurlp/{name}")
def ln_resolve(request: Request, name: str = None):

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
def ln_pay( amount: float,
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

    acorn_obj = Acorn(nsec=safebox_found.nsec, relays=RELAYS, mints=MINTS, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
   
    print(f"current balance is: {acorn_obj.balance}, home relay: {acorn_obj.home_relay}")
    cli_quote = acorn_obj.deposit(amount//1000)

    quote_check = PaymentQuote(nsec=safebox_found.nsec, quote=cli_quote.quote, amount=int(amount//1000),mint=HOME_MINT, handle=name)
    with Session(engine) as session:
        session.add(quote_check)
        session.commit()

   

    success_obj = {     "tag": "message",
                            "message" : f"Payment sent to {name} for {int(amount//1000)} sats. The quote is: {cli_quote.quote}"  }

    

    return  {   "pr": cli_quote.invoice,
                "hash": None,
                "routes": [],
                "successAction": success_obj
            } 

    return name

@router.post("/create", tags=["lnaddress"])
def create_safebox(request: Request):
    
    private_key = Keys()
    
 
    
    NSEC = private_key.private_key_bech32()


    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS, mints=MINTS, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
    nsec_new = acorn_obj.create_instance()
    profile_info = acorn_obj.get_profile()

    register_safebox = RegisteredSafebox(   handle=acorn_obj.handle,
                                            npub=acorn_obj.pubkey_bech32,
                                            nsec=acorn_obj.privkey_bech32,
                                            access_key=acorn_obj.access_key
                                            )
    
    with Session(engine) as session:
        session.add(register_safebox)
        session.commit()

    with Session(engine) as session:
        statement = select(RegisteredSafebox)
        safeboxes = session.exec(statement)
        for each in safeboxes:
            print(each.handle)

    return {"detail": request.url.hostname,
            "nsec": nsec_new,
            "npub": f"{acorn_obj.pubkey_bech32} ",
            "seed_phrase": acorn_obj.seed_phrase,
            "access_key": acorn_obj.access_key,
            "address": f"{acorn_obj.handle}@{request.url.hostname}",
          
            
            }

@router.post("/access", tags=["lnaddress"])
def acess_safebox(request: Request, access_key:str):
    
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.access_key==access_key)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            raise HTTPException(status_code=404, detail=f"{access_key} not found")


    acorn_obj = Acorn(nsec=safebox_found.nsec, home_relay=HOME_RELAY, mints=MINTS)

    return {"handle": safebox_found.handle,
            "npub": safebox_found.npub,
            "nsec": safebox_found.nsec,
            "balance": acorn_obj.balance
            }
           
          
            
     