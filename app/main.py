from sqlmodel import Field, Session, SQLModel, select
from fastapi import FastAPI, Request, BackgroundTasks, Cookie, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import asyncio, os, secrets
import logging
import inspect
from contextlib import asynccontextmanager
from filelock import FileLock, Timeout
from sqlalchemy import inspect
from sqlalchemy.exc import SQLAlchemyError
from aiohttp.client_exceptions import WSMessageTypeError

import oqs

from monstr.encrypt import Keys, DecryptionException

from app.config import Settings, ConfigWithFallback
from app.db import (
    DB_BACKEND,
    engine as DB_ENGINE,
    ensure_registeredsafebox_uniqueness,
    schema_init_lock,
)
from app.branding import build_templates, ensure_branding_bootstrap
from app.routers import     (   lnaddress, 
                                safebox, 
                                scanner, 
                                emergency, 
                                pos, 
                                public, 
                                
                                records )

from app.tasks import periodic_task
from app.utils import fetch_safebox, ensure_csrf_cookie
from app.appmodels import RegisteredSafebox
from app.rates import refresh_currency_rates, init_currency_rates, get_online_currency_rates

from app.relay import run_relay
from app.nwc import listen_nwc, listen_notes, listen_notes_connected, listen_notes_query
from safebox.acorn import Acorn
import sys

lock_path = "/tmp/monstr_listener.lock"
listener_task = None
relay_task = None
logger = logging.getLogger(__name__)
previous_loop_exception_handler = None

# Create Settings:
SETTINGS = Settings()


def _is_expected_monstr_ws_close(context: dict) -> bool:
    """Suppress known monstr websocket close noise during shutdown."""
    exc = context.get("exception")
    if not isinstance(exc, WSMessageTypeError):
        return False
    if "not WSMsgType.TEXT" not in str(exc):
        return False
    fut = context.get("future") or context.get("task")
    coro = fut.get_coro() if fut and hasattr(fut, "get_coro") else None
    qualname = getattr(coro, "__qualname__", "")
    return "Client._my_consumer" in qualname


def _install_loop_exception_filter() -> None:
    global previous_loop_exception_handler
    loop = asyncio.get_running_loop()
    previous_loop_exception_handler = loop.get_exception_handler()

    def _handler(loop_obj, context):
        if _is_expected_monstr_ws_close(context):
            logger.debug("Suppressed expected monstr websocket close-frame exception")
            return
        if previous_loop_exception_handler is not None:
            previous_loop_exception_handler(loop_obj, context)
        else:
            loop_obj.default_exception_handler(context)

    loop.set_exception_handler(_handler)


config = ConfigWithFallback()
# print(f"config: {config.SERVICE_NSEC}")



# print(f"SETTINGS service key {config.SERVICE_NSEC}")
if config.SERVICE_NSEC:
    
    SERVICE_KEY = Keys(config.SERVICE_NSEC)
else:
    logger.error("SERVICE_NSEC is not configured; generated a replacement key for setup guidance")
    SERVICE_KEY = Keys()
    logger.error(
        "Add this to your environment: SERVICE_SECRET_KEY=%s",
        SERVICE_KEY.private_key_bech32(),
    )
    raise RuntimeError("SERVICE_NSEC is required")


nwc_task_handle = None

# Periodic task function
async def periodic_task(interval: int, stop_event: asyncio.Event):
    while not stop_event.is_set():
        worker_id = os.getenv("GUNICORN_WORKER_ID", "1")
        logger.debug("Executing periodic task worker_id=%s", worker_id)
        # await refresh_currency_rates()
        await asyncio.sleep(interval)  # Wait for the next interval

@asynccontextmanager
async def lifespan(app: FastAPI):
    # stop_event = asyncio.Event()  # Event to signal stopping
    global nwc_task_handle
    global relay_task
    _install_loop_exception_filter()
    ensure_branding_bootstrap()
    try:
        with schema_init_lock():
            if DB_BACKEND.startswith("sqlite"):
                SQLModel.metadata.create_all(DB_ENGINE, checkfirst=True)
            else:
                inspector = inspect(DB_ENGINE)
                required_tables = ("registeredsafebox", "currencyrate")
                missing_tables = [name for name in required_tables if not inspector.has_table(name)]
                if missing_tables:
                    raise RuntimeError(
                        "PostgreSQL schema is not initialized. Run `alembic upgrade head` before starting the app. "
                        f"Missing tables: {', '.join(missing_tables)}"
                    )
            ensure_registeredsafebox_uniqueness()
    except SQLAlchemyError:
        logger.exception("Database initialization failed during startup")
        raise
    except RuntimeError:
        logger.exception("Database integrity check failed during startup")
        raise
    
    #TODO add in current rates    
    await init_currency_rates();
   

    is_production = SETTINGS.APP_ENV.lower() in {"prod", "production"}
    if is_production and not config.NWC_NSEC:
        raise RuntimeError("NWC_NSEC must be set in production")
    if is_production and ("*" in SETTINGS.CORS_ALLOW_ORIGINS or not SETTINGS.CORS_ALLOW_ORIGINS):
        raise RuntimeError("CORS_ALLOW_ORIGINS must be explicit and non-empty in production")
    if is_production and not SETTINGS.COOKIE_SECURE:
        raise RuntimeError("COOKIE_SECURE must be enabled in production")

    relay_task = asyncio.create_task(run_relay())
    if SETTINGS.NWC_SERVICE:
        pass
        # nwc_task_handle = asyncio.create_task(listen_nwc())
    
    logger.info("Application startup complete")
    # Create Task
    # task = asyncio.create_task(periodic_task(SETTINGS.REFRESH_CURRENCY_INTERVAL, stop_event))
    global listener_task
    lock_path = "/tmp/monstr_listener.lock"
    file_lock = FileLock(lock_path)
    
    # have_lock = False
    # try:
    #    file_lock.acquire(timeout=0.1)  # <-- synchronous, blocks here
    #    have_lock = True
    #    print(f"[PID {os.getpid()}] Acquired lock. Starting listener.")
    #    url = "wss://relay.getsafebox.app"
    #     listener_task = asyncio.create_task(listen_notes(url))
    # except Timeout:
    #    print(f"[PID {os.getpid()}] Could not acquire lock. Skipping listener.")
    
    # The single event handling is now done in nwc.py, so all listeners can be running
    if config.NWC_NSEC:
        logger.info("[PID %s] Starting nwc listener", os.getpid())
        url = SETTINGS.NWC_RELAYS[0]
        listener_task = asyncio.create_task(listen_notes_connected(url))
    else:
        logger.info("[PID %s] NWC listener disabled: NWC_NSEC not configured", os.getpid())

    
    yield

    if listener_task:
        logger.info("Shutting down listener")
        listener_task.cancel()
        try:
            await listener_task
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.debug("Suppressed listener shutdown exception: %r", exc)

    if relay_task:
        logger.info("Shutting down relay")
        relay_task.cancel()
        try:
            await relay_task
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.debug("Suppressed relay shutdown exception: %r", exc)

   





# asyncio.run(init_currency_rates())
# asyncio.run(refresh_currency_rates())




# Create an instance of the FastAPI application
origins = SETTINGS.CORS_ALLOW_ORIGINS
#TODO figure out how to lock a worker to do periodic tasks
app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


app.include_router(lnaddress.router) 
app.include_router(safebox.router, prefix="/safebox") 
app.include_router(scanner.router, prefix="/scanner") 
app.include_router(emergency.router) 
app.include_router(pos.router, prefix="/pos")
app.include_router(public.router, prefix="/public")

app.include_router(records.router, prefix="/records")

templates = build_templates()
app.mount("/src", StaticFiles(directory="app/src"), name="src")
app.mount("/js", StaticFiles(directory="app/js"), name="js")
app.mount("/img", StaticFiles(directory="app/img"), name="img")
app.mount("/static", StaticFiles(directory="app/static"), name="static")



# Define a root endpoint
@app.get("/", tags=["public"])
async def read_root(request: Request, access_token: str = Cookie(default=None)):    
    if access_token:
        try:
            await fetch_safebox(access_token=access_token)
            response = RedirectResponse(url="/safebox/access", status_code=302)
            return response
        except DecryptionException:
            logger.debug("Access token decrypt failed at root route")
        except HTTPException as exc:
            logger.debug("Access token not usable at root route: %s", exc.detail)
        except Exception:
            logger.exception("Unexpected error resolving root access token")
    csrf_cookie = request.cookies.get(SETTINGS.CSRF_COOKIE_NAME)
    csrf_token = csrf_cookie if csrf_cookie and len(csrf_cookie) >= 32 else secrets.token_urlsafe(32)
    response = templates.TemplateResponse(
        "welcome.html",
        {
            "request": request,
            "title": "Welcome Page",
            "csrf_token": csrf_token,
        },
    )
    ensure_csrf_cookie(response=response, current_token=csrf_token, request=request)
    return response

# Define a npub endpoint
@app.get("/npub", tags=["public"])
async def get_npub(request: Request): 
    return {"npub": config.SERVICE_NPUB}

# Define a npub endpoint
@app.get("/pqc", tags=["public"])
async def get_pqc(request: Request): 

    data_to_return = {  "sigpub": config.PQC_SIG_PUBLIC_KEY, 
                        "sigalg": SETTINGS.PQC_SIGALG,
                        "kempub": config.PQC_KEM_PUBLIC_KEY,
                        "kemalg": SETTINGS.PQC_KEMALG                        
                    }


    

    return data_to_return


@app.get("/.well-known/nostr.json",tags=["public"])
async def get_nostr_name(request: Request, name: str, ):

    # nostr_db = SqliteDict(os.path.join(wallets_directory,"nostr_lookup.db"))
    if name == "_":
        npub_hex = SERVICE_KEY.public_key_hex()
        return {
        "names": {
            "_": npub_hex
        },
        "relays":
                     { f"{npub_hex}": SETTINGS.RELAYS}  }
    else:
        pass
        with Session(DB_ENGINE) as session:
            statement = select(RegisteredSafebox).where(RegisteredSafebox.custom_handle==name)
            safeboxes = session.exec(statement)
            safebox_found = safeboxes.first()
            if safebox_found:
                if safebox_found.owner:
                    key_obj = Keys(pub_k=safebox_found.owner)
                else:
                    key_obj = Keys(pub_k=safebox_found.npub)  
                
                npub_hex = key_obj.public_key_hex()
            else:
                statement = select(RegisteredSafebox).where(RegisteredSafebox.handle==name)
                safeboxes = session.exec(statement)
                safebox_found = safeboxes.first()
                if safebox_found:
                    if safebox_found.owner:
                        key_obj = Keys(pub_k=safebox_found.owner)
                    else:
                        key_obj = Keys(pub_k=safebox_found.npub)  
                
                    npub_hex = key_obj.public_key_hex()
                   
                else:
                    raise HTTPException(status_code=404, detail=f"{name} not found")

    pubkey = npub_hex

    account_metadata = {}    
    # pubkey =  wallet_info['wallet_info']['npub_hex']

    

    nostr_names = {
                    "names": {
                        f"{name}": pubkey
                        },
                     "relays":
                     { f"{pubkey}": SETTINGS.RELAYS}   
                    
                    }

    headers = {"Access-Control-Allow-Origin" : "*"}
    return JSONResponse(content=nostr_names, headers=headers)
    # return nostr_names

@app.get("/.well-known/safebox.json/{name}",tags=["public"])
async def get_safebox_pubhex(request: Request, name: str, ):

    #This returns the the pubkey of the safebox based on the lightning address
    # Either the custom handle or default

    # nostr_db = SqliteDict(os.path.join(wallets_directory,"nostr_lookup.db"))
    if name == "_":
        npub_hex = SERVICE_KEY.public_key_hex()
        return {
        "names": {
            "_": npub_hex
        },
        "relays":
                     { f"{npub_hex}": SETTINGS.RELAYS},
        "ecash_relays":
                     { f"{npub_hex}": SETTINGS.ECASH_RELAYS}                  }
    else:
        pass
        with Session(DB_ENGINE) as session:
            statement = select(RegisteredSafebox).where(RegisteredSafebox.custom_handle==name)
            safeboxes = session.exec(statement)
            safebox_found = safeboxes.first()
            if safebox_found:
                key_obj = Keys(pub_k=safebox_found.npub)
                npub_hex = key_obj.public_key_hex()
            else:
                statement = select(RegisteredSafebox).where(RegisteredSafebox.handle==name)
                safeboxes = session.exec(statement)
                safebox_found = safeboxes.first()
                if safebox_found:
                    key_obj = Keys(pub_k=safebox_found.npub)
                    npub_hex = key_obj.public_key_hex()
                else:
                    raise HTTPException(status_code=404, detail=f"{name} not found")



    safebox_json = {
                    "pubkey": npub_hex,                       
                     "relays": SETTINGS.RELAYS,
                    "ecash_relays": SETTINGS.ECASH_RELAYS     
                    
                    }

    headers = {"Access-Control-Allow-Origin" : "*"}
    return JSONResponse(content=safebox_json, headers=headers)
    # return nostr_names

@app.get("/user/{user}/did.json",tags=["public"])
def get_user_did_doc(user: str, request: Request):
    """did:web:asats.io:wallet:wallet_id"""



    did_doc = {
               
                "id": f"did:web:{request.url.hostname}:user:{user}",
                "verificationMethod":[{
                                        "id": f"did:web:{request.url.hostname}:user:{user}#pubkey",
                                        "controller": f"did:web:{request.url.hostname}:user:{user}",
                                        "type": "EcdsaSecp256k1RecoveryMethod2020",
                                        "publicKeyHex": "tbd"
                                      }],
                "authentication":[{
                                        "id": f"did:web:{request.url.hostname}:user:{user}#pubkey",
                                        "controller": f"did:web:{request.url.hostname}:user:{user}",
                                        "type": "EcdsaSecp256k1VerificationKey2019",
                                        "publicKeyHex": "tbd"
                                      }]

                }
               
                

    return did_doc 


  
