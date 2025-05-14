from sqlmodel import Field, Session, SQLModel, create_engine, select
from fastapi import FastAPI, Request, BackgroundTasks, WebSocket, Cookie, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import asyncio, os
from contextlib import asynccontextmanager

from monstr.encrypt import Keys

from app.config import Settings
from app.routers import     (   lnaddress, 
                                safebox, 
                                scanner, 
                                prescriptions, 
                                emergency, 
                                pos, 
                                public, 
                                credentials,
                                records )

from app.tasks import periodic_task
from app.utils import fetch_safebox
from app.appmodels import RegisteredSafebox
from app.rates import refresh_currency_rates, init_currency_rates, get_online_currency_rates

from app.relay import run_relay
from app.nwc import listen_nwc

# Create Settings:
settings = Settings()


# Periodic task function
async def periodic_task(interval: int, stop_event: asyncio.Event):
    while not stop_event.is_set():
        worker_id = os.getenv("GUNICORN_WORKER_ID", "1")
        print(f"Executing periodic task... {worker_id}")
        # await refresh_currency_rates()
        await asyncio.sleep(interval)  # Wait for the next interval

@asynccontextmanager
async def lifespan(app: FastAPI):
    # stop_event = asyncio.Event()  # Event to signal stopping
    try:
        engine = create_engine(settings.DATABASE)
        SQLModel.metadata.create_all(engine, checkfirst=True)
    except:
        pass
    
    asyncio.create_task(run_relay())
    if settings.NWC_SERVICE:
        asyncio.create_task(listen_nwc())
    
    print("let's start up!")
    # Create Task
    # task = asyncio.create_task(periodic_task(settings.REFRESH_CURRENCY_INTERVAL, stop_event))
    
    yield
    # stop_event.set()  # Stop the task
    # await task  # Ensure task finishes properly
   



SERVICE_KEY = Keys(settings.SERVICE_SECRET_KEY)


# asyncio.run(init_currency_rates())
# asyncio.run(refresh_currency_rates())




# Create an instance of the FastAPI application
origins = ["*"]
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
app.include_router(prescriptions.router, prefix="/prescriptions") 
app.include_router(emergency.router) 
app.include_router(pos.router, prefix="/pos")
app.include_router(public.router, prefix="/public")
app.include_router(credentials.router, prefix="/credentials")
app.include_router(records.router, prefix="/records")

templates = Jinja2Templates(directory="app/templates")
app.mount("/src", StaticFiles(directory="app/src"), name="src")
app.mount("/js", StaticFiles(directory="app/js"), name="js")
app.mount("/img", StaticFiles(directory="app/img"), name="img")
app.mount("/static", StaticFiles(directory="app/static"), name="static")



# Define a root endpoint
@app.get("/", tags=["public"])
async def read_root(request: Request, access_token: str = Cookie(default=None)):    

    
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
        response = RedirectResponse(url="/safebox/access", status_code=302)
        return response
    except:
        pass
        print("pass")
    return templates.TemplateResponse(  "welcome.html", 
                                        {   "request": request, 
                                            "title": "Welcome Page", 
                                            "branding": settings.BRANDING,
                                            "branding_message": settings.BRANDING_MESSAGE})

@app.get("/.well-known/nostr.json",tags=["public"])
async def get_nostr_name(request: Request, name: str, ):

    # nostr_db = SqliteDict(os.path.join(wallets_directory,"nostr_lookup.db"))
    engine = create_engine(settings.DATABASE)
    
    if name == "_":
        npub_hex = SERVICE_KEY.public_key_hex()
        return {
        "names": {
            "_": npub_hex
        },
        "relays":
                     { f"{npub_hex}": settings.RELAYS}  }
    else:
        pass
        with Session(engine) as session:
            statement = select(RegisteredSafebox).where(RegisteredSafebox.custom_handle==name)
            safeboxes = session.exec(statement)
            safebox_found = safeboxes.first()
            if safebox_found:
                key_obj = Keys(pub_k=safebox_found.owner)
                npub_hex = key_obj.public_key_hex()
            else:
                statement = select(RegisteredSafebox).where(RegisteredSafebox.handle==name)
                safeboxes = session.exec(statement)
                safebox_found = safeboxes.first()
                if safebox_found:
                    key_obj = Keys(pub_k=safebox_found.owner)
                    npub_hex = key_obj.public_key_hex()
                else:
                    raise HTTPException(status_code=404, detail=f"{name} not found")

    try: 
        # wallet_info = get_public_profile(wallet_name=name)
        # print(wallet_info['wallet_info']['npub_hex'])
        # return{"status": "OK", "reason": "not implemented yet"}
        
        pubkey = npub_hex
        
    except:
        return{"status": "ERROR", "reason": "Name does not exist"}

    account_metadata = {}    
    # pubkey =  wallet_info['wallet_info']['npub_hex']

    

    nostr_names = {
                    "names": {
                        f"{name}": pubkey
                        },
                     "relays":
                     { f"{pubkey}": settings.RELAYS}   
                    
                    }

    headers = {"Access-Control-Allow-Origin" : "*"}
    return JSONResponse(content=nostr_names, headers=headers)
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


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    while True:
        try:
            data = await websocket.receive_text()
            print(f"message received: {data}")
            await websocket.send_text(f"message received: {data}")
        except Exception as e:
            print(f"Websocket error: {e}")
            break
    print("websocket connection closed")
            
html = """
<!DOCTYPE html>
<html>
    <head>
        <title>Chat</title>
    </head>
    <body>
        <h1>WebSocket Chat</h1>
        <form action="" onsubmit="sendMessage(event)">
            <input type="text" id="messageText" autocomplete="off"/>
            <button>Send</button>
        </form>
        <ul id='messages'>
        </ul>
        <script>
            var ws = new WebSocket("ws://localhost:7375/ws");
            ws.onmessage = function(event) {
                var messages = document.getElementById('messages')
                var message = document.createElement('li')
                var content = document.createTextNode(event.data)
                message.appendChild(content)
                messages.appendChild(message)
            };
            function sendMessage(event) {
                var input = document.getElementById("messageText")
                ws.send(input.value)
                input.value = ''
                event.preventDefault()
            }
        </script>
    </body>
</html>
"""   

@app.get("/test")
async def get():
    return HTMLResponse(html)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    while True:
        data = await websocket.receive_text()
        await websocket.send_text(f"Message text was: {data}")


