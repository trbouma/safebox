from sqlmodel import Field, Session, SQLModel, create_engine, select
from fastapi import FastAPI, Request, BackgroundTasks, WebSocket
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import asyncio
from contextlib import asynccontextmanager

from app.config import Settings
from app.routers import lnaddress, safebox, scanner
from app.tasks import periodic_task


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create Task
    asyncio.create_task(periodic_task())
    yield
    pass
   

# Create Settings:
settings = Settings()
print(settings)

# Create instance of database
engine = create_engine(settings.DATABASE)
SQLModel.metadata.create_all(engine)


# Create an instance of the FastAPI application
origins = ["*"]
app = FastAPI()
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

templates = Jinja2Templates(directory="app/templates")
app.mount("/src", StaticFiles(directory="app/src"), name="src")
app.mount("/img", StaticFiles(directory="app/img"), name="img")



# Define a root endpoint
@app.get("/")
def read_root(request: Request):
    return templates.TemplateResponse(  "welcome.html", 
                                        {   "request": request, 
                                            "title": "Welcome Page", 
                                            "branding": settings.BRANDING,
                                            "branding_message": settings.BRANDING_MESSAGE})

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


