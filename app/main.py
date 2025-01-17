from sqlmodel import Field, Session, SQLModel, create_engine, select
from fastapi import FastAPI, Request, BackgroundTasks
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



# Define a root endpoint
@app.get("/")
def read_root(request: Request):
    return templates.TemplateResponse( "welcome.html", {"request": request, "title": "Welcome Page", "message": "Welcome to Safebox Web!"})
    # return {"message": "Welcome to the Safebox app!"}



