from sqlmodel import Field, Session, SQLModel, create_engine, select
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware



from app.routers import lnaddress


# Create instance of database
engine = create_engine("sqlite:///data/safebox.db")
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

# Define a root endpoint
@app.get("/")
def read_root():
    return {"message": "Welcome to the Safebox app!"}

# Define another example endpoint

