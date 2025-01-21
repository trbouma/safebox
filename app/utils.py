from pydantic import BaseModel
from datetime import datetime, timedelta
import jwt, re, requests, bech32
from time import sleep
import asyncio

from fastapi import FastAPI, HTTPException
from app.appmodels import RegisteredSafebox
from sqlmodel import Field, Session, SQLModel, create_engine, select
from app.config import Settings

settings = Settings()
# Secret key for signing JWT
# SECRET_KEY = "foobar"
# ALGORITHM = "HS256"
engine = create_engine(settings.DATABASE)
SQLModel.metadata.create_all(engine)

# Function to generate JWT token
def create_jwt_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def decode_jwt_token(token: str):
    try:
        decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return decoded_token
    except jwt.ExpiredSignatureError:
        return "Token has expired"
    except jwt.InvalidTokenError:
        return "Invalid token"

# Example Login Function
def authenticate_user(username: str, password: str):
    # Mock user authentication
    if username == "user" and password == "password":
        return {"username": username}
    return None

async def fetch_safebox(access_token) -> RegisteredSafebox:
    if not access_token:
        raise HTTPException(status_code=401, detail="Missing access token")
    try:
        payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        access_key = payload.get("sub")
        if not access_key:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    print(access_key)
    # Token is valid, now get the safebox
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.access_key==access_key)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
        if safebox_found:
            handle = safebox_found.handle
        else:

            raise HTTPException(status_code=404, detail=f"{access_key} not found")
        
    return safebox_found

async def fetch_balance(id: int):
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.id==id)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()

        return safebox_found.balance

async def db_state_change(id: int):
    # print(f"db state change for {id}")
    await asyncio.sleep(5)
    return

def check_ln_address(ln_address: str):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    # pass the regular expression
    # and the string into the fullmatch() method
    if(re.fullmatch(regex, ln_address)):
        return True 
    else:
        False  

def decode_lnurl(lnurl: str) -> str:
    """
    Decodes a Bech32-encoded LNURL into a readable URL.

    Args:
        lnurl (str): The LNURL string to decode.

    Returns:
        str: The decoded URL.

    Raises:
        ValueError: If the LNURL is not a valid Bech32 string.
    """
    try:
        # Decode the Bech32 string
        hrp, data = bech32.bech32_decode(lnurl)
        if hrp is None or data is None:
            raise ValueError("Invalid LNURL encoding")

        # Convert the decoded data into bytes
        decoded_bytes = bech32.convertbits(data, 5, 8, False)
        if decoded_bytes is None:
            raise ValueError("Failed to convert Bech32 data to bytes")

        # Convert the bytes to a readable URL
        url = bytes(decoded_bytes).decode("utf-8")
        return url
    except Exception as e:
        raise ValueError(f"Error decoding LNURL: {e}")
    
def extract_leading_numbers(input_string: str) -> str:
    """
    Extracts the leading numbers from a string.
    
    Args:
        input_string (str): The input string containing numbers and text.
    
    Returns:
        int: The leading numbers as an integer. Returns None if no numbers are found.
    """
    match = re.match(r"^\d+", input_string)
    if match:
        return match.group()
    return None