from pydantic import BaseModel
from datetime import datetime, timedelta
import jwt, re, requests, bech32
from time import sleep
import asyncio
from zoneinfo import ZoneInfo

from bech32 import bech32_decode, convertbits
import struct

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
timezone = ZoneInfo(settings.TZ)
# Function to generate JWT token
def create_jwt_token(data: dict, expires_delta: timedelta = None):
    
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone) + expires_delta
    else:
        expire = datetime.now(timezone) + timedelta(days=1)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SERVICE_SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def decode_jwt_token(token: str):
    try:
        decoded_token = jwt.decode(token, settings.SERVICE_SECRET_KEY, algorithms=[settings.ALGORITHM])
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
        payload = jwt.decode(access_token, settings.SERVICE_SECRET_KEY, algorithms=[settings.ALGORITHM])
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



def parse_nostr_bech32(encoded_string):
    # Decode the Bech32 string
    hrp, data = bech32_decode(encoded_string)
    if hrp not in {"nprofile", "nevent", "naddr"} or data is None:
        raise ValueError("Invalid Bech32 string or unsupported prefix")

    # Convert 5-bit data to 8-bit for processing
    decoded_data = bytes(convertbits(data, 5, 8, False))

    # Initialize result dictionary
    result = {"prefix": hrp, "values": {}}

    index = 0
    while index < len(decoded_data):
        # Extract the tag and length
        tag = decoded_data[index]
        index += 1
        length = decoded_data[index]
        index += 1

        # Extract the corresponding value based on length
        value = decoded_data[index : index + length]
        index += length

        # Parse based on the tag
        if tag == 0:  # Special
            if hrp in {"nprofile", "nevent", "naddr"}:
                result["values"]["pubhex"] = value.hex()
        elif tag == 1:  # Relay
            relay = value.decode("ascii")
            if "relay" not in result["values"]:
                result["values"]["relay"] = []
            result["values"]["relay"].append(relay)
        elif tag == 2:  # Author
            result["values"]["author"] = value.hex()
        elif tag == 3:  # Kind
            kind = struct.unpack(">I", value)[0]  # Parse 32-bit big-endian integer
            result["values"]["kind"] = kind

    return result


async def create_nprofile_from_hex(npub, relays=None):
    if len(npub) != 64:
        raise ValueError("Invalid public key length. Must be 32 bytes (64 hex characters).")
    
    # Convert the hex-encoded public key to bytes
    pubkey_bytes = bytes.fromhex(npub)
    
    # Create the encoded data
    data = []

    # Tag 0: Special (public key)
    data.append(0)  # Tag 0
    data.append(len(pubkey_bytes))  # Length of the public key (32 bytes)
    data.extend(pubkey_bytes)  # Public key bytes

    # Tag 1: Relay
    if relays:
        for relay in relays:
            relay_bytes = relay.encode("ascii")
            data.append(1)  # Tag 1
            data.append(len(relay_bytes))  # Length of the relay string
            data.extend(relay_bytes)  # Relay string as bytes

    # Convert 8-bit data to 5-bit data for Bech32 encoding
    converted_data = convertbits(data, 8, 5, True)

    # Encode the data as a Bech32 string with the "nprofile" prefix
    nprofile = bech32.bech32_encode("nprofile", converted_data)
    
    return nprofile

def create_nprofile_from_npub(npub_bech32, relays=None):
    # Decode the npub Bech32 string
    hrp, data = bech32.bech32_decode(npub_bech32)
    if hrp != "npub" or data is None:
        raise ValueError("Invalid npub Bech32 string")
    
    # Convert 5-bit data back to 8-bit data
    pubkey_bytes = bytes(convertbits(data, 5, 8, False))
    if len(pubkey_bytes) != 32:
        raise ValueError("Invalid public key length in npub Bech32 string")
    
    # Create the encoded data for nprofile
    encoded_data = []

    # Tag 0: Special (public key)
    encoded_data.append(0)  # Tag 0
    encoded_data.append(len(pubkey_bytes))  # Length of the public key (32 bytes)
    encoded_data.extend(pubkey_bytes)  # Public key bytes

    # Tag 1: Relay (optional)
    if relays:
        for relay in relays:
            relay_bytes = relay.encode("ascii")
            encoded_data.append(1)  # Tag 1
            encoded_data.append(len(relay_bytes))  # Length of the relay string
            encoded_data.extend(relay_bytes)  # Relay string as bytes

    # Convert 8-bit data to 5-bit data for Bech32 encoding
    converted_data = convertbits(encoded_data, 8, 5, True)

    # Encode the data as a Bech32 string with the "nprofile" prefix
    nprofile = bech32.bech32_encode("nprofile", converted_data)
    
    return nprofile

def npub_to_hex(npub: str) -> str:
    """
    Converts a Nostr npub public key to its corresponding hex representation.
    
    :param npub: A Nostr public key in Bech32 format (starting with 'npub')
    :return: The corresponding hex public key.
    """
    if not npub.startswith("npub"):
        raise ValueError("Invalid npub format. It should start with 'npub'.")

    # Decode Bech32 npub format
    hrp, data = bech32.bech32_decode(npub)
    
    if hrp != "npub" or data is None:
        raise ValueError("Invalid npub Bech32 encoding.")

    # Convert 5-bit chunks to 8-bit bytes
    decoded_bytes = bech32.convertbits(data, 5, 8, False)
    
    if decoded_bytes is None:
        raise ValueError("Error in converting Bech32 data.")

    # Convert bytes to hex string
    return bytes(decoded_bytes).hex()