from pydantic import BaseModel
from datetime import datetime, timedelta
import jwt, re, requests, bech32
from time import sleep
import asyncio, json
from zoneinfo import ZoneInfo
import os
import io, gzip
import validators
from urllib.parse import urlparse
import secrets
from fastapi import Depends, Cookie, HTTPException

from hashlib import sha256
import base64
import secp256k1
import re, idna




from bech32 import bech32_decode, convertbits, bech32_encode
import struct
from monstr.event.event import Event
from monstr.encrypt import Keys, NIP44Encrypt
from monstr.client.client import Client, ClientPool

from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip32Slip10Ed25519, Bip32Slip10Secp256k1
from safebox.acorn import Acorn
from typing import Optional, List

from fastapi import FastAPI, HTTPException
from app.appmodels import RegisteredSafebox
from sqlmodel import Field, Session, SQLModel, create_engine, select
from app.config import Settings, ConfigWithFallback



settings = Settings()
config = ConfigWithFallback()
# Secret key for signing JWT
# SECRET_KEY = "foobar"
# ALGORITHM = "HS256"
engine = create_engine(settings.DATABASE)
# SQLModel.metadata.create_all(engine,checkfirst=True)
timezone = ZoneInfo(settings.TZ)
# Function to generate JWT token

Tag = List[str]
Tags = List[Tag]

def get_tag_value(tags: Tags, key: str) -> Optional[str]:
    """
    Retrieve the value for a given key from a tag list.

    Example tags:
    [["key1", "value1"], ["key2", "value2"]]
    """
    for k, v in tags:
        if k == key:
            return v
    return ""

def generate_secure_pin():
    while True:
        pin = ''.join(secrets.choice('0123456789') for _ in range(4))
        if len(set(pin)) > 1:  # Ensure not all digits are the same
            return pin

def get_label_by_id(data, target_id):
    for entry in data:
        if entry[0] == target_id:
            return entry[1]
    return None

def get_id_by_label(data, target_label):
    for entry in data:
        if entry[1].replace(' ','').lower() == target_label.replace(' ','').lower():
            return entry[0]
    return None

def create_jwt_token(data: dict, expires_delta: timedelta = None):
    k = Keys(priv_k=config.SERVICE_NSEC)

    my_enc = NIP44Encrypt(k.private_key_bech32())

    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone) + expires_delta
    else:
        expire = datetime.now(timezone) + timedelta(days=1)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, config.SERVICE_NSEC, algorithm=settings.ALGORITHM)
    encrypted_encoded_jwt = my_enc.encrypt(encoded_jwt,k.public_key_hex())
    print(f"encrypted encoded jwt: {encrypted_encoded_jwt}")
    
    return encrypted_encoded_jwt

def decode_jwt_token(token: str):
    k = Keys(priv_k=config.SERVICE_NSEC)
    my_enc = NIP44Encrypt(k.private_key_bech32())
   

    try:
        decrypt_token = my_enc.decrypt(token, k.public_key_hex())
        decoded_token = jwt.decode(decrypt_token, config.SERVICE_NSEC, algorithms=[settings.ALGORITHM])
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
    k = Keys(priv_k=config.SERVICE_NSEC)
    my_enc = NIP44Encrypt(k.private_key_bech32())
    non_custodial = False

    if not access_token:
        raise HTTPException(status_code=401, detail="Missing access token")
    try:
        decrypt_access_token = my_enc.decrypt(access_token, k.public_key_hex())
        payload = jwt.decode(decrypt_access_token, config.SERVICE_NSEC, algorithms=[settings.ALGORITHM])
        access_key = payload.get("sub")
        



        if not access_key:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    print(f"from access_token {access_key}")
    try:
        k_from_token = Keys(priv_k=access_key)
        print(f"we have a private key in the access token! The public key is: {k_from_token.public_key_bech32()}")
        non_custodial = True
    except:
        print("just an ordinary access key")

    # Token is valid, now get the safebox
    with Session(engine) as session:
        if non_custodial:
            statement = select(RegisteredSafebox).where(RegisteredSafebox.npub== k_from_token.public_key_bech32())
        else:    
            statement = select(RegisteredSafebox).where(RegisteredSafebox.access_key==access_key)
        
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
       
        if safebox_found:
            handle = safebox_found.handle
            if non_custodial:
                print("non custodial set service nsec and home relay")
                safebox_found.nsec = k_from_token.private_key_bech32()
                safebox_found.home_relay = settings.HOME_RELAY

        else:

            raise HTTPException(status_code=404, detail=f"{access_key} not found")
        
    return safebox_found

async def fetch_safebox_by_npub(npub: str) -> RegisteredSafebox:


    with Session(engine) as session:
        
        statement = select(RegisteredSafebox).where(RegisteredSafebox.npub== npub)
        
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
       
        if safebox_found:
            print("found safebox!")

        else:

            raise Exception("Could not find safebox!")
        
    return safebox_found
async def fetch_safebox_by_access_key(access_key: str) -> RegisteredSafebox:


    with Session(engine) as session:
        
        statement = select(RegisteredSafebox).where(RegisteredSafebox.access_key== access_key)
        
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
       
        if safebox_found:
            print("found safebox!")

        else:

            raise Exception("Could not find safebox!")
        
    return safebox_found

async def fetch_safebox_by_handle(handle: str) -> RegisteredSafebox:

    print("fetch by handle")
    with Session(engine) as session:
        
        statement = select(RegisteredSafebox).where(RegisteredSafebox.handle==handle)
        
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
       
        if safebox_found:
            print("found safebox!")

        else:

            raise Exception("Could not find safebox!")
        
    return safebox_found

async def fetch_access_token(access_key:str):
    access_key=access_key.strip().lower()
    match = False
    # Authenticate user
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.access_key==access_key)
        print(statement)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            pass
            # Try to find withouy hypens
            leading_num = extract_leading_numbers(access_key)
            if not leading_num:
                return {"access_token": None}
            
            statement = select(RegisteredSafebox).where(RegisteredSafebox.access_key.startswith(leading_num))
            safeboxes = session.exec(statement)
            for each_safebox in safeboxes:
                access_key_on_record = each_safebox.access_key
                split_key= access_key_on_record.split("-")
                if split_key[1] in access_key and split_key[2] in access_key:
                    print("match!")
                    # set the access key to the one of record
                    access_key = access_key_on_record
                    match=True
                    break
                
                print(each_safebox)
            
            if not match:
                
                return {"access_token": None}


    # Create JWT token
    settings.TOKEN_EXPIRES_HOURS
    access_token = create_jwt_token({"sub": access_key}, expires_delta=timedelta(hours=settings.TOKEN_EXPIRES_HOURS,weeks=settings.TOKEN_EXPIRES_WEEKS))
    
   
    return access_token

async def db_lookup_safebox(npub: str) -> RegisteredSafebox:

   
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.npub==npub)
        safeboxes = session.exec(statement)
        try:
            safebox_found = safeboxes.first()
        except:
            raise HTTPException(status_code=404, detail=f"{npub} not found")
        
    return safebox_found

async def get_safebox(access_token: str = Cookie(None)):
    if not access_token:
        raise HTTPException(status_code=401, detail="Access token missing")
    
    safebox_found = await fetch_safebox(access_token=access_token)
    
    if not safebox_found:
        raise HTTPException(status_code=404, detail="Safebox not found")
    
    return safebox_found

async def get_acorn(access_token: str = Cookie(None)):
    if not access_token:
        # raise HTTPException(status_code=401, detail="Access token missing")
        return None
    
    safebox_found = await fetch_safebox(access_token=access_token)
    
    if not safebox_found:
        raise HTTPException(status_code=404, detail="Safebox not found")
    
    acorn_found = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
    await acorn_found.load_data()
    return acorn_found

async def get_acorn_by_npub(npub: str ):
    if not npub:
        # raise HTTPException(status_code=401, detail="Access token missing")
        return None
    
    safebox_found = await fetch_safebox_by_npub(npub)
    
    if not safebox_found:
        raise HTTPException(status_code=404, detail="Safebox not found")
    
    acorn_found = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
    await acorn_found.load_data()
    return acorn_found



def format_relay_url(relay: str) -> str:
    """
    Accepts a domain name, converts it to lowercase, strips spaces,
    and ensures it has the 'wss://' prefix.
    """
    relay = relay.strip().lower()

    if relay.startswith("ws://"):
        return relay

    if not relay.startswith("wss://"):
        relay = "wss://" + relay
    
    # Parse and validate the URL
    parsed_url = urlparse(relay)
    
    if not parsed_url.scheme or parsed_url.scheme != "wss":
        raise ValueError(f"Invalid URL scheme: {parsed_url.scheme}")
    
    if not parsed_url.netloc:
        raise ValueError(f"Invalid URL: {relay} (Missing hostname)")
    
    if "@" in parsed_url.netloc:
        raise ValueError(f"Invalid URL: {relay} (User credentials should not be included)")
    
    return relay




async def fetch_balance(id: int):
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.id==id)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()

        return safebox_found.balance

async def db_state_change(acorn_obj:Acorn=None ):
    print(f"db state change for {acorn_obj.handle}")
    same_state = True
    
    if acorn_obj:
        while same_state:
            await asyncio.sleep(3)
            with Session(engine) as session:

                statement = select(RegisteredSafebox).where(RegisteredSafebox.npub==acorn_obj.pubkey_bech32)
                safeboxes = session.exec(statement)
                safebox_found = safeboxes.first()
            balance = acorn_obj.get_balance()    
            if safebox_found.balance != balance:
                    print(f"we have a db state change: safebox balance: {safebox_found.balance} acorn balance: {balance}")
                    same_state = False
            
    return safebox_found.balance



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



def build_lnurlp_url(address: str, prefer_well_known: bool = True) -> str:
    """
    Convert a Lightning Address (name@domain) to its HTTPS LNURL-pay URL.
    Tries /.well-known/lnurlp/<name> (preferred) and can fall back to /lnurlp/<name>.

    Args:
        address: Lightning Address, e.g., "alice@example.com"
        prefer_well_known: If False, build /lnurlp/<name> instead.

    Returns:
        HTTPS URL string.
    """
    if not isinstance(address, str):
        raise ValueError("address must be a string")

    addr = address.strip()
    if "@" not in addr:
        raise ValueError("Invalid Lightning Address (missing @)")

    # Split into local-part and domain
    local, domain = addr.split("@", 1)
    if not local or not domain:
        raise ValueError("Invalid Lightning Address")

    # Basic local-part sanity (allow common email chars, incl. '+', '.', '-', '_')
    if not re.fullmatch(r"[A-Za-z0-9._%+\-~]+", local):
        raise ValueError("Local part contains unsupported characters")

    # IDNA (punycode) encode the domain to be safe with unicode domains
    try:
        ascii_domain = idna.encode(domain.strip().lower()).decode("ascii")
    except idna.IDNAError as e:
        raise ValueError(f"Invalid domain in Lightning Address: {e}")

    path = f"/.well-known/lnurlp/{local}" if prefer_well_known else f"/lnurlp/{local}"
    return f"https://{ascii_domain}{path}"


def encode_lnurl(url: str) -> str:
    """
    Encodes a URL into a Bech32-encoded LNURL string (HRP='lnurl').
    Requires a module exposing bech32_encode and convertbits akin to the 'bech32' package.
    """
    # If you're using the 'bech32' pip package, import its helpers:
    # from bech32 import bech32_encode, convertbits

    # ---- Minimal inline adaptors; replace with your bech32 helpers if already available ----
    from bech32 import bech32_encode, convertbits  # noqa: F401

    url_bytes = url.encode("utf-8")
    data = convertbits(list(url_bytes), 8, 5, True)
    if data is None:
        raise ValueError("Failed to convert URL bytes to Bech32 data")
    return bech32_encode("lnurl", data).upper()


def lightning_address_to_lnurl(address: str, prefer_well_known: bool = True) -> tuple[str, str]:
    """
    Convenience: take a Lightning Address, produce (pay_url, LNURL1...).
    """
    url = build_lnurlp_url(address, prefer_well_known=prefer_well_known)
    lnurl = encode_lnurl(url)
    return url, lnurl


# ---- Examples ----
# url, lnurl = lightning_address_to_lnurl("coffee@example.com")
# print(url)   # https://example.com/.well-known/lnurlp/coffee
# print(lnurl) # LNURL1...
#
# # If you need the /lnurlp/<name> style instead of well-known:
# url2, lnurl2 = lightning_address_to_lnurl("coffee@example.com", prefer_well_known=False)

    


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
    if hrp not in {"nprofile", "nevent", "naddr","nauth"} or data is None:
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
            if hrp in {"nprofile", "nevent", "naddr", "nauth"}:
                result["values"]["pubhex"] = value.hex()    

        elif tag == 1:  # Relay
            relay = value.decode("ascii")
            if "relay" not in result["values"]:
                result["values"]["relay"] = []
            result["values"]["relay"].append(relay)
        elif tag == 2:  # Author or nonce
            if hrp == "nauth":
                nonce = value.decode("ascii")
                result["values"]["nonce"] = nonce
            else:
                result["values"]["author"] = value.hex()
        elif tag == 3:  # Kind
            if hrp == "nauth":
                # kind = int(value.decode("ascii"))
                kind = struct.unpack(">I", value)[0]  # Parse 32-bit big-endian integer
                result["values"]["kind"] = kind
            else:
                kind = struct.unpack(">I", value)[0]  # Parse 32-bit big-endian integer
                result["values"]["kind"] = kind
        elif tag == 4:  # Transmittal Relays
             if hrp == "nauth":
                transmittal_relay = value.decode("ascii")
                if "transmittal_relay" not in result["values"]:
                    result["values"]["transmittal_relay"] = []
                result["values"]["transmittal_relay"].append(transmittal_relay)
        
        elif tag == 5:  # Transmittal Kind
            if hrp == "nauth":
                #transmittal_kind = int(value.decode("ascii"))
                transmittal_kind = struct.unpack(">I", value)[0]  # Parse 32-bit big-endian integer
                result["values"]["transmittal_kind"] = transmittal_kind
            else:
                kind = struct.unpack(">I", value)[0]  # Parse 32-bit big-endian integer
                result["values"]["transmittal_kind"] = transmittal_kind
         

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

def create_naddr_from_npub(npub_bech32, relays=None):
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
        # Tag 1: Relay (optional)
    
    # Convert 8-bit data to 5-bit data for Bech32 encoding
    converted_data = convertbits(encoded_data, 8, 5, True)
    # Encode the data as a Bech32 string with the "naddr" prefix
    naddr = bech32.bech32_encode("naddr", converted_data)
    
    return naddr

def create_nauth_from_npub( npub_bech32, 
                            relays=None, 
                            nonce:str=None, 
                            kind: int=None, 
                            transmittal_relays = None, 
                            transmittal_kind: int =None):
    
    #TODO This function has been deprecated by create_nauth

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
        relay = None
        for relay in relays:
            relay_bytes = relay.encode("ascii")
            encoded_data.append(1)  # Tag 1
            encoded_data.append(len(relay_bytes))  # Length of the relay string
            encoded_data.extend(relay_bytes)  # Relay string as bytes
        # Tag 1: Relay (optional)
       
    # Tag 2: nonce (optional)
    if nonce:
        nonce_bytes = nonce.encode("ascii")        
        encoded_data.append(2)
        encoded_data.append(len(nonce_bytes))  # Length of the public key (32 bytes)
        encoded_data.extend(nonce_bytes)  # Public key bytes
    
    # Tag 3: kind (optional)    
    if kind:
        # kind_bytes = str(kind).encode("ascii")  
        kind_bytes = struct.pack(">I", kind)      
        encoded_data.append(3)
        encoded_data.append(len(kind_bytes))  # Length of the public key (32 bytes)
        encoded_data.extend(kind_bytes)  # Public key bytes

    # Tag 4: Transmittal Relay (optional)
    if transmittal_relays:
        
        for transmittal_relay in transmittal_relays:
            transmittal_relay_bytes = transmittal_relay.encode("ascii")
            encoded_data.append(4)  # Tag 4
            encoded_data.append(len(transmittal_relay_bytes))  # Length of the relay string
            encoded_data.extend(transmittal_relay_bytes)  # Relay string as bytes
        
    # Tag 5: transmittal kind (optional)    
    if transmittal_kind:
        # transmittal_kind_bytes = str(transmittal_kind).encode("ascii")   
        transmittal_kind_bytes = struct.pack(">I", transmittal_kind)     
        encoded_data.append(5)
        encoded_data.append(len(transmittal_kind_bytes))  # Length of the public key (32 bytes)
        encoded_data.extend(transmittal_kind_bytes)  # 


    # Convert 8-bit data to 5-bit data for Bech32 encoding
    converted_data = convertbits(encoded_data, 8, 5, True)

    # Encode the data as a Bech32 string with the "naddr" prefix
    nauth = bech32.bech32_encode("nauth", converted_data)
    
    return nauth

def create_nauth(   npub, 
                    nonce:str=None,                                                       
                    auth_kind: int=None, 
                    auth_relays=None,
                    transmittal_npub: str = None,
                    transmittal_kind= None,  
                    transmittal_relays = None,
                    name: str = None,
                    scope: str = None,
                    grant: str = None 
                ):
    
    # Decode the npub Bech32 string
    hrp, data = bech32.bech32_decode(npub)
    if hrp != "npub" or data is None:
        raise ValueError("Invalid npub Bech32 string")
    
    # Convert 5-bit data back to 8-bit data
    pubkey_bytes = bytes(convertbits(data, 5, 8, False))
    if len(pubkey_bytes) != 32:
        raise ValueError("Invalid public key length in npub Bech32 string")
    
    # Create the encoded data for nprofile
    encoded_data = []

    # Tag 0 : npub in hex
    # Tag 1 : nonce
    # Tag 2 : auth_kind
    # Tag 3 : auth_relays
    # Tag 4 : transmittal_npub in hex
    # Tag 5 : transmittal_kind
    # Tag 6 : transmittal_relays
    # Tag 7 : name 
    # Tag 8 : scope
    # Tag 9 : grant

    # Tag 0: Special (public key)
    encoded_data.append(0)  # Tag 0
    encoded_data.append(len(pubkey_bytes))  # Length of the public key (32 bytes)
    encoded_data.extend(pubkey_bytes)  # Public key bytes

    # Tag 1: nonce (optional)
    if nonce:
        nonce_bytes = nonce.encode("ascii")        
        encoded_data.append(1)
        encoded_data.append(len(nonce_bytes))  # Nonce
        encoded_data.extend(nonce_bytes)  # Public key bytes

    # Tag 2: auth_kind (optional)    
    if auth_kind:
        # kind_bytes = str(kind).encode("ascii")  
        auth_kind_bytes = struct.pack(">I", auth_kind)      
        encoded_data.append(2)
        encoded_data.append(len(auth_kind_bytes))  # Length of the public key (32 bytes)
        encoded_data.extend(auth_kind_bytes)  # Public key bytes

    # Tag 3: Auth Relays (optional)
    if auth_relays:
        auth_relay = None
        for auth_relay in auth_relays:
            auth_relay_bytes = auth_relay.encode("ascii")
            encoded_data.append(3)  # Tag 3
            encoded_data.append(len(auth_relay_bytes))  # Length of the relay string
            encoded_data.extend(auth_relay_bytes)  # Relay string as bytes
    
    # Tag 4: Transmittal npub
    if transmittal_npub:
        # Decode the npub Bech32 string
        transmittal_hrp, transmittal_data = bech32.bech32_decode(transmittal_npub)
        if transmittal_hrp != "npub" or transmittal_hrp is None:
            raise ValueError("Invalid transmittal npub Bech32 string")
        
        # Convert 5-bit data back to 8-bit data
        transmittal_pubkey_bytes = bytes(convertbits(transmittal_data, 5, 8, False))
        if len(transmittal_pubkey_bytes) != 32:
            raise ValueError("Invalid public key length in transmittal npub Bech32 string")
        # Tag 4:  (public key)
        encoded_data.append(4)  # Tag 4
        encoded_data.append(len(transmittal_pubkey_bytes))  # Length of the public key (32 bytes)
        encoded_data.extend(transmittal_pubkey_bytes)  # Public key bytes


    # Tag 5: transmittal_kind (optional)    
    if transmittal_kind:
        # kind_bytes = str(kind).encode("ascii")  
        transmittal_kind_bytes = struct.pack(">I", transmittal_kind)      
        encoded_data.append(5)
        encoded_data.append(len(transmittal_kind_bytes))  # Length of the public key (32 bytes)
        encoded_data.extend(transmittal_kind_bytes)  # Public key bytes

    # Tag 6: Transmittal Relay (optional)
    if transmittal_relays:
        
        for transmittal_relay in transmittal_relays:
            transmittal_relay_bytes = transmittal_relay.encode("ascii")
            encoded_data.append(6)  # Tag 6
            encoded_data.append(len(transmittal_relay_bytes))  # Length of the relay string
            encoded_data.extend(transmittal_relay_bytes)  # Relay string as bytes
        
    # Tag 7: name (optional)
    if name:
        name_bytes = name.encode("ascii")        
        encoded_data.append(7)
        encoded_data.append(len(name_bytes))  # Nonce
        encoded_data.extend(name_bytes)  # Public key bytes
    
    # Tag 8: scope (optional)
    if scope:
        scope_bytes =scope.encode("ascii")        
        encoded_data.append(8)
        encoded_data.append(len(scope_bytes))  # Nonce
        encoded_data.extend(scope_bytes)  # Public key bytes

    # Tag 9: scope (optional)
    if grant:
        grant_bytes =grant.encode("ascii")        
        encoded_data.append(9)
        encoded_data.append(len(grant_bytes))  # Nonce
        encoded_data.extend(grant_bytes)  # Public key bytes


    # Convert 8-bit data to 5-bit data for Bech32 encoding
    converted_data = convertbits(encoded_data, 8, 5, True)

    # Encode the data as a Bech32 string with the "naddr" prefix
    nauth = bech32.bech32_encode("nauth", converted_data)
    
    return nauth

def mod_nauth(      nauth:str,
                    npub: str = None , 
                    nonce:str   =None,                                                       
                    auth_kind: int=None, 
                    auth_relays=None,
                    transmittal_npub: str = None,
                    transmittal_kind= None,  
                    transmittal_relays = None,
                    name: str = None,
                    scope: str = None,
                    grant: str = None 
                ):
    
    
    # parse existing nauth
    orig_parsed_nauth = parse_nauth(nauth)
    orig_pubhex = orig_parsed_nauth["values"].get("pubhex", None)
    orig_nonce = orig_parsed_nauth["values"].get("nonce", None)
    orig_auth_kind = orig_parsed_nauth["values"].get("auth_kind", None)
    orig_auth_relays = orig_parsed_nauth["values"].get("auth_relays", None)
    orig_trasmittal_kind = orig_parsed_nauth["values"].get("transmittal_kind", None)
    orig_transmittal_relays = orig_parsed_nauth["values"].get("transmittal_relays", None)
    orig_name = orig_parsed_nauth["values"].get("name", None)
    orig_scope = orig_parsed_nauth["values"].get("scope", None)
    orig_grant = orig_parsed_nauth["values"].get("grant", None)
    
    if npub:
        new_npub = npub
    elif orig_pubhex:
        new_npub = hex_to_npub(orig_pubhex)
    else:
        new_npub = None
   
    new_npub = npub if npub is not None else (hex_to_npub(orig_pubhex) if orig_pubhex is not None else None)
    new_nonce = nonce if nonce is not None else orig_nonce
    new_auth_kind = auth_kind if auth_kind is not None else orig_auth_kind
    new_auth_relays = auth_relays if auth_relays is not None else orig_auth_relays
    new_transmittal_kind = transmittal_kind if transmittal_kind is not None else orig_trasmittal_kind
    new_transmittal_relays = transmittal_relays if transmittal_kind is not None else orig_transmittal_relays
    new_name = name if name is not None else orig_name
    new_scope = scope if scope is not None else orig_scope
    new_grant = grant if grant is not None else orig_grant

    new_nauth = create_nauth(   new_npub,
                                nonce= new_nonce,
                                auth_kind = new_auth_kind,
                                auth_relays= new_auth_relays,
                                transmittal_kind= new_transmittal_kind,
                                transmittal_relays=new_transmittal_relays,
                                name=new_name,
                                scope=new_scope,
                                grant=new_grant
                             )
    
    return new_nauth

def parse_nauth(encoded_string):
    # Decode the Bech32 string
    hrp, data = bech32_decode(encoded_string)
    print(f"hrp {hrp}")
    if hrp not in {"nprofile", "nevent", "naddr","nauth"} or data is None:
        raise ValueError("Invalid Bech32 string or unsupported prefix")

    # Convert 5-bit data to 8-bit for processing
    decoded_data = bytes(convertbits(data, 5, 8, False))

    # Initialize result dictionary
    result = {"prefix": hrp, "values": {}}

    # Tag 0 : npub in hex
    # Tag 1 : nonce
    # Tag 2 : auth_kind
    # Tag 3 : auth_relays
    # Tag 4 : transmittal_npub in hex
    # Tag 5 : transmittal_kind
    # Tag 6 : transmittal_relays 
    # Tag 7 : name
    # Tag 8 : scope
    # Tag 9 : grant

 
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
            if hrp in {"nprofile", "nevent", "naddr", "nauth"}:
                result["values"]["pubhex"] = value.hex()    

        elif tag == 1:  # None
            nonce = value.decode("ascii")
            if "nonce" not in result["values"]:
                result["values"]["nonce"] = nonce
            # result["values"]["nonce"].append(nonce)
        
        elif tag == 2:  # auth_kind
            
            auth_kind = struct.unpack(">I", value)[0]
            result["values"]["auth_kind"] = auth_kind
            
        elif tag == 3:  # Auth Relays
            auth_relays = value.decode("ascii")
            if "auth_relays" not in result["values"]:
                result["values"]["auth_relays"] = []
            result["values"]["auth_relays"].append(auth_relays)

        elif tag == 4:  # transmittal_npub
            
            result["values"]["transmittal_pubhex"] = value.hex() 

        elif tag == 5:  # transmittal_kind
            
            transmittal_kind = struct.unpack(">I", value)[0]
            result["values"]["transmittal_kind"] = transmittal_kind  
        
        elif tag == 6:  # Transmittal Relays
            transmittal_relays = value.decode("ascii")
            if "transmittal_relays" not in result["values"]:
                result["values"]["transmittal_relays"] = []
            result["values"]["transmittal_relays"].append(transmittal_relays)
        
        elif tag == 7:  # None
            name = value.decode("ascii")
            if "name" not in result["values"]:
                result["values"]["name"] = name
            
        elif tag == 8:  # None
            scope = value.decode("ascii")
            if "scope" not in result["values"]:
                result["values"]["scope"] = scope

        elif tag == 9:  # None
            grant = value.decode("ascii")
            if "grant" not in result["values"]:
                result["values"]["grant"] = grant
            
      

    return result

def parse_nembed(encoded_string):
    # Decode the Bech32 string
    hrp, data = bech32_decode(encoded_string)
    # print(f"hrp {hrp} data {data}")
    if hrp not in {"nembed"} or data is None:
        raise ValueError("Invalid Bech32 string or unsupported prefix")

    # Convert 5-bit data to 8-bit for processing
    decoded_data = bytes(convertbits(data, 5, 8, False))


    
    try:
        json_obj = json.loads(decoded_data)  
    except:
        json_obj = {}

    return json_obj

def create_nembed(json_obj):
    encoded_data = []
    if type(json_obj) != dict:
        raise ValueError("not a json objecte")
    json_obj_str = json.dumps(json_obj)
    json_bytes = json_obj_str.encode("ascii") 
    encoded_data.extend(json_bytes)  # Public key bytes    
    converted_data = convertbits(encoded_data, 8, 5, True)
    
    return bech32_encode("nembed",converted_data )

def create_nembed_compressed(json_obj):
    buffer = io.BytesIO()
    encoded_data = []

    if not isinstance(json_obj, (dict, list)):
        raise ValueError("Expected a JSON object (dict) or JSON array (list)")
    
    json_obj_str = json.dumps(json_obj)

    with gzip.GzipFile(fileobj=buffer, mode="wb") as gz:
        gz.write(json_obj_str.encode())
    
    json_bytes = buffer.getvalue() 
    encoded_data.extend(json_bytes)  # Public key bytes    
    converted_data = convertbits(encoded_data, 8, 5, True)
    
    return bech32_encode("nembed",converted_data )

def parse_nembed_compressed(encoded_string):
    # Decode the Bech32 string
    hrp, data = bech32_decode(encoded_string)
    # print(f"hrp {hrp} data {data}")
    if hrp not in {"nembed"} or data is None:
        raise ValueError("Invalid Bech32 string or unsupported prefix")

    # Convert 5-bit data to 8-bit for processing
    decoded_data = bytes(convertbits(data, 5, 8, False))
    # this is gzipped data

    buffer = io.BytesIO(decoded_data)
    with gzip.GzipFile(fileobj=buffer, mode="rb") as gz:
        decompressed_data = gz.read()
    
    try:
        json_obj = json.loads(decompressed_data.decode())  
    except:
        json_obj = {}

    return json_obj

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

def hex_to_npub(hex_key: str) -> str:
    """
    Converts a hex-encoded Nostr public key to its corresponding npub Bech32 representation.
    
    :param hex_key: A Nostr public key in hex format.
    :return: The corresponding npub public key in Bech32 format.
    """
    if len(hex_key) != 64:
        raise ValueError("Invalid hex key length. Must be 64 characters.")

    try:
        # Convert hex string to bytes
        key_bytes = bytes.fromhex(hex_key)
    except ValueError:
        raise ValueError("Invalid hex key format.")

    # Convert 8-bit bytes to 5-bit chunks
    encoded_data = bech32.convertbits(key_bytes, 8, 5, True)
    
    if encoded_data is None:
        raise ValueError("Error in converting hex data to Bech32 format.")

    # Encode using Bech32 with 'npub' prefix
    npub = bech32.bech32_encode("npub", encoded_data)
    
    return npub

def validate_local_part(local_part: str) -> bool:
    """
    Validates the local part of an email address.

    Args:
        local_part (str): The local part of the email (before @).

    Returns:
        bool: True if valid, False otherwise.
    """
    # Check length constraint
    if not (1 <= len(local_part) <= 64):
        return False

    # Regular expression for valid local part
    local_part_regex = r'^(?!\.)(?!.*\.\.)[A-Za-z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&\'*+/=?^_`{|}~-]+)*$'

    return bool(re.fullmatch(local_part_regex, local_part))

def generate_nonce(length:int = 16):
    return os.urandom(length).hex()


async def send_zap_receipt(nostr:str, lninvoice:str=None):

    service_k = Keys(priv_k=config.SERVICE_NSEC)
    try:
        # print(f"nostr parm: type: {type(nostr)} {nostr}")
        # nostr_decode=urllib.parse.unquote(nostr)
        # print(f"nostr_decode: {nostr_decode}")
        try:
            nostr_obj = json.loads(nostr)
            # print(f"nostr obj: {nostr_obj}")
            zap_request = Event(    id=nostr_obj['id'],
                                    pub_key=nostr_obj['pubkey'], 
                                    kind=nostr_obj['kind'],
                                    sig=nostr_obj['sig'],
                                    content=nostr_obj['content'],
                                    tags=nostr_obj['tags'], 
                                    created_at=nostr_obj['created_at'])
            # print(f"zap receipt tags: {zap_receipt.tags}")
        except:
            print("could not load json object")

        #Extract the tags we need
        receipt_tags = []
        zap_relays = None
        for each in zap_request.tags:
            if each[0] == "p":                
                receipt_tags.append(["p",each[1]])
            elif each[0] == "e":
                receipt_tags.append(["e",each[1]])
            elif each[0] == "relays":
                zap_relays = each[1:]

        
        receipt_tags.append(["description",json.dumps(nostr_obj)])
        receipt_tags.append(["bolt11", lninvoice])

        print(f"resulting: {receipt_tags} {zap_relays}")
        # create zap receipt
        zap_receipt = Event(    kind=9735,
                                pub_key= service_k.public_key_hex(),
                                created_at=zap_request.created_at,
                                tags = receipt_tags,
                                content= None
                            )
    


        async with ClientPool(zap_relays) as c:
            zap_receipt.sign(priv_key=service_k.private_key_hex())
            # print(f"zap receipt: {zap_receipt.is_valid()}")
            print(f"zap relays: {zap_relays}")

            c.publish(zap_receipt)
            # print("zap published!")

       
        # print("parsed zap receipt!")
    except:
        print("could not parse zap receipt!")
    
    # print(nostr_decode=urllib.parse.unquote(nostr))

    return

def recover_nsec_from_seed(seed_phrase: str, legacy: bool = False):
    mnemo = Mnemonic("english")
    print(f"legacy: {legacy}")
    seed = Bip39SeedGenerator(seed_phrase).Generate()
    if legacy:
        bip32_ctx = Bip32Slip10Ed25519.FromSeed(seed)
    else:
        bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed)
    
    seed_private_key_hex = bip32_ctx.PrivateKey().Raw().ToBytes().hex()
   

    data_bytes = bytes.fromhex(seed_private_key_hex)
    data_5bit = convertbits(data_bytes, 8, 5)
    bech32_address = bech32_encode("nsec", data_5bit)

    return bech32_address

def generate_name_from_hex(hex_string):
    # Ensure the input is a valid 32-byte hex string
    if len(hex_string) != 64:
        raise ValueError("Input must be a 32-byte hex string (64 characters).")

    # Load BIP-0039 word list
    mnemonic = Mnemonic("english")
    word_list = mnemonic.wordlist

    # Extract the first four bytes (8 hex characters)
    first_four_bytes = hex_string[:8]

    # Convert these bytes to a binary string (32 bits)
    binary_string = bin(int(first_four_bytes, 16))[2:].zfill(32)

    # Split the binary string into two 11-bit values and one 10-bit value
    first_11_bit = int(binary_string[:11], 2)
    second_11_bit = int(binary_string[11:22], 2)
    ten_bit = int(binary_string[22:32], 2)

    # Look up the words corresponding to the 11-bit values
    first_word = word_list[first_11_bit]
    second_word = word_list[second_11_bit]

    # Create the hyphen-separated name
    name = f"{first_word}-{second_word}-{ten_bit}"

    return name


def generate_access_key_from_hex(hex_string):
    # Ensure the input is a valid 32-byte hex string
    if len(hex_string) != 64:
        raise ValueError("Input must be a 32-byte hex string (64 characters).")

    # Load BIP-0039 word list
    mnemonic = Mnemonic("english")
    word_list = mnemonic.wordlist

    # Extract the first four bytes (8 hex characters)
    first_four_bytes = hex_string[:8]

    # Convert these bytes to a binary string (32 bits)
    binary_string = bin(int(first_four_bytes, 16))[2:].zfill(32)

    # Split the binary string into two 11-bit values and one 10-bit value
    first_11_bit = int(binary_string[:11], 2)
    second_11_bit = int(binary_string[11:22], 2)
    ten_bit = int(binary_string[22:32], 2)

    # Look up the words corresponding to the 11-bit values
    first_word = word_list[first_11_bit]
    second_word = word_list[second_11_bit]

    # Create the hyphen-separated name
    access_key = f"{ten_bit}-{first_word}-{second_word}"

    return access_key

def generate_new_identity():
    # This function generates a new service identity
    k = Keys()
    handle = generate_name_from_hex(k.public_key_hex())
    access_key = generate_access_key_from_hex(k.private_key_hex())
    return handle, access_key

def generate_pnr(length=6):
    """Generates a six-character PNR using a cryptographically secure method."""
    characters = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # Excludes I, O, 0, 1
    return ''.join(secrets.choice(characters) for _ in range(length))

async def listen_for_request(acorn_obj: Acorn, kind: int = 1060,since_now:int=None, relays: List=None):
   """List for transfer"""
   #TODO change this to listen_for_transfer
    
    

    records_out = await acorn_obj.get_user_records(record_kind=kind, since=since_now, relays=relays)
    print(f"listen for request {records_out}")
    
    return records_out[0]["payload"], records_out[0]["presenter"],

def lnaddress_to_safebox_npub(lnaddress: str):
    relays = []
    try:
        parts = lnaddress.lower().split('@')
        nip05_url = f"https://{parts[1]}/.well-known/safebox.json?name={parts[0]}"
        response = requests.get(nip05_url)
        pubkey = response.json()['safebox']
        
    except:
        pubkey = None   

    try:
        relays = response.json()['relays']
    except:
        relays = []    
    return pubkey, relays  

#################################

def sign_payload(payload: str, private_key_hex: str):
    
    digest = sha256(payload.encode('utf-8')).digest()
    pk = secp256k1.PrivateKey()
    pk.deserialize(private_key_hex)
    sig = pk.schnorr_sign(digest, bip340tag='', raw=True)
    return sig.hex()

def verify_payload(payload: str, signature_hex: str, public_key_hex: str) -> bool:
    
    digest = sha256(payload.encode('utf-8')).digest()
    pubkey = secp256k1.PublicKey()
    pubkey.deserialize(bytes.fromhex('02'+public_key_hex))
    signature = bytes.fromhex(signature_hex)
    return pubkey.schnorr_verify(digest, signature, bip340tag='', raw=True)

def starts_with(test: str, target: str) -> bool:
    """
    Case-insensitive check: return True if 'target' starts with 'test'.
    """
    if not isinstance(test, str) or not isinstance(target, str):
        raise TypeError("Both arguments must be strings.")
    
    return target.lower().startswith(test.lower())


    