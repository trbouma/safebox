from pydantic import BaseModel
from datetime import datetime, timedelta
import jwt, re, requests, bech32
from time import sleep
import asyncio, json
from zoneinfo import ZoneInfo
import os
import io, gzip


from bech32 import bech32_decode, convertbits, bech32_encode
import struct
from monstr.event.event import Event
from monstr.encrypt import Keys
from monstr.client.client import Client, ClientPool


from fastapi import FastAPI, HTTPException
from app.appmodels import RegisteredSafebox
from sqlmodel import Field, Session, SQLModel, create_engine, select
from app.config import Settings

settings = Settings()
# Secret key for signing JWT
# SECRET_KEY = "foobar"
# ALGORITHM = "HS256"
engine = create_engine(settings.DATABASE)
# SQLModel.metadata.create_all(engine,checkfirst=True)
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

async def db_state_change(id: int=0):
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
                    transmittal_kind= None,  
                    transmittal_relays = None,
                    name: str = None 
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
    # Tag 4 : transmittal_kind
    # Tag 5 : transmittal_relays
    # Tag 6 : name 

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
    
    
    # Tag 4: transmittal_kind (optional)    
    if transmittal_kind:
        # kind_bytes = str(kind).encode("ascii")  
        transmittal_kind_bytes = struct.pack(">I", transmittal_kind)      
        encoded_data.append(4)
        encoded_data.append(len(transmittal_kind_bytes))  # Length of the public key (32 bytes)
        encoded_data.extend(transmittal_kind_bytes)  # Public key bytes

    # Tag 5: Transmittal Relay (optional)
    if transmittal_relays:
        
        for transmittal_relay in transmittal_relays:
            transmittal_relay_bytes = transmittal_relay.encode("ascii")
            encoded_data.append(5)  # Tag 5
            encoded_data.append(len(transmittal_relay_bytes))  # Length of the relay string
            encoded_data.extend(transmittal_relay_bytes)  # Relay string as bytes
        
    # Tag 6: nonce (optional)
    if name:
        name_bytes = nonce.encode("ascii")        
        encoded_data.append(1)
        encoded_data.append(len(name_bytes))  # Nonce
        encoded_data.extend(name_bytes)  # Public key bytes


    # Convert 8-bit data to 5-bit data for Bech32 encoding
    converted_data = convertbits(encoded_data, 8, 5, True)

    # Encode the data as a Bech32 string with the "naddr" prefix
    nauth = bech32.bech32_encode("nauth", converted_data)
    
    return nauth

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
    # Tag 4 : transmittal_kind
    # Tag 5 : transmittal_relays 

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

        elif tag == 4:  # transmittal_kind
            
            transmittal_kind = struct.unpack(">I", value)[0]
            result["values"]["transmittal_kind"] = transmittal_kind  
        
        elif tag == 5:  # Transmittal Relays
            transmittal_relays = value.decode("ascii")
            if "transmittal_relays" not in result["values"]:
                result["values"]["transmittal_relays"] = []
            result["values"]["transmittal_relays"].append(transmittal_relays)
        
        elif tag == 6:  # None
            nonce = value.decode("ascii")
            if "name" not in result["values"]:
                result["values"]["name"] = nonce
            # result["values"]["nonce"].append(nonce)
      

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
    if type(json_obj) != dict:
        raise ValueError("not a json objecte")
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

def generate_nonce():
    return os.urandom(16).hex()


async def send_zap_receipt(nostr):

    service_k = Keys(priv_k=settings.SERVICE_SECRET_KEY)
    try:
        print(f"nostr parm: type: {type(nostr)} {nostr}")
        # nostr_decode=urllib.parse.unquote(nostr)
        # print(f"nostr_decode: {nostr_decode}")
        try:
            nostr_obj = json.loads(nostr)
            print(f"nostr obj: {nostr_obj}")
            zap_request = Event(    id=nostr_obj['id'],
                                    pub_key=nostr_obj['pubkey'], 
                                    kind=nostr_obj['kind'] ,
                                    sig=nostr_obj['sig'],
                                    content=nostr_obj['content'],
                                    tags=nostr_obj['tags'], 
                                    created_at=nostr_obj['created_at'])
            print(f"zap receipt tags: {zap_request.tags}")
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

        description_hash = "6e05f9c603cb655a217e8c84d68d9117a2a405d8b3df3f08737fab92d5015d58"
        receipt_tags.append(["description",nostr_obj])
        receipt_tags.append(["bolt11", description_hash])

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
            print(f"zap receipt: {zap_receipt.is_valid()}")
            print(f"zap relays: {zap_relays}")

            c.publish(zap_receipt)
            print("zap published!")

       
        # print("parsed zap receipt!")
    except:
        print("could not parse zap receipt!")
    
    # print(nostr_decode=urllib.parse.unquote(nostr))

    return