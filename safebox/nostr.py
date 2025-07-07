import bech32
import binascii
import requests
import json
import io
from bech32 import bech32_encode, convertbits, bech32_decode
import gzip

def hex_to_bech32(key_str: str, prefix='npub'):
    as_int = [int(key_str[i:i+2], 16) for i in range(0, len(key_str), 2)]
    data = bech32.convertbits(as_int, 8, 5)
    return bech32.bech32_encode(prefix, data)

@staticmethod
def bech32_to_hex(key: str):
    # should be the reverese of hex_to_bech32...
    as_int = bech32.bech32_decode(key)
    data = bech32.convertbits(as_int[1], 5, 8)
    return ''.join([hex(i).replace('0x', '').rjust(2,'0') for i in data][:32])

def nip05_to_npub(nip05: str):
    relays = []
    try:
        parts = nip05.lower().split('@')
        nip05_url = f"https://{parts[1]}/.well-known/nostr.json?name={parts[0]}"
        response = requests.get(nip05_url)
        pubkey = response.json()['names'][parts[0]]
        
    except:
        pubkey = None   

    try:
        relays = response.json()['relays'][pubkey]
    except:
        relays = []    
    return pubkey, relays   

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

