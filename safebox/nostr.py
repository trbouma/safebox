import bech32
import binascii
import requests


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

