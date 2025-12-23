import urllib.parse
import requests, json
import asyncio, base64, io, re
import datetime, hashlib, urllib, uuid
import binascii
import os
from bech32 import bech32_encode, convertbits
from mnemonic import Mnemonic

def lightning_address_pay(amount: int, lnaddress: str, comment:str="Payment made!"):
    
    ln_parts = lnaddress.split('@')
    local_part = ln_parts[0]
    url_to_call = "https://" + ln_parts[1]+"/.well-known/lnurlp/"+ln_parts[0].lower()
    # print(f"Pay to: {url_to_call}")
    try:    
           
        ln_parms = requests.get(url_to_call)
        lnparms_obj     = ln_parms.json()
        allows_nostr    = lnparms_obj.get("allowsNostr", False)
        nostr_pubkey    = lnparms_obj.get("nostrPubkey", None)
        safebox         = lnparms_obj.get("safebox", False)
        nonce            = lnparms_obj.get("nonce", None)
           
        
        # print("ln_parms", ln_parms.json())

        # print("lightning address pay callback: multiplier", ln_parms.json()['currency']['multiplier'])

        pass 
    except:
        return {"status": "ERROR", "reason": "Lighting address does not exist!"}
    
    # print(f"Pay to: {ln_parms.json()['callback']}")

    data_to_send = {    "wallet_name": ln_parts[0],
                        "amount": amount*1000,
                        "comment": comment,
                        "safebox": safebox,
                        "nonce":    nonce
                        
                        }

    ln_return = requests.get(ln_parms.json()['callback'],params=data_to_send)
    return ln_return.json(), safebox, nonce

def lnaddress_to_lnurl(lnaddress):
    domain = lnaddress.split('@')[1]
    name = lnaddress.split('@')[0]
    url = f"https://{domain}/.well-known/lnurlp/{name}"
    url_bytes = url.encode('utf-8')
    data = convertbits(url_bytes, 8, 5)
    lnurl = bech32_encode("lnurl", data)
    return lnurl

def get_zap_info(lnaddress: str):
    domain = lnaddress.split('@')[1]
    name = lnaddress.split('@')[0]
    url = f"https://{domain}/.well-known/lnurlp/{name}"
    zap_parms = requests.get(url)
    return zap_parms.json()

def zap_address_pay(amount: int, lnaddress: str, zap_dict: dict):
    ln_parts = lnaddress.split('@')
    local_part = ln_parts[0]
    url_to_call = "https://" + ln_parts[1]+"/.well-known/lnurlp/"+ln_parts[0].lower()
    lnurl = lnaddress_to_lnurl(lnaddress)
    # print(f"Pay to: {url_to_call}")
    try:    
           
        ln_parms = requests.get(url_to_call)
        zap_parms = ln_parms.json()
        
        # print("lightning address pay callback: multiplier", ln_parms.json()['currency']['multiplier'])

        pass 
    except:
        return {"status": "ERROR", "reason": "Lighting address does not exist!"}
    
    # print(f"Zap to pay: {zap_parms}")
    
    allows_nostr = zap_parms.get("allowsNostr", False)
    nostr_pubkey = zap_parms.get("nostrPubkey", None)
    # print(f"allowsNostr {allows_nostr} with pubkey {nostr_pubkey}")
    if allows_nostr:
        pass
        data_to_send = {  
                            "lnurl" : lnurl,
                            "amount": int(amount*1000),
                            "nostr" : json.dumps(zap_dict)
                        
                        }
        ln_return = requests.get(zap_parms['callback'],params=data_to_send)
        # print(ln_return.json())
        pr = ln_return.json()['pr']
        

    return pr, allows_nostr,nostr_pubkey



