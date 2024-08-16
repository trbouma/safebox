import requests, json
import asyncio, base64, io, re
import datetime, hashlib, urllib, uuid
import binascii
import os

def lightning_address_pay(amount: int, lnaddress: str, comment:str="Payment made!"):
    
    ln_parts = lnaddress.split('@')
    local_part = ln_parts[0]
    url_to_call = "https://" + ln_parts[1]+"/.well-known/lnurlp/"+ln_parts[0].lower()
    print(f"Pay to: {url_to_call}")
    try:    
           
        ln_parms = requests.get(url_to_call)
        
        

        # print("lightning address pay callback: multiplier", ln_parms.json()['currency']['multiplier'])

        pass 
    except:
        return {"status": "ERROR", "reason": "Lighting address does not exist!"}
    
    print(f"Pay to: {ln_parms.json()['callback']}")

    data_to_send = {    "wallet_name": ln_parts[0],
                        "amount": amount*1000,
                        "comment": comment
                        
                        }

    ln_return = requests.get(ln_parms.json()['callback'],params=data_to_send)
    return ln_return.json()