from fastapi import FastAPI, HTTPException, Depends, Request, APIRouter, Response, Form, Header
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, StreamingResponse


from pydantic import BaseModel
from fastapi.templating import Jinja2Templates
import asyncio

import logging

from app.utils import check_ln_address

from fastapi import FastAPI, File, UploadFile
import shutil



import datetime, requests
import urllib.parse

import qrcode
import io
import bolt11

from app.config import Settings

settings = Settings() 


templates = Jinja2Templates(directory="app/templates")

router = APIRouter()


@router.get("/scan", tags=["scanner"], response_class=HTMLResponse)
async def get_scanner(request: Request, qr_code: str = "none", wallet_name: str = "user", acquire_mode: str = "public"):
    """return user information"""
    
   

    
    return templates.TemplateResponse("acquirescan.html", 
                                      {"request": request,
                                       "wallet_name": wallet_name,
                                       "acquire_mode": acquire_mode
                                       
                                       } )
   
@router.get("/scanresult", tags=["acquire"], response_class=HTMLResponse)
async def get_scan_result(request: Request, qr_code: str = "none"):
    """return wallet mode information"""

   

    data = None
    #remove any scheme prefixes
    qr_code = qr_code.replace('lightning:','').replace('bitcoin:','').replace("LIGHTNING:","")
    #remove any annoying url prepends
    qr_code = qr_code.replace('https://wallet.cashu.me/?token=',"")
    print(qr_code)
    
    return RedirectResponse(f"/safebox/access")
    
    wallet_mode = "text"
    out_data = qr_code

    if check_ln_address(qr_code):
        wallet_mode ="lnaddress"
       
    
    elif qr_code[:5].lower() == "lnurl":
        # This handles the different lnurl types
        try:
            wallet_mode, return_data = lnurl_handler(qr_code)
            out_data = return_data
                

        except:
            # logger.debug("there is an error")
            wallet_mode = "initial"
        
    elif qr_code[:6] == "cashuA":
        wallet_mode = "ecash"
         
    elif qr_code[:4].lower() == 'lnbc':
        wallet_mode = 'lninvoice'        
        
    elif qr_code[:4].lower() == 'lock':
        wallet_mode = 'lock'
    elif qr_code[:8].lower() == 'location':

        wallet_mode = 'location'
        loc_parms = "words="+ qr_code.replace('location.','').replace('.',"%2C")
        print(loc_parms)
        return RedirectResponse(f"https://find.fastlogin.io/?{loc_parms}")

    
    elif qr_code[:6].lower() == 'key://':
        wallet_mode = 'login'
        wallet_qr_key= qr_code.lower().replace("key://","")
        print("we are logging in!", wallet_qr_key, request.url.hostname)

        host_login_url = f"{request.url.scheme}://{request.url.hostname}:{request.url.port}/wallet/login"
        login_data = {
            "wallet_key": wallet_qr_key
            }
        # login_response = requests.post(host_login_url,json=login_data)
        # print(login_response.txt)
       
        return RedirectResponse(f"/wallet/?wallet_qr_key={wallet_qr_key}") 
        
    elif qr_code[:5].lower() == "nostr": 
        wallet_mode ="lnaddress"
        nfragment =  qr_code[6:].lower()
        # return RedirectResponse(f"https://njump.me/{nfragment}")
        return RedirectResponse(f"/wallet/?wallet_mode={wallet_mode}&qr_code={nfragment}")  
    
    elif qr_code[:4].lower() == "npub": 
        wallet_mode ="lnaddress"
        nfragment =  qr_code.lower()
        # return RedirectResponse(f"https://njump.me/{nfragment}")
        return RedirectResponse(f"/wallet/?wallet_mode={wallet_mode}&qr_code={nfragment}")
    
    elif qr_code[:5].lower() == 'https':
        # Check for wallet.cashu.me

        wallet_mode = 'secureredirect'        
        return RedirectResponse(out_data)
    elif qr_code[:4].lower() == 'http':
        wallet_mode = 'insecureredirect'
        return RedirectResponse(out_data)
        
    elif qr_code[:3].lower() == 'bc1' or qr_code[:1].lower() == '3':
        wallet_mode = 'bitcoinaddress'
    elif qr_code[:10].lower() == 'credential':
        wallet_mode = 'credential'
        return RedirectResponse(f"/qrverify?credential={out_data}")
    elif qr_code[:9].lower() == 'openid-vc':
        wallet_mode = "openid-vc"

    else:
        
        return RedirectResponse(f"/wallet/?wallet_mode={wallet_mode}&qr_code={out_data}")
    
    return RedirectResponse(f"/wallet/?wallet_mode={wallet_mode}&qr_code={out_data}")
      


