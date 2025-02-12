from fastapi import FastAPI, HTTPException, Depends, Request, APIRouter, Response, Form, Header
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, StreamingResponse


from pydantic import BaseModel
from fastapi.templating import Jinja2Templates
import asyncio

import logging
from urllib.parse import urlparse

from app.utils import check_ln_address, decode_lnurl

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
async def get_scanner(  request: Request, 
                        qr_code: str = "none", 
                        wallet_name: str = None,
                        referer: str = None):
    """return user information"""
    
    # referer = urllib.parse.urlparse(request.headers.get("referer")).path

    

    
    return templates.TemplateResponse("acquirescan.html", 
                                      {"request": request,
                                       "referer": referer,
                                       "wallet_name": wallet_name
                                      
                                       
                                       
                                       } )
   
@router.get("/scanresult", tags=["acquire"], response_class=HTMLResponse)
async def get_scan_result(  request: Request, 
                            qr_code: str = "none",
                            referer:str = "none"):
    """return wallet mode information"""

   

    data = None
    action_mode = None
    action_data = None
    #remove any scheme prefixes
    qr_code = qr_code.replace('lightning:','').replace('bitcoin:','').replace("LIGHTNING:","")
    #remove any annoying url prepends
    qr_code = qr_code.replace('https://wallet.cashu.me/?token=',"")
    print(qr_code)

    

    if check_ln_address(qr_code):
        action_mode ="lnaddress"
        action_data= qr_code
        
    
    elif qr_code[:5].lower() == "lnurl":
        # This handles the different lnurl types
        try:
            url = decode_lnurl(qr_code)
            if "lnurlp" in url:
                ln_parts = urlparse(url)
                action_data = ln_parts.path.split('/')[-1]+ "@" + ln_parts.netloc
                action_mode = "lnaddress"
                
        except:
            # logger.debug("there is an error")
            wallet_mode = "initial"
    elif qr_code[:4].lower() == 'lnbc':
        action_mode = 'lninvoice'
        action_data = qr_code
        try:
            decode_invoice=bolt11.decode(qr_code)
            action_amount =decode_invoice.amount_msat//1000
            action_comment=decode_invoice.description
            return RedirectResponse(f"/safebox/access?action_mode={action_mode}&action_data={action_data}&action_amount={action_amount}&action_comment={action_comment}")
        except:
            pass
    elif qr_code[:6] == "cashuA":
        action_mode = "ecash"
        action_data = qr_code
    
    elif qr_code[:8].lower() == "nprofile":
            # Go directly to health consultation
            action_mode = "nprofile"
            action_data = qr_code
            return RedirectResponse(f"/safebox/healthconsult?nprofile={qr_code}")

    elif qr_code[:5].lower() == "nauth":
            # Go directly to health consultation 
            action_mode = "nauth"
            action_data = qr_code            
    
            if referer == "health-data":
                return RedirectResponse(f"/safebox/health?nauth={qr_code}") 
                  
            elif referer == "health-consult":
                return RedirectResponse(f"/safebox/healthconsult?nauth={qr_code}")
            else:
                return RedirectResponse(f"/safebox/access?nauth={qr_code}") 

               
    elif qr_code[:5].lower() == 'https':
        return RedirectResponse(qr_code)
       

    else:
        return RedirectResponse(f"/safebox/access")

    return RedirectResponse(f"/safebox/access?action_mode={action_mode}&action_data={action_data}")
    
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
      


