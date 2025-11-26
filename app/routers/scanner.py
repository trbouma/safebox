from fastapi import FastAPI, HTTPException, Depends, Request, APIRouter, Response, Form, Header
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, StreamingResponse


from pydantic import BaseModel
from fastapi.templating import Jinja2Templates
import asyncio

import logging
from urllib.parse import urlparse

from app.utils import check_ln_address, decode_lnurl, parse_nauth

from fastapi import FastAPI, File, UploadFile
import shutil
from urllib.parse import quote, unquote



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
   
@router.api_route("/scanresult", tags=["acquire"], methods=["GET", "POST"],response_class=HTMLResponse)
async def get_scan_result(  request: Request, 
                            qr_code: str = "none",
                            referer:str = "none"):
    """return wallet mode information"""

    if request.method == "POST":
        data = await request.json()
        qr_code = data.get("data", None)
    else:
        data = None
        
    action_mode = None
    action_data = None
    amount = 0
    currency = None
    
    #remove any scheme prefixes
    qr_code = qr_code.replace('lightning:','').replace('bitcoin:','').replace("LIGHTNING:","")
    #remove any annoying url prepends
    qr_code = qr_code.replace('https://wallet.cashu.me/?token=',"")
    qr_code = qr_code.replace(' ',"+")
    print(qr_code)

    

    if check_ln_address(qr_code):
        action_mode ="lnaddress"
        action_data= unquote(qr_code)
        address_parts = action_data.split("@")
        local_part = address_parts[0].split('__')
        name = local_part[0]

        if len(local_part) >= 2:
            amount = float(local_part[1])

        if len(local_part) == 3:
            currency = local_part[2]

        action_data = f"{name}@{address_parts[1]}"
           
        
    
    elif qr_code[:5].lower() == "lnurl":
        # This handles the different lnurl types
        try:
            url = decode_lnurl(qr_code)
            if "lnurlp" in url:
                ln_parts = urlparse(url)
                action_data = ln_parts.path.split('/')[-1]+ "@" + ln_parts.netloc
                action_mode = "lnaddress"
                # Add parsing logic here
                address_parts = action_data.split("@")
                local_part = address_parts[0].split('__')
                name = local_part[0]
                if len(local_part) >= 2:
                    amount = float(local_part[1])

                if len(local_part) == 3:
                    currency = local_part[2]

                action_data = f"{name}@{address_parts[1]}"
                
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
            # Do nauth handling
            action_mode = "nauth"
            action_data = qr_code            
    
            parsed_nauth = parse_nauth(qr_code)

            print(f"scanner parsed nauth: {parsed_nauth}")
            
            if "prover" in parsed_nauth['values']['scope']:
                print(f"We have a credential presentation! {parsed_nauth['values']['scope']}")
                return RedirectResponse(f"/credentials/presentationrequest?nauth={qr_code}")
            elif "vcred" in parsed_nauth['values']['scope']:
                return RedirectResponse(f"/credentials/present?nauth={qr_code}")
            elif "offer" in parsed_nauth['values']['scope']:
                return RedirectResponse(f"/records/accept?nauth={qr_code}")
                
            elif "verifier" in parsed_nauth['values']['scope']:
                return RedirectResponse(f"/records/present?nauth={qr_code}")
            
            elif "vissue" in parsed_nauth['values']['scope']:
                return RedirectResponse(f"/credentials/offer?nauth={qr_code}")

            if referer == "health-data":
                return RedirectResponse(f"/safebox/health?nauth={qr_code}") 
                  
            elif referer == "health-consult":
                return RedirectResponse(f"/safebox/healthconsult?nauth={qr_code}")
            
            elif referer == "my-credentials":
                return RedirectResponse(f"/credentials/present?nauth={qr_code}")
            elif referer == "credential-offer":
                return RedirectResponse(f"/credentials/offer?nauth={qr_code}")
            else:
                return RedirectResponse(f"/safebox/access?nauth={qr_code}") 

    elif qr_code[:12].lower() == "nostr:nevent":
        
        nevent = qr_code[6:].lower()
        print(f"we have a nevent: {nevent}")
        
               
    elif qr_code[:5].lower() == 'https':
        return RedirectResponse(qr_code)
       

    else:
        return RedirectResponse(f"/safebox/access")

    return RedirectResponse(f"/safebox/access?action_mode={action_mode}&action_data={action_data}&amount={amount}&currency={currency}")
    
      


