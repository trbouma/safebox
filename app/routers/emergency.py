from fastapi import FastAPI, WebSocket, HTTPException, Depends, Request, APIRouter, Response, Form, Header, Cookie
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, StreamingResponse

from pydantic import BaseModel
from typing import Optional, List
from fastapi.templating import Jinja2Templates
import asyncio,qrcode, io, urllib

from datetime import datetime, timedelta, timezone
from safebox.acorn import Acorn
from time import sleep
import json
from monstr.util import util_funcs
import ipinfo


from app.utils import create_jwt_token, fetch_safebox,extract_leading_numbers, fetch_balance, db_state_change, create_nprofile_from_hex, npub_to_hex, validate_local_part, parse_nostr_bech32, hex_to_npub, create_naddr_from_npub,create_nprofile_from_npub, generate_nonce, create_nauth_from_npub, create_nauth, parse_nauth
from sqlmodel import Field, Session, SQLModel, create_engine, select
from app.appmodels import RegisteredSafebox, CurrencyRate, lnPayAddress, lnPayInvoice, lnInvoice, ecashRequest, ecashAccept, ownerData, customHandle, addCard, deleteCard, updateCard, transmitConsultation, incomingRecord
from app.config import Settings
from app.tasks import service_poll_for_payment, invoice_poll_for_payment

import logging, jwt


settings = Settings()

templates = Jinja2Templates(directory="app/templates")


router = APIRouter()

engine = create_engine(settings.DATABASE)
# SQLModel.metadata.create_all(engine,checkfirst=True)


@router.get("/eqr/{emergency_code}", tags=["emergency"]) 
async def emergency_help (request: Request, emergency_code: str=""):
    details = None
    emergency__info = {"status": "OK", "detail":f"emergency info {emergency_code}"}
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        ip = forwarded_for.split(",")[0]  # Get the first IP in the list
    else:
        ip = request.client.host

    try:
        handler = ipinfo.getHandler(settings.IP_INFO_TOKEN)
        details = handler.getDetails(ip)
        city = details.city
        location = details.loc
        country = details.country_name
        details_all = details.all
    except:
        city = "Not located"
        location = "Not located"
        details_all = None

    # print(f"requesting ip: {ip}")

    with Session(engine) as session:
            statement = select(RegisteredSafebox).where(RegisteredSafebox.emergency_code==emergency_code.upper().strip())
            safeboxes = session.exec(statement)

            try:
                safebox_found = safeboxes.one()
                acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=settings.MINTS)
                await acorn_obj.load_data()
                emergency_card = await acorn_obj.get_record("medical emergency card")
                emergency__info = emergency_card['payload']
                if safebox_found.owner:
                    print(f"send message to owner")
                    message = f"Your Emergency QR Code has been scanned from {details_all}"
                    await acorn_obj.secure_transmittal(nrecipient=safebox_found.owner, message=message, dm_relays=settings.RELAYS, kind=1059)
            except:
                emergency__info = "Not available"

            final_text = emergency__info.encode().decode('unicode_escape').replace("\n","<br>") 
            # emergency__info.replace("\n", "<br>")

    return templates.TemplateResponse( "eqr.html", {"request": request, "title": "Medical Emergency Card", "message": "Medical Emergency Card", "emergency_info": final_text, "ip": ip})



@router.get("/imgeqr/{emergency_code}", tags=["emergency"])
def create_inviteqr(request: Request, emergency_code: str):

    qr_text = f"{request.base_url}eqr/{emergency_code}"      
    img = qrcode.make(qr_text)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0) # important here!
    return StreamingResponse(buf, media_type="image/jpeg")
