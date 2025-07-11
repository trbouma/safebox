from fastapi import FastAPI,  HTTPException, Depends, Request, APIRouter, Response, Form, Header, Cookie
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


from app.utils import create_jwt_token, fetch_safebox,extract_leading_numbers, fetch_balance, db_state_change, create_nprofile_from_hex, npub_to_hex, validate_local_part, parse_nostr_bech32, hex_to_npub, get_acorn,create_naddr_from_npub,create_nprofile_from_npub, generate_nonce, create_nauth_from_npub, create_nauth, parse_nauth
from sqlmodel import Field, Session, SQLModel, create_engine, select
from app.appmodels import RegisteredSafebox, CurrencyRate, lnPayAddress, lnPayInvoice, lnInvoice, ecashRequest, ecashAccept, ownerData, customHandle, addCard, deleteCard, updateCard, transmitConsultation, incomingRecord
from app.config import Settings
from app.tasks import service_poll_for_payment, invoice_poll_for_payment

import logging, jwt


settings = Settings()

templates = Jinja2Templates(directory="app/templates")


router = APIRouter()

engine = create_engine(settings.DATABASE)



@router.get("/", tags=["pos"]) 
async def pos_main (    request: Request, 
                        acorn_obj = Depends(get_acorn)
                    ):
    
    return templates.TemplateResponse("pos.html", {"request": request, "expression": ""})

@router.post("/calculate", response_class=HTMLResponse)
async def calculate(request: Request, expression: str = Form(...)):
    try:
        # WARNING: `eval` should be avoided or sandboxed in production
        result = eval(expression)
    except Exception:
        result = "Error"
    return templates.TemplateResponse("result.html", {"request": request, "expression": str(result)})

