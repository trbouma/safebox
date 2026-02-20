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


from app.utils import create_jwt_token, fetch_safebox,extract_leading_numbers, fetch_balance, db_state_change, create_nprofile_from_hex, npub_to_hex, validate_local_part, parse_nostr_bech32, hex_to_npub, get_acorn,create_naddr_from_npub,create_nprofile_from_npub, generate_nonce, create_nauth_from_npub, create_nauth, parse_nauth
from sqlmodel import Field, Session, SQLModel, select
from app.appmodels import RegisteredSafebox, CurrencyRate, lnPayAddress, lnPayInvoice, lnInvoice, ecashRequest, ecashAccept, ownerData, customHandle, addCard, deleteCard, updateCard, transmitConsultation, incomingRecord
from app.config import Settings
from app.db import engine
from app.tasks import service_poll_for_payment, invoice_poll_for_payment
from app.rates import refresh_currency_rates, get_currency_rates

import logging, jwt


settings = Settings()

templates = Jinja2Templates(directory="app/templates")


router = APIRouter()

@router.get("/rates", tags=["public"]) 
async def public_rates (    request: Request, 
                    
                    
                       
                    ):
    
    await refresh_currency_rates()
    rates = await get_currency_rates()
    
    return templates.TemplateResponse("public/rates.html", {"request": request, "rates": rates})

@router.get("/paypass", tags=["public"]) 
async def pay_pass(    request: Request, 
                    
                    
                       
                    ):
    
    pass
    
    return templates.TemplateResponse("paypass.html", {"request": request})
