from fastapi import FastAPI, WebSocket, HTTPException, Depends, Request, APIRouter, Response, Form, Header, Cookie
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, StreamingResponse

from pydantic import BaseModel
from typing import Optional, List
from fastapi.templating import Jinja2Templates
import asyncio,qrcode, io, urllib
import httpx

from datetime import datetime, timedelta, timezone
from safebox.acorn import Acorn
from time import sleep
import json
from monstr.util import util_funcs
from monstr.encrypt import Keys
import ipinfo


from app.utils import create_jwt_token, fetch_safebox,extract_leading_numbers, fetch_balance, db_state_change, create_nprofile_from_hex, npub_to_hex, validate_local_part, parse_nostr_bech32, hex_to_npub, get_acorn,create_naddr_from_npub,create_nprofile_from_npub, generate_nonce, create_nauth_from_npub, create_nauth, parse_nauth, parse_nembed_compressed, sign_payload
from sqlmodel import Field, Session, SQLModel, select
from app.appmodels import RegisteredSafebox, CurrencyRate, lnPayAddress, lnPayInvoice, lnInvoice, ecashRequest, ecashAccept, ownerData, customHandle, addCard, deleteCard, updateCard, transmitConsultation, incomingRecord
from app.config import Settings, ConfigWithFallback
from app.db import engine
from app.branding import build_templates
from app.tasks import service_poll_for_payment, invoice_poll_for_payment
from app.rates import refresh_currency_rates, get_currency_rates, get_currency_rate

import logging, jwt


settings = Settings()
config = ConfigWithFallback()

templates = build_templates()


router = APIRouter()


class MyBalanceRequest(BaseModel):
    nembed: str
    currency: str = "SAT"

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


@router.get("/mybalance", tags=["public"])
@router.get("/mybalance/", tags=["public"])
async def my_balance_page(request: Request):
    return templates.TemplateResponse(
        "mybalance.html",
        {
            "request": request,
            "currencies": settings.SUPPORTED_CURRENCIES,
        },
    )


@router.post("/mybalance/check", tags=["public"])
@router.post("/mybalance/check/", tags=["public"])
async def my_balance_check(request: Request, payload: MyBalanceRequest):
    try:
        parsed_nembed = parse_nembed_compressed(payload.nembed)
        host = parsed_nembed["h"]
        vault_token = parsed_nembed["k"]
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid NFC payload: {exc}")

    k = Keys(config.SERVICE_NSEC)
    sig = sign_payload(vault_token, k.private_key_hex())
    status_payload = {"token": vault_token, "pubkey": k.public_key_hex(), "sig": sig}

    balance_url = f"https://{host}/.well-known/card-balance"
    timeout = httpx.Timeout(4.0, connect=2.0)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(balance_url, json=status_payload, headers={"Content-Type": "application/json"})
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=502,
            detail="Unable to reach the card's home server right now. Please try again shortly.",
        )
    except httpx.RequestError:
        raise HTTPException(
            status_code=502,
            detail="The card's home server is unavailable. Please try again later.",
        )

    if response.status_code != 200:
        if response.status_code in (404, 405):
            status_url = f"https://{host}/.well-known/card-status"
            try:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    status_response = await client.post(
                        status_url,
                        json=status_payload,
                        headers={"Content-Type": "application/json"},
                    )
                if status_response.status_code == 200:
                    raise HTTPException(
                        status_code=502,
                        detail=(
                            "This card's server is online, but it does not support the "
                            "balance endpoint yet. Please upgrade that server."
                        ),
                    )
                if status_response.status_code in (401, 404):
                    raise HTTPException(
                        status_code=status_response.status_code,
                        detail="Card is invalid, rotated, or not recognized by its home server.",
                    )
            except httpx.RequestError:
                pass

        if response.status_code in (401, 404):
            raise HTTPException(status_code=response.status_code, detail="Card is invalid, rotated, or not recognized by its home server.")
        raise HTTPException(
            status_code=502,
            detail="Balance service is temporarily unavailable. Please try again later.",
        )

    response_json = response.json()
    balance_sats = int(response_json.get("balance_sats", 0))
    selected_currency = (payload.currency or "SAT").upper()

    if selected_currency == "SAT":
        selected_amount = float(balance_sats)
        currency_symbol = ""
    else:
        local_currency = await get_currency_rate(selected_currency)
        selected_amount = local_currency.currency_rate * balance_sats / 1e8
        currency_symbol = local_currency.currency_symbol

    return {
        "status": "OK",
        "balance_sats": balance_sats,
        "selected_currency": selected_currency,
        "selected_amount": selected_amount,
        "currency_symbol": currency_symbol,
    }
