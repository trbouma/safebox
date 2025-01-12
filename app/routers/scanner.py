from fastapi import FastAPI, HTTPException, Depends, Request, APIRouter, Response, Form, Header
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, StreamingResponse


from pydantic import BaseModel
from fastapi.templating import Jinja2Templates
import asyncio

import logging


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
   

