from fastapi import FastAPI, HTTPException, Depends, Request, APIRouter, Response, Form, Header, Cookie
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, StreamingResponse

from pydantic import BaseModel
from typing import Optional
from fastapi.templating import Jinja2Templates
import asyncio,qrcode, io

from datetime import datetime, timedelta
from safebox.acorn import Acorn


from app.utils import create_jwt_token, fetch_safebox
from sqlmodel import Field, Session, SQLModel, create_engine, select
from app.appmodels import RegisteredSafebox, PaymentQuote
from app.config import Settings

import logging, jwt


settings = Settings()

templates = Jinja2Templates(directory="app/templates")


router = APIRouter()

engine = create_engine(settings.DATABASE)
SQLModel.metadata.create_all(engine)

@router.post("/login", tags=["safebox"])
def login(access_key: str = Form()):

    
    # Authenticate user
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.access_key==access_key)
        print(statement)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            pass
            raise HTTPException(status_code=404, detail=f"{access_key} not found")


    # Create JWT token
    access_token = create_jwt_token({"sub": access_key}, expires_delta=timedelta(hours=1))

    # Create response with JWT as HttpOnly cookie
    response = RedirectResponse(url="/safebox/access", status_code=302)
    # response = JSONResponse({"message": "Login successful"})
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,  # Prevent JavaScript access
        max_age=3600,  # 1 hour
        secure=False,  # Set to True in production to enforce HTTPS
        samesite="Lax",  # Protect against CSRF
    )
    return response

@router.get("/logout")
def logout():
    response = JSONResponse({"message": "Successfully logged out"})
    response.delete_cookie(key="access_token")
    return response



@router.get("/qr/{qr_text}", tags=["public"])
def create_authqr(qr_text: str):
          
    img = qrcode.make(qr_text)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0) # important here!
    return StreamingResponse(buf, media_type="image/jpeg")

@router.get("/access", tags=["safebox", "protected"])
def protected_route(request: Request, access_token: str = Cookie(None)):
    try:
        safebox_found = fetch_safebox(access_token=access_token)
    except:
        response = RedirectResponse(url="/", status_code=302)
        return response
        


    safebox = Acorn(nsec=safebox_found.nsec,home_relay=settings.HOME_RELAY)
    asyncio.run(safebox.load_data())
    # Token is valid, proceed
    return templates.TemplateResponse( "access.html", {"request": request, "title": "Welcome Page", "message": "Welcome to Safebox Web!", "safebox":safebox})
    return {"message": f"Welcome, {access_key}!"}

@router.get("/poll", tags=["protected"])
async def poll_for_payment(request: Request, access_token: str = Cookie(None)):
    try:
        safebox_found = fetch_safebox(access_token=access_token)
        safebox = Acorn(nsec=safebox_found.nsec,home_relay=settings.HOME_RELAY)
        await safebox.load_data()
    except:
        return {"detail": "not logged in"}



    return {"detail": "polling",
            "balance": safebox.balance}

@router.get("/profile/{handle}", response_class=HTMLResponse)
async def root_get_user_profile(    request: Request, 
                                    handle: str, 

                                   
                                ):

    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.handle ==handle)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            raise HTTPException(status_code=404, detail=f"{handle} not found")

    user_name = safebox_found.handle    
    lightning_address = f"{safebox_found.handle}@{request.url.hostname}"

    return templates.TemplateResponse("profile.html", 
                                      {"request": request, "user_name": user_name, 
                                       "lightning_address": lightning_address,
                                       
                                       
                                         
                                      
                                          
                                            })