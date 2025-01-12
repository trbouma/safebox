from fastapi import FastAPI, HTTPException, Depends, Request, APIRouter, Response, Form, Header, Cookie
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, StreamingResponse

from pydantic import BaseModel
from fastapi.templating import Jinja2Templates
import asyncio

from datetime import datetime, timedelta
from safebox.acorn import Acorn


from app.utils import create_jwt_token
from sqlmodel import Field, Session, SQLModel, create_engine, select
from app.appmodels import RegisteredSafebox, PaymentQuote
from app.config import Settings

import logging, jwt




templates = Jinja2Templates(directory="app/templates")
engine = create_engine("sqlite:///data/database.db")
SQLModel.metadata.create_all(engine)

router = APIRouter()
settings = Settings()

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

@router.get("/access", tags=["safebox"])
def protected_route(request: Request, access_token: str = Cookie(None)):
    # Extract and verify JWT from the cookie
    if not access_token:
        raise HTTPException(status_code=401, detail="Missing access token")

    try:
        payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        access_key = payload.get("sub")
        if not access_key:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    print(access_key)
    # Token is valid, now get the safebox
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.access_key==access_key)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
        if safebox_found:
            handle = safebox_found.handle
        else:
            raise HTTPException(status_code=404, detail=f"{access_key} not found")

    safebox = Acorn(nsec=safebox_found.nsec,home_relay=settings.HOME_RELAY)
    asyncio.run(safebox.load_data())
    # Token is valid, proceed
    return templates.TemplateResponse( "access.html", {"request": request, "title": "Welcome Page", "message": "Welcome to Safebox Web!", "safebox":safebox})
    return {"message": f"Welcome, {access_key}!"}