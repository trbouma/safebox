from fastapi import FastAPI, HTTPException, Depends, Request, APIRouter, Response, Form, Header, Cookie
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, StreamingResponse

from pydantic import BaseModel
from fastapi.templating import Jinja2Templates
import asyncio

from datetime import datetime, timedelta

from app.utils import create_jwt_token

import logging, jwt

# Secret key for signing JWT
SECRET_KEY = "foobar"
ALGORITHM = "HS256"

templates = Jinja2Templates(directory="templates")

router = APIRouter()

@router.post("/login", tags=["safebox"])
def login(access_key: str):


    # Authenticate user


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

@router.post("/logout")
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
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        access_key = payload.get("sub")
        if not access_key:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Token is valid, proceed
    return templates.TemplateResponse( "access.html", {"request": request, "title": "Welcome Page", "message": "Welcome to Safebox Web!", "access_key":access_key})
    return {"message": f"Welcome, {access_key}!"}