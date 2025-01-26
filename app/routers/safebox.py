from fastapi import FastAPI, WebSocket, HTTPException, Depends, Request, APIRouter, Response, Form, Header, Cookie
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, StreamingResponse

from pydantic import BaseModel
from typing import Optional
from fastapi.templating import Jinja2Templates
import asyncio,qrcode, io

from datetime import datetime, timedelta
from safebox.acorn import Acorn
from time import sleep


from app.utils import create_jwt_token, fetch_safebox,extract_leading_numbers, fetch_balance, db_state_change
from sqlmodel import Field, Session, SQLModel, create_engine, select
from app.appmodels import RegisteredSafebox, lnPayAddress, lnPayInvoice, lnInvoice, ecashRequest, ecashAccept
from app.config import Settings
from app.tasks import service_poll_for_payment, invoice_poll_for_payment

import logging, jwt

HOME_MINT = "https://mint.nimo.cash"
MINTS = ['https://mint.nimo.cash']
settings = Settings()

templates = Jinja2Templates(directory="app/templates")


router = APIRouter()

engine = create_engine(settings.DATABASE)
SQLModel.metadata.create_all(engine)

@router.post("/login", tags=["safebox"])
async def login(request: Request, access_key: str = Form()):

    access_key=access_key.strip().lower()
    match = False
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
            # Try to find withouy hypens
            leading_num = extract_leading_numbers(access_key)
            if not leading_num:
                return templates.TemplateResponse(  "welcome.html", 
                                        {   "request": request, 
                                            "title": "Welcome Page", 
                                            "branding": settings.BRANDING,
                                            "branding_message": settings.BRANDING_RETRY})
                # raise HTTPException(status_code=404, detail=f"{access_key} not found")
            
            statement = select(RegisteredSafebox).where(RegisteredSafebox.access_key.startswith(leading_num))
            safeboxes = session.exec(statement)
            for each_safebox in safeboxes:
                access_key_on_record = each_safebox.access_key
                split_key= access_key_on_record.split("-")
                if split_key[1] in access_key and split_key[2] in access_key:
                    print("match!")
                    # set the access key to the one of record
                    access_key = access_key_on_record
                    match=True
                    break
                
                print(each_safebox)
            
            if not match:
                
                return templates.TemplateResponse(  "welcome.html", 
                                        {   "request": request, 
                                            "title": "Welcome Page", 
                                            "branding": settings.BRANDING,
                                            "branding_message": settings.BRANDING_RETRY})
                # raise HTTPException(status_code=404, detail=f"{access_key} not found")


    # Create JWT token
    access_token = create_jwt_token({"sub": access_key}, expires_delta=timedelta(hours=1))

    # Create response with JWT as HttpOnly cookie
    response = RedirectResponse(url="/safebox/access", status_code=302)
    # response = JSONResponse({"message": "Login successful"})
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,  # Prevent JavaScript access
        max_age=3600 * 24 * settings.SESSION_AGE_DAYS,  # Set login session length
        secure=False,  # Set to True in production to enforce HTTPS
        samesite="Lax",  # Protect against CSRF
    )
    return response

@router.get("/logout")
async def logout():
    response = JSONResponse({"message": "Successfully logged out"})
    response.delete_cookie(key="access_token")
    return response



@router.get("/qr/{qr_text}", tags=["public"])
async def create_qr(qr_text: str):
          
    img = qrcode.make(qr_text)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0) # important here!
    return StreamingResponse(buf, media_type="image/jpeg")

@router.get("/access", tags=["safebox", "protected"])
async def protected_route(    request: Request, 
                        onboard: bool = False, 
                        action_mode:str=None, 
                        action_data: str = None,
                        action_amount: int = None,
                        action_comment: str = None,
                        access_token: str = Cookie(None)
                    ):
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
    except:
        response = RedirectResponse(url="/", status_code=302)
        return response
        
    if safebox_found.custom_handle:
        lightning_address = f"{safebox_found.custom_handle}@{request.url.hostname}"
    else:
        lightning_address = f"{safebox_found.handle}@{request.url.hostname}"
        
    #TODO Update balance here

    print(f"onboard {onboard} action_mode {action_mode} acquire_data: {action_data}")
    acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
    await acorn_obj.load_data()
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.handle ==safebox_found.handle)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.one()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            raise ValueError("Could not find safebox!")
    
       

        safebox_found.balance = acorn_obj.balance
        session.add(safebox_found)
        session.commit()

    # Token is valid, proceed
    return templates.TemplateResponse(  "access.html", 
                                        {   "request": request, 
                                            "title": "Welcome Page", 
                                            "message": "Welcome to Safebox Web!", 
                                            "safebox":acorn_obj, 
                                            "lightning_address": lightning_address,
                                            "branding": settings.BRANDING,
                                            "onboard": onboard,
                                            "action_mode": action_mode,
                                            "action_data": action_data,
                                            "action_amount": action_amount,
                                            "action_comment": action_comment

                                        })
    

@router.post("/payaddress", tags=["protected"])
async def ln_pay_address(   request: Request, 
                        ln_pay: lnPayAddress,
                        access_token: str = Cookie(None)):
    msg_out ="No payment"
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
        acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
        await acorn_obj.load_data()
        msg_out = await acorn_obj.pay_multi(amount=ln_pay.amount,lnaddress=ln_pay.address,comment=ln_pay.comment)
    except Exception as e:
        return {f"detail": f"error {e}"}

    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.handle ==safebox_found.handle)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.one()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            raise ValueError("Could not find safebox!")
    
       

        safebox_found.balance = acorn_obj.balance
        session.add(safebox_found)
        session.commit()

    return {"detail": msg_out}

@router.post("/payinvoice", tags=["protected"])
async def ln_pay_invoice(   request: Request, 
                        ln_invoice: lnPayInvoice,
                        access_token: str = Cookie(None)):
    msg_out ="No payment"
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
        acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
        await acorn_obj.load_data()

        msg_out = await  acorn_obj.pay_multi_invoice(lninvoice=ln_invoice.invoice, comment=ln_invoice.comment)
    except Exception as e:
        return {f"detail": "error {e}"}

    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.handle ==safebox_found.handle)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.one()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            raise ValueError("Could not find safebox!")
    
       

        safebox_found.balance = acorn_obj.balance
        session.add(safebox_found)
        session.commit()
    
    return {"detail": msg_out}

@router.post("/issueecash", tags=["protected"])
async def issue_ecash(   request: Request, 
                        ecash_request: ecashRequest,
                        access_token: str = Cookie(None)):
    msg_out ="No payment"
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
        acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
        await acorn_obj.load_data()

        # msg_out = await  acorn_obj.pay_multi_invoice(lninvoice=ln_invoice.invoice, comment=ln_invoice.comment)
        msg_out = await acorn_obj.issue_token(ecash_request.amount)
    except Exception as e:
        return {    "status": "ERROR",
                    f"detail": "error {e}"}

    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.handle ==safebox_found.handle)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.one()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            raise ValueError("Could not find safebox!")
    
       

        safebox_found.balance = acorn_obj.balance
        session.add(safebox_found)
        session.commit()
    
    return {    "status": "OK",
                "detail": msg_out
            }

@router.post("/acceptecash", tags=["protected"])
async def accept_ecash(   request: Request, 
                        ecash_accept: ecashAccept,
                        access_token: str = Cookie(None)):
    msg_out ="No payment"
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
        acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
        await acorn_obj.load_data()

       
        
        msg_out = await acorn_obj.accept_token(ecash_accept.ecash_token)
    except Exception as e:
        return {    "status": "ERROR",
                    "detail": f"error {e}"}

    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.handle ==safebox_found.handle)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.one()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            raise ValueError("Could not find safebox!")
    
       

        safebox_found.balance = acorn_obj.balance
        session.add(safebox_found)
        session.commit()
    
    return {    "status": "OK",
                "detail": msg_out
            }

@router.post("/invoice", tags=["protected"])
async def ln_invoice_payment(   request: Request, 
                        ln_invoice: lnInvoice,
                        access_token: str = Cookie(None)):
    msg_out ="No payment"
    try:
        safebox_found = await fetch_safebox(access_token=access_token)

        
    except Exception as e:
        return {f"status": "error {e}"}
    

    acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    await acorn_obj.load_data()
    cli_quote = acorn_obj.deposit(amount=ln_invoice.amount )   

    




    task2 = asyncio.create_task(invoice_poll_for_payment(safebox_found=safebox_found,quote=cli_quote.quote, amount=ln_invoice.amount, mint=HOME_MINT))
    return {"status": "ok", "invoice": cli_quote.invoice}

    # Do the update for the polling balance
 
    # task = asyncio.create_task(acorn_obj.poll_for_payment(quote=cli_quote.quote, amount=ln_invoice.amount,mint=HOME_MINT))
    # Update the cache amout   
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.handle ==safebox_found.handle)
        safeboxes = session.exec(statement)
        safebox_update = safeboxes.first()
        safebox_update.balance = safebox_update.balance + ln_invoice.amount
        session.add(safebox_update)
        session.commit()
    



    return {"status": "ok",
            "invoice": cli_quote.invoice}


@router.get("/poll", tags=["protected"])
async def poll_for_balance(request: Request, access_token: str = Cookie(None)):
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
        
    except:
        return {"detail": "error",
                "balance": 0}

    print(f"safebox poll {safebox_found.handle} {safebox_found.balance}")


    return {"detail": "polling",
            "balance": safebox_found.balance}

@router.get("/privatedata", tags=["safebox", "protected"])
async def private_data(       request: Request, 
                        access_token: str = Cookie(None)
                    ):
    """Protected access to private data stored in home relay"""
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
    except:
        response = RedirectResponse(url="/", status_code=302)
        return response
    
    acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    await acorn_obj.load_data()
    user_records = await acorn_obj.get_user_records()
    
    msg_out = "To be implemented!"

    return templates.TemplateResponse(  "privatedata.html", 
                                        {   "request": request,
                                            "safebox": safebox_found ,
                                            "user_records": user_records

                                        })
@router.get("/health", tags=["safebox", "protected"])
async def my_health(       request: Request, 
                        access_token: str = Cookie(None)
                    ):
    """Protected access to private data stored in home relay"""
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
    except:
        response = RedirectResponse(url="/", status_code=302)
        return response
    
    msg_out = "To be implemented!"

    return templates.TemplateResponse(  "healthdata.html", 
                                        {   "request": request,
                                            "safebox": safebox_found 

                                        })


@router.get("/credentials", tags=["safebox", "protected"])
async def my_credentials(       request: Request, 
                        access_token: str = Cookie(None)
                    ):
    """Protected access to credentials stored in home relay"""
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
    except:
        response = RedirectResponse(url="/", status_code=302)
        return response
    
    

    return templates.TemplateResponse(  "credentials.html", 
                                        {   "request": request,
                                            "safebox": safebox_found 

                                        })


@router.get("/ecash", tags=["safebox", "protected"])
async def my_ecash(       request: Request, 
                        access_token: str = Cookie(None)
                    ):
    """Protected access to credentials stored in home relay"""
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
    except:
        response = RedirectResponse(url="/", status_code=302)
        return response
    
    

    return templates.TemplateResponse(  "ecash.html", 
                                        {   "request": request,
                                            "safebox": safebox_found 

                                        })

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


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, access_token=Cookie()):

    await websocket.accept()

    # access_token = websocket.cookies.get("access_token")
    try:
       
       safebox_found = await fetch_safebox(access_token=access_token)
    except:
        await websocket.close(code=1008)  # Policy violation
        return

    starting_balance = safebox_found.balance
    new_balance = starting_balance
    message = "All payments up to date!"
    status = "SAME"


    while True:
        try:
            await db_state_change(safebox_found.id)
            
            # data = await websocket.receive_text()
            # print(f"message received: {data}")
            # await websocket.send_text(f"message received {safebox_found.handle} from safebox: {data}")
            
            
            new_balance = await fetch_balance(safebox_found.id)
                


            if new_balance > starting_balance:
                message = f"Payment received! {new_balance-starting_balance} sats."
                status = "RECD"

            elif new_balance < starting_balance:
                message = f"Payment sent! {starting_balance-new_balance} sats."
                status = "SENT"

            elif new_balance == starting_balance:
                message = f"Payment Ready."
                status = "OK"

            
            await websocket.send_json({"balance":new_balance, "message": message, "status": status})
            starting_balance = new_balance
          
            
           
            
        
        except Exception as e:
            print(f"Websocket message: {e}")
            break
        
        
        
    print("websocket connection closed")

@router.get("/getrecords", tags=["safebox", "protected"])
async def get_records(       request: Request, 
                            access_token: str = Cookie(None)
                    ):
    """Protected access to private data stored in home relay"""
    try:
        safebox_found = await fetch_safebox(access_token=access_token)
        
    except:
        response = RedirectResponse(url="/", status_code=302)
        return response
    
    acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    await acorn_obj.load_data()
    records_out = await acorn_obj.get_user_records()

    return records_out
    