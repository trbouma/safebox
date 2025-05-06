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


from app.utils import create_jwt_token, fetch_safebox,extract_leading_numbers, fetch_balance, db_state_change, create_nprofile_from_hex, npub_to_hex, validate_local_part, parse_nostr_bech32, hex_to_npub, get_acorn,create_naddr_from_npub,create_nprofile_from_npub, generate_nonce, create_nauth_from_npub, create_nauth, parse_nauth, listen_for_request, create_nembed_compressed, parse_nembed_compressed

from sqlmodel import Field, Session, SQLModel, create_engine, select
from app.appmodels import RegisteredSafebox, CurrencyRate, lnPayAddress, lnPayInvoice, lnInvoice, ecashRequest, ecashAccept, ownerData, customHandle, addCard, deleteCard, updateCard, transmitConsultation, incomingRecord, sendCredentialParms
from app.config import Settings
from app.tasks import service_poll_for_payment, invoice_poll_for_payment
from app.rates import refresh_currency_rates, get_currency_rates

import logging, jwt


settings = Settings()

templates = Jinja2Templates(directory="app/templates")


router = APIRouter()

engine = create_engine(settings.DATABASE)



@router.get("/issue", tags=["credentials"]) 
async def issue_credentials (   request: Request, 
                                acorn_obj = Depends(get_acorn)                  
                    
                       
                            ):
    
    profile = acorn_obj.get_profile()
    
    
        
   

    
    return templates.TemplateResponse("credentials/issuecredentials.html", {"request": request, "profile": profile})

@router.get("/offer", tags=["credentials", "protected"])
async def do_credential_offer(      request: Request,
                                    private_mode:str = "offer", 
                                    kind:int = 34001,   
                                    nprofile:str = None, 
                                    nauth: str = None,                            
                                    acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to consulting recods in home relay"""
    nprofile_parse = None
    auth_msg = None


    user_records = await acorn_obj.get_user_records(record_kind=kind)
    
    if nprofile:
        nprofile_parse = parse_nostr_bech32(nprofile)
        pass

    if nauth:
        
        print(f"nauth from do consult {nauth}")


        parsed_result = parse_nauth(nauth)
        npub_initiator = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values']['nonce']
        auth_kind = parsed_result['values'].get("auth_kind", settings.AUTH_KIND)
        auth_relays = parsed_result['values'].get("auth_relays", settings.AUTH_RELAYS)
        transmittal_pubhex = parsed_result['values'].get("transmittal_pubhex")
        transmittal_kind = parsed_result['values'].get("transmittal_kind", settings.TRANSMITTAL_KIND)
        transmittal_relays = parsed_result['values'].get("transmittal_relays",settings.TRANSMITTAL_RELAYS)
        scope = parsed_result['values'].get("scope")

        transmittal_npub = hex_to_npub(transmittal_pubhex)
    
        #TODO  transmittal npub from nauth

        auth_msg = create_nauth(    npub=acorn_obj.pubkey_bech32,
                                    nonce=nonce,
                                    auth_kind= auth_kind,
                                    auth_relays=auth_relays,
                                    transmittal_npub=transmittal_npub,
                                    transmittal_kind=transmittal_kind,
                                    transmittal_relays=transmittal_relays,
                                    name=acorn_obj.handle,
                                    scope=scope,
                                    grant=scope
        )

        print(f"do credential offer initiator npub: {npub_initiator} and nonce: {nonce} auth relays: {auth_kind} auth kind: {auth_kind} transmittal relays: {transmittal_relays} transmittal kind: {transmittal_kind}")

        
        # send the recipient nauth message
        msg_out = await acorn_obj.secure_transmittal(nrecipient=npub_initiator,message=auth_msg,dm_relays=auth_relays,kind=auth_kind)

    else:
       pass
    

    return templates.TemplateResponse(  "credentials/credentialoffer.html", 
                                        {   "request": request,
                                           
                                            "user_records": user_records,
                                            "record_kind": kind,
                                            "private_mode": private_mode,
                                            "client_nprofile": nprofile,
                                            "client_nprofile_parse": nprofile_parse,
                                            "client_nauth": auth_msg

                                        })

@router.get("/presentationrequest", tags=["credentials", "protected"])
async def credential_presentation_request(      request: Request,
                                    private_mode:str = "offer", 
                                    kind:int = 34003,   
                                    nprofile:str = None, 
                                    nauth: str = None,                            
                                    acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """This function display the verification page"""
    """The page sets up a websocket to listen for the incoming credential"""
    
    nprofile_parse = None
    response_nauth = None


    user_records = await acorn_obj.get_user_records(record_kind=kind)
    
    if nprofile:
        nprofile_parse = parse_nostr_bech32(nprofile)
        pass

    if nauth:
        
        print(f"nauth from do verify {nauth}")


        parsed_result = parse_nauth(nauth)
        npub_initiator = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values']['nonce']
        auth_kind = parsed_result['values'].get("auth_kind", settings.AUTH_KIND)
        auth_relays = parsed_result['values'].get("auth_relays", settings.AUTH_RELAYS)
        transmittal_npub = parsed_result['values'].get("transmittal_npub") # It is the verifier that receives the credential
        transmittal_kind = parsed_result['values'].get("transmittal_kind", settings.TRANSMITTAL_KIND)
        transmittal_relays = parsed_result['values'].get("transmittal_relays",settings.TRANSMITTAL_RELAYS)
        scope = parsed_result['values'].get("scope")
    
        #TODO  transmittal npub from nauth

        response_nauth = create_nauth(    npub=acorn_obj.pubkey_bech32,
                                    nonce=nonce,
                                    auth_kind= auth_kind,
                                    auth_relays=auth_relays,
                                    transmittal_npub=acorn_obj.pubkey_bech32,
                                    transmittal_kind=transmittal_kind,
                                    transmittal_relays=transmittal_relays,
                                    name=acorn_obj.handle,
                                    scope=scope,
                                    grant=scope.replace("prover","vselect")
        )

        print(f"do credential offer initiator npub: {npub_initiator} and nonce: {nonce} auth relays: {auth_kind} auth kind: {auth_kind} transmittal relays: {transmittal_relays} transmittal kind: {transmittal_kind}")

        
        # send the recipient nauth message
        msg_out = await acorn_obj.secure_transmittal(nrecipient=npub_initiator,message=response_nauth,dm_relays=auth_relays,kind=auth_kind)

    else:
       pass
    

    return templates.TemplateResponse(  "credentials/presentationrequest.html", 
                                        {   "request": request,
                                           
                                            "user_records": user_records,
                                            "record_kind": kind,
                                            "private_mode": private_mode,
                                            "client_nprofile": nprofile,
                                            "client_nprofile_parse": nprofile_parse,
                                            "client_nauth": response_nauth,
                                            "nauth": nauth

                                        })
@router.get("/verificationrequest", tags=["credentials", "protected"])
async def credential_verfication_request(      request: Request,
                          
                                    acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """This function display the verification page"""
    """The page sets up a websocket to listen for the incoming credential"""

    
    credential_types = ["id_card","passport","drivers_license"]

    return templates.TemplateResponse(  "credentials/verificationrequest.html", 
                                        {   "request": request,   
                                            "credential_types": credential_types

                                        })


@router.get("/display", tags=["credentials", "protected"])
async def display_card(     request: Request, 
                            card: str = None,
                            kind: int = 34001,
                            action_mode: str = None,
                            acorn_obj = Depends(get_acorn)
                    ):
    """Protected access to updating the card"""

    
    if action_mode == 'edit':

        record = await acorn_obj.get_record(record_name=card, record_kind=kind)
        
        content = record["payload"]
    elif action_mode =='add':
        card = ""
        content =""
    
    referer = urllib.parse.urlparse(request.headers.get("referer")).path

    return templates.TemplateResponse(  "card.html", 
                                        {   "request": request,
                                            
                                            "card": card,
                                            "record_kind": kind,
                                            "referer": referer,
                                            "action_mode":action_mode,
                                            "content": content
                                            
                                        })

@router.post("/transmit", tags=["credentials", "protected"])
async def transmit_records(        request: Request, 
                                        transmit_consultation: transmitConsultation,
                                        acorn_obj = Depends(get_acorn)
                    ):
    """ transmit consultation retreve 32227 records from issuing wallet and send as as 32225 records to nprofile recipient recieving wallet """

    status = "OK"
    detail = "Nothing yet"
    transmit_consultation.originating_kind = 34001
    transmit_consultation.final_kind = 34002

    
    print(f"transmit nauth: {transmit_consultation.nauth}")

    try:


        parsed_nauth = parse_nauth(transmit_consultation.nauth)
        pubhex = parsed_nauth['values']['pubhex']
        npub_recipient = hex_to_npub(pubhex)
        scope = parsed_nauth['values']['scope']
        nonce = parsed_nauth['values']['nonce']
        auth_kind = parsed_nauth['values']['auth_kind']
        auth_relays = parsed_nauth['values']['auth_relays']


        
        transmittal_pubhex = parsed_nauth['values']['transmittal_pubhex']
        transmittal_npub = hex_to_npub(transmittal_pubhex)
        
        
        transmittal_kind = parsed_nauth['values']['transmittal_kind']
        transmittal_relays = parsed_nauth['values']['transmittal_relays']

        # print(f" session nonce {safebox_found.session_nonce} {nonce}")
        #TODO Need to figure out session nonce when authenticating from other side
        # Need to update somewhere in the process leave out for now
        # if safebox_found.session_nonce != nonce:
        #     raise Exception("Invalid session!")


        records_to_transmit = await acorn_obj.get_user_records(record_kind=transmit_consultation.originating_kind)
        for each_record in records_to_transmit:
            print(f"transmitting: {each_record['tag']} {each_record['payload']}")

            record_obj = { "tag"   : [each_record['tag']],
                            "type"  : str(transmit_consultation.final_kind),
                            "payload": each_record['payload']
                          }
            print(f"record obj: {record_obj}")
            # await acorn_obj.secure_dm(npub,json.dumps(record_obj), dm_relays=relay)
            # 32227 are transmitted as kind 1060
            
            msg_out = await acorn_obj.secure_transmittal(transmittal_npub,json.dumps(record_obj), dm_relays=transmittal_relays,kind=transmittal_kind)

        detail = f"Successful"
        
    except Exception as e:
        status = "ERROR"
        detail = f"Error: {e}"
    

    return {"status": status, "detail": detail} 

@router.get("/present", tags=["credentials", "protected"])
async def my_credentials(       request: Request, 
                                nauth: str = None,
                                nonce: str = None,
                                acorn_obj = Depends(get_acorn)
                    ):
    """Protected access to private data stored in home relay"""
    nauth_response = None
    credential_select = False
    

    try:
        credential_records = await acorn_obj.get_user_records(record_kind=34002 )
    except:
        credential_records = None

    if nauth:
        
        print("nauth")

        

        parsed_result = parse_nauth(nauth)
        npub_initiator = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values']['nonce']
        auth_kind = parsed_result['values'].get("auth_kind")
        auth_relays = parsed_result['values'].get("auth_relays")
        transmittal_npub = parsed_result['values'].get("transmittal_npub")
        transmittal_kind = parsed_result['values'].get("transmittal_kind")
        transmittal_relays = parsed_result['values'].get("transmittal_relays")
        scope = parsed_result['values'].get("scope")
    
        if "verifier" in scope:
            credential_select = True
            nauth_response = nauth
        
        else:

        
            # also need to set transmittal npub 


            nauth_response = create_nauth(    npub=acorn_obj.pubkey_bech32,
                                        nonce=nonce,
                                        auth_kind= auth_kind,
                                        auth_relays=auth_relays,
                                        transmittal_npub=transmittal_npub,
                                        transmittal_kind=transmittal_kind,
                                        transmittal_relays=transmittal_relays,
                                        name=acorn_obj.handle,
                                        scope=scope,
                                        grant=scope
            )



        
        # send the recipient nauth message
        msg_out = await acorn_obj.secure_transmittal(nrecipient=npub_initiator,message=nauth_response,dm_relays=auth_relays,kind=auth_kind)

    else:
       pass

        

    
    return templates.TemplateResponse(  "credentials/present.html", 
                                        {   "request": request,
                                            
                                            
                                            "credential_records": credential_records ,
                                            "nauth": nauth_response,
                                            "credential_select": credential_select

                                        })




@router.get("/accept", tags=["credentials", "protected"])
async def get_inbox(      request: Request,

                                nauth: str = None,                         
                                acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to inbox in home relay"""
    nprofile_parse = None
 

    
    # acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    # await acorn_obj.load_data()
    # since = None
    since = util_funcs.date_as_ticks(datetime.now())
   


    if nauth:
        
        print("nauth")
        parsed_result = parse_nauth(nauth)
        npub = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values']['nonce']
        auth_kind = parsed_result['values'].get("auth_kind",settings.AUTH_KIND)
        auth_relays = parsed_result['values'].get("auth_relays",settings.AUTH_RELAYS)
        transmittal_kind = parsed_result['values'].get("transmittal_kind",settings.TRANSMITTAL_KIND)
        transmittal_relays = parsed_result['values'].get("transmittal_relays",settings.TRANSMITTAL_RELAYS)
        
        user_records = await acorn_obj.get_user_records(record_kind=transmittal_kind, relays=transmittal_relays)
        

    return templates.TemplateResponse(  "credentials/accept.html", 
                                        {   "request": request,
                                            
                                            "user_records": user_records,
                                            "transmittal_kind": transmittal_kind,
                                            "nauth": nauth

                                        })

@router.post("/acceptincomingcredential", tags=["safebox", "protected"])
async def accept_incoming_credential(       request: Request, 
                                        incoming_record: incomingRecord,
                                        acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """ accept incoming NPI-17 1060 health record and store as a 32225 record"""

    status = "OK"
    detail = "Nothing yet"



    try:
        parsed_result = parse_nauth(incoming_record.nauth)
        npub_initiator = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values']['nonce']
        auth_kind = parsed_result['values'].get("auth_kind", settings.AUTH_KIND)
        auth_relays = parsed_result['values'].get("auth_relays", settings.AUTH_RELAYS)
        transmittal_kind = parsed_result['values'].get("transmittal_kind", settings.TRANSMITTAL_KIND)
        transmittal_relays = parsed_result['values'].get("transmittal_relays",settings.TRANSMITTAL_RELAYS)

        # acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
        # await acorn_obj.load_data()
        
        records_to_accept = await acorn_obj.get_user_records(record_kind=transmittal_kind, relays=transmittal_relays)
        
        detail = f"Could not find incoming record"
        for each_record in records_to_accept:
            print(f"incoming record id: {each_record['id']}")
            # await acorn_obj.secure_dm(npub,json.dumps(record_obj), dm_relays=relay)
            # 32227 are transmitted as kind 1060
            # await acorn_obj.secure_transmittal(npub,json.dumps(record_obj), dm_relays=relay,transmittal_kind=1060)
            if each_record['id'] == incoming_record.id:
                print(each_record)
                print(each_record['tag'][0][0],each_record['payload'] )
                # acorn_obj.put_record(record_name=each_record['tag'][0][0],record_value=each_record['payload'],record_type='health',record_kind=37375)
                # record_name = f"{each_record['tag'][0][0]} {each_record['created_at']}" 
                record_name = f"{each_record['tag'][0][0]}" 
                record_value = each_record['payload']
                await acorn_obj.put_record(record_name=record_name, record_value=record_value, record_kind=34002)
                
                detail = f"Matched record {incoming_record.id} accepted!"

        
        
    except Exception as e:
        status = "ERROR"
        detail = f"Error: {e}"
    

    return {"status": status, "detail": detail}  

@router.get("/displaycredential", tags=["credentials", "protected"])
async def display_credential(     request: Request, 
                            card: str = None,
                            kind: int = 34002,
                            action_mode: str = None,
                            acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to updating the card"""

    
    if action_mode == 'edit':

        record = await acorn_obj.get_record(record_name=card, record_kind=kind)
        label_hash = await acorn_obj.get_label_hash(label=card)
        content = record["payload"]
        # record_id = record["id"]
        
    elif action_mode =='add':
        card = ""
        content =""
    
    credential_record = {"card":card, "content": content}
    referer = urllib.parse.urlparse(request.headers.get("referer")).path

    return templates.TemplateResponse(  "credentials/credential.html", 
                                        {   "request": request,
                                            
                                            "card": card,
                                            "record_kind": kind,
                                            "label_hash": label_hash,
                                            "referer": referer,
                                            "action_mode":action_mode,
                                            "content": content,
                                            "credential_record": credential_record
                                            
                                        })

@router.get("/nauth", tags=["safebox", "protected"])
async def generate_nauth(    request: Request, 
                        scope: str = 'transmit',
                        acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to private data stored in home relay"""
    status = "OK"
    detail = "None"

    
    # acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    # await acorn_obj.load_data()
    # figure out to use the owner key or the wallet key
    # just use the wallet
    print("this is the credentials/nauth")

    # pub_hex_to_use = acorn_obj.pubkey_hex
    npub_to_use = acorn_obj.pubkey_bech32
    nonce = generate_nonce()
    print(f"scope: {scope} nonce: {nonce}")
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.npub==acorn_obj.pubkey_bech32)
        safeboxes = session.exec(statement)
        safebox_for_nonce = safeboxes.first()
        safebox_for_nonce.session_nonce = nonce
        session.add(safebox_for_nonce)
        session.commit()

    try:
        #TODO add in nonce to safebox table and change from naddr to nauth
        # detail = create_nauth_from_npub(    npub_bech32=npub_to_use,
        #                                    relays=[settings.AUTH_RELAY], 
        #                                    nonce=nonce,
        #                                    kind=settings.HEALTH_SECURE_AUTH_KIND,
        #                                    transmittal_relays=[settings.HOME_RELAY],
        #                                    transmittal_kind=settings.HEALTH_SECURE_TRANSMITTAL_KIND
        # )
        
        transmittal_npub = acorn_obj.pubkey_bech32
       
        detail = create_nauth(  npub=npub_to_use,
                                nonce=nonce,
                                auth_kind=settings.AUTH_KIND,
                                auth_relays=settings.AUTH_RELAYS,
                                transmittal_npub=transmittal_npub,
                                transmittal_kind = settings.CREDENTIAL_TRANSMITTAL_KIND,
                                transmittal_relays=settings.CREDENTIAL_TRANSMITTAL_RELAYS,
                                name=acorn_obj.handle,
                                scope=scope 

                               
                            )
        

        print(f"generated nauth: {detail}")
      
    except:
        detail = "Not created"

    return {"status": status, "detail": detail}

@router.post("/sendcredential", tags=["credentials", "protected"])
async def post_send_credential(      request: Request, 
                                credential_parms: sendCredentialParms,                                
                                acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Select credential for verification"""
    nauth_response = None
    print(f"send credential {credential_parms.nauth}")

    if credential_parms.nauth:
        parsed_nauth = parse_nauth(credential_parms.nauth)

        scope = parsed_nauth['values']['scope']
        grant = parsed_nauth['values'].get("grant")
        

        
        pubhex = parsed_nauth['values']['pubhex']
        npub_recipient = hex_to_npub(pubhex)
        nonce = parsed_nauth['values']['nonce']
        auth_kind = parsed_nauth['values']['auth_kind']
        auth_relays = parsed_nauth['values']['auth_relays']
        transmittal_pubhex = parsed_nauth['values'].get('transmittal_pubhex',acorn_obj.pubkey_hex)
        transmittal_kind = parsed_nauth['values']['transmittal_kind']
        transmittal_relays = parsed_nauth['values']['transmittal_relays']

        print(f"send credential to transmittal_pubhex: {transmittal_pubhex} scope: {scope} grant:{grant}")

        # Need to inspect scope to determine what to do
        #TODO refactor this code
        if "prover" in scope:
            # this means the presentation has the corresponding record hash
            transmittal_npub = hex_to_npub(transmittal_pubhex)
            print(f"grant: {credential_parms.grant}")
            # record_hash = scope.replace("prover:","")
            # print(f"need to select credential with record hash {record_hash}")
            # record_out = await acorn_obj.get_record(record_kind=34002, record_by_hash=record_hash)
            record_out = await acorn_obj.get_record(record_name=credential_parms.grant, record_kind=34002)
            
        elif "verifier" in scope:
            transmittal_npub = hex_to_npub(transmittal_pubhex)
            #need to figure how to pass in the label to look up
            print(f"grant: {credential_parms.grant}")
            record_out = await acorn_obj.get_record(record_name=credential_parms.grant, record_kind=34002)
            # record_out = {"tag": "TBD", "payload" : "This will be a real credential soon!"}
        else:
            record_out = {"tag": "TBD", "payload" : "This will be a real credential soon!"}

        print(record_out)
        
        nembed = create_nembed_compressed(record_out)
        # print(nembed)

        #TODO Need to select the right credential and send over the to verifier
        # just send scope for now

        msg_out = await acorn_obj.secure_transmittal(transmittal_npub,nembed, dm_relays=transmittal_relays,kind=transmittal_kind)

    return {"status": "OK", "result": True, "detail": f"Successfully sent to {transmittal_npub}for verification!"}

@router.websocket("/ws/credentialdata")
async def ws_credential_data( websocket: WebSocket,                                          
                                        acorn_obj = Depends(get_acorn)
                                        ):
    await websocket.accept()
    return

@router.websocket("/ws/offer/{nauth}")
async def ws_credential_offer( websocket: WebSocket, 
                                        nauth:str=None, 
                                        acorn_obj = Depends(get_acorn)
                                        ):

    print(f"ws nauth: {nauth}")
    auth_relays = None

    await websocket.accept()

    if nauth:
        parsed_nauth = parse_nauth(nauth)   
        auth_kind = parsed_nauth['values'] ['auth_kind']   
        auth_relays = parsed_nauth['values']['auth_relays']
        print(f"ws auth relays: {auth_relays}")



    # acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    # await acorn_obj.load_data()

    naddr = acorn_obj.pubkey_bech32
    nauth_old = None
    # since_now = None
    since_now = int(datetime.now(timezone.utc).timestamp())
    start_time = datetime.now()

    while True:
        if datetime.now() - start_time > timedelta(minutes=1):
            print("1 minute has passed. Exiting loop.")
            await websocket.send_json({"test":"test"})
            break
        try:
            # await acorn_obj.load_data()
            try:
                client_nauth = await listen_for_request(acorn_obj=acorn_obj,kind=auth_kind, since_now=since_now, relays=auth_relays)
            except:
                client_nauth=None
            

            
            # parsed_nauth = parse_nauth(client_nauth)
            # name = parsed_nauth['name']
            # print(f"client nauth {client_nauth}")
            

            if client_nauth != nauth_old: 
                parsed_nauth = parse_nauth(client_nauth)
                transmittal_kind = parsed_nauth['values'].get('transmittal_kind')
                transmittal_relays = parsed_nauth['values'].get('transmittal_relays')
                nprofile = {'nauth': client_nauth, 'name': 'safebox user', 'transmittal_kind': transmittal_kind, "transmittal_relays": transmittal_relays}
                print(f"send {client_nauth}") 
                await websocket.send_json(nprofile)
                nauth_old = client_nauth
                print("authentication successful!")
                break
           
        
        except Exception as e:
            print(f"Websocket message: {e}")
            break
        
        await asyncio.sleep(5)
        
        
        
    print("websocket connection closed")

@router.websocket("/ws/listenforverifier/{nauth}")
async def ws_listen_for_verifier( websocket: WebSocket, 
                                        nauth:str=None, 
                                        acorn_obj = Depends(get_acorn)
                                        ):
    """After presenting a QR code, listen for verifier reponse using nauth parameters"""
    print(f"ws nauth: {nauth}")
    auth_relays = None

    await websocket.accept()

    if nauth:
        parsed_nauth = parse_nauth(nauth)   
        auth_kind = parsed_nauth['values'] ['auth_kind']   
        auth_relays = parsed_nauth['values']['auth_relays']
        print(f"ws auth relays: {auth_relays}")



    # acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    # await acorn_obj.load_data()

    naddr = acorn_obj.pubkey_bech32
    nauth_old = None
    # since_now = None
    since_now = int(datetime.now(timezone.utc).timestamp())
    start_time = datetime.now()

    while True:
        if datetime.now() - start_time > timedelta(minutes=1):
            print("1 minute has passed. Exiting loop.")
            await websocket.send_json({"status":"TIMEOUT"})
            break
        try:
            # Error handling
            
            try:
                client_nauth = await listen_for_request(acorn_obj=acorn_obj,kind=auth_kind, since_now=since_now, relays=auth_relays)
            except:
                client_nauth=None
            


            if client_nauth != nauth_old: 
                parsed_nauth = parse_nauth(client_nauth)
                transmittal_kind = parsed_nauth['values'].get('transmittal_kind')
                transmittal_relays = parsed_nauth['values'].get('transmittal_relays')
                msg_out =   {   "status": "PRESENTACK",
                                'nauth': client_nauth, 
                                'name': 'safebox user', 
                                'transmittal_kind': transmittal_kind, 
                                'transmittal_relays': transmittal_relays}
                print(f"send {client_nauth}") 
                await websocket.send_json(msg_out)
                nauth_old = client_nauth
                print("credential presentation successful!")
                break
           
        
        except Exception as e:
            print(f"Websocket message: {e}")
            break
        
        await asyncio.sleep(5)
     
        
    print("websocket connection closed")

@router.websocket("/ws/listenforcredential/{nauth}")
async def ws_credential_listen( websocket: WebSocket, 
                                        nauth:str=None, 
                                        acorn_obj: Acorn = Depends(get_acorn)
                                        ):

    print(f"listen with: {nauth}")
    auth_relays = None

    await websocket.accept()

    if nauth:
        parsed_nauth = parse_nauth(nauth)   
        transmittal_kind = parsed_nauth['values'] ['transmittal_kind']   
        transmittal_relays = parsed_nauth['values']['auth_relays']
        print(f"ws auth relays: {auth_relays}")



    # acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    # await acorn_obj.load_data()

    naddr = acorn_obj.pubkey_bech32
    client_credential_old = None
    # since_now = None
    since_now = int(datetime.now(timezone.utc).timestamp())
    start_time = datetime.now()

    while True:
        if datetime.now() - start_time > timedelta(minutes=1):
            print("1 minute has passed. Exiting loop.")
            await websocket.send_json({"status":"TIMEOUT"})
            break
        try:
            # await acorn_obj.load_data()
            try:
                client_credential = await listen_for_request(acorn_obj=acorn_obj,kind=transmittal_kind, since_now=since_now, relays=transmittal_relays)
            except Exception as e:
                client_credential=None
            


            if client_credential != client_credential_old: 
                # parsed_nauth = parse_nauth(client_nauth)
                # transmittal_kind = parsed_nauth['values'].get('transmittal_kind')
                # transmittal_relays = parsed_nauth['values'].get('transmittal_relays')
                credential_json = parse_nembed_compressed(client_credential)
                #### Do the verification here... ####
                verify_result = True
                #### Finish verification ####

                msg_out =   {   "status": "VERIFIED",
                                "detail": credential_json, 
                                "result": verify_result
                               
                               }
                print(f"send {client_credential}") 
                await websocket.send_json(msg_out)
                client_credential_old = client_credential
                print("credential receipt successful!")
                break
           
        
        except Exception as e:
            print(f"Websocket message: {e}")
            break
        
        await asyncio.sleep(5)
     
        
    print("websocket connection closed")

@router.websocket("/wsrequesttransmittal/{nauth}")
async def websocket_requesttransmittal( websocket: WebSocket, 
                                        nauth:str=None, 
                                        acorn_obj = Depends(get_acorn)
                                        ):

    print(f"ws nauth: {nauth}")
    auth_relays = None

    await websocket.accept()

    if nauth:
        parsed_nauth = parse_nauth(nauth)   
        auth_kind = parsed_nauth['values'] ['auth_kind']   
        auth_relays = parsed_nauth['values']['auth_relays']
        print(f"ws auth relays: {auth_relays}")



    # acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    # await acorn_obj.load_data()

    naddr = acorn_obj.pubkey_bech32
    nauth_old = None
    # since_now = None
    since_now = int(datetime.now(timezone.utc).timestamp())

    while True:
        try:
            # await acorn_obj.load_data()
            try:
                client_nauth = await listen_for_request(acorn_obj=acorn_obj,kind=auth_kind, since_now=since_now, relays=auth_relays)
            except:
                client_nauth=None
            

            
            # parsed_nauth = parse_nauth(client_nauth)
            # name = parsed_nauth['name']
            # print(f"client nauth {client_nauth}")
            

            if client_nauth != nauth_old: 
                parsed_nauth = parse_nauth(client_nauth)
                pubhex = parsed_nauth['values'].get('pubhex')
                transmittal_pubhex = parsed_nauth['values'].get('transmittal_pubhex')
                transmittal_kind = parsed_nauth['values'].get('transmittal_kind')
                transmittal_relays = parsed_nauth['values'].get('transmittal_relays')
                
                # Need to create a new nauth where the transmittal npub points back to the initiator
                new_nauth = create_nauth (  npub= hex_to_npub(pubhex),
                                            nonce = parsed_nauth['values'].get('nonce'),
                                            auth_kind = parsed_nauth['values'].get('auth_kind'),
                                            auth_relays = parsed_nauth['values'].get('auth_relays'),
                                            transmittal_npub = hex_to_npub(pubhex),
                                            transmittal_kind=  transmittal_kind,
                                            transmittal_relays= transmittal_relays,
                                            scope= parsed_nauth['values'].get('scope'),
                                            grant = parsed_nauth['values'].get('grant')

                ) 

                nprofile = {'nauth': new_nauth, 'name': 'safebox user', 'transmittal_kind': transmittal_kind, "transmittal_relays": transmittal_relays}
                print(f"send {client_nauth}") 
                await websocket.send_json(nprofile)
                nauth_old = client_nauth
                break
           
        
        except Exception as e:
            print(f"Websocket message: {e}")
            break
        
        await asyncio.sleep(5)
        
        
    print("websocket connection closed")    