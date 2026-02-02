from fastapi import FastAPI, WebSocket, HTTPException, Depends, Request, APIRouter, Response, Form, Header, Cookie
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, StreamingResponse

from pydantic import BaseModel
from typing import Optional, List
from fastapi.templating import Jinja2Templates
import asyncio,qrcode, io, urllib

from datetime import datetime, timedelta, timezone
from safebox.acorn import Acorn
from safebox.models import GrantRecord, OfferRecord
from time import sleep
import json
from monstr.util import util_funcs
from monstr.encrypt import Keys
from monstr.event.event import Event
import ipinfo
import requests
from safebox.func_utils import get_profile_for_pub_hex, get_attestation
from safebox.monstrmore import ExtendedNIP44Encrypt
from monstr.encrypt import NIP44Encrypt
import oqs


from app.utils import create_jwt_token, fetch_safebox,extract_leading_numbers, fetch_balance, db_state_change, create_nprofile_from_hex, npub_to_hex, validate_local_part, parse_nostr_bech32, hex_to_npub, get_acorn,create_naddr_from_npub,create_nprofile_from_npub, generate_nonce, create_nauth_from_npub, create_nauth, parse_nauth, listen_for_request, create_nembed_compressed, parse_nembed_compressed, get_label_by_id, get_id_by_label, sign_payload, get_tag_value

from sqlmodel import Field, Session, SQLModel, create_engine, select
from app.appmodels import RegisteredSafebox, CurrencyRate, lnPayAddress, lnPayInvoice, lnInvoice, ecashRequest, ecashAccept, ownerData, customHandle, addCard, deleteCard, updateCard, transmitConsultation, incomingRecord, sendCredentialParms, nauthRequest, proofByToken, OfferToken
from app.config import Settings, ConfigWithFallback
from app.tasks import service_poll_for_payment, invoice_poll_for_payment
from app.rates import refresh_currency_rates, get_currency_rates

import logging, jwt


settings = Settings()
config = ConfigWithFallback()

templates = Jinja2Templates(directory="app/templates")


router = APIRouter()

engine = create_engine(settings.DATABASE)



@router.get("/issue", tags=["records"]) 
async def issue_credentials (   request: Request, 
                                acorn_obj = Depends(get_acorn)                  
                    
                       
                            ):
    
    profile = acorn_obj.get_profile()
    
    
        
   

    
    return templates.TemplateResponse("credentials/issuecredentials.html", {"request": request, "profile": profile})

@router.get("/offerlist", tags=["records", "protected"])
async def offer_list(      request: Request,
                                    private_mode:str = "offer", 
                                    kind:int = None,   
                                    nprofile:str = None, 
                                    nauth: str = None,                            
                                    acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to consulting recods in home relay"""
    nprofile_parse = None
    auth_msg = None

    offer_kinds = settings.OFFER_KINDS
    if not kind:
        kind = offer_kinds[0][0]

    user_records = await acorn_obj.get_user_records(record_kind=kind)
    
    if nprofile:
        nprofile_parse = parse_nostr_bech32(nprofile)
        pass

    if nauth:
        
        print(f"nauth from do consult {nauth}")


        parsed_result = parse_nauth(nauth)
        npub_initiator = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values'].get('nonce', '0')
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

        print(f"do  offer initiator npub: {npub_initiator} and nonce: {nonce} auth relays: {auth_kind} auth kind: {auth_kind} transmittal relays: {transmittal_relays} transmittal kind: {transmittal_kind}")

        
        # send the recipient nauth message
        msg_out = await acorn_obj.secure_transmittal(nrecipient=npub_initiator,message=auth_msg,dm_relays=auth_relays,kind=auth_kind)

    else:
       pass
    


    offer_kinds = settings.OFFER_KINDS
    grant_kinds = settings.GRANT_KINDS
    offer_kind_label = get_label_by_id(offer_kinds, kind)

    # Get correspond grant kind
    grant_kind = get_id_by_label(grant_kinds,offer_kind_label)

    return templates.TemplateResponse(  "records/offerlist.html", 
                                        {   "request": request,
                                           
                                            "user_records": user_records,
                                            "record_kind": kind,
                                            "offer_kind": kind,
                                            "offer_kind_label": offer_kind_label,
                                            "grant_kind": grant_kind,
                                            "private_mode": private_mode,
                                            "client_nprofile": nprofile,
                                            "client_nprofile_parse": nprofile_parse,
                                            "client_nauth": auth_msg,
                                            "offer_kinds": offer_kinds

                                        })

@router.get("/request", tags=["records", "protected"])
async def record_request(      request: Request,                                    
                                kind:int = 34003,                          
                                acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """This function display the verification page"""
    """The page sets up a websocket to listen for the incoming credential"""
    



    # user_records = await acorn_obj.get_user_records(record_kind=kind)

    # this is the replacement for records/request.html
    # const ws = new WebSocket(`wss://{{request.url.hostname}}/records/ws/request/${nauth}`); 
    
    host = request.url.hostname
    scheme = "ws" if host in ("localhost", "127.0.0.1") else "wss"
    port = f":{request.url.port}" if request.url.port not in (None, 80) else ""
    ws_url = f"{scheme}://{host}{port}/records/ws/request/"
    

    return templates.TemplateResponse(  "records/request.html", 
                                        {   "request": request,
                                            
                                            "record_kind": kind,   
                                            "grant_kinds": settings.GRANT_KINDS,
                                            "ws_url": ws_url


                                        })
@router.get("/verificationrequest", tags=["records", "protected"])
async def records_verfication_request(      request: Request,
                          
                                    acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """This function display the verification page"""
    """The page sets up a websocket to listen for the incoming credential"""

    
    credential_types = ["id_card","passport","drivers_license"]

    return templates.TemplateResponse(  "credentials/verificationrequest.html", 
                                        {   "request": request,   
                                            "credential_types": credential_types

                                        })




@router.post("/transmit", tags=["records", "protected"])
async def transmit_records(        request: Request, 
                                        transmit_consultation: transmitConsultation,
                                        acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """ transmit consultation retreve 32227 records from issuing wallet and send as as 32225 records to nprofile recipient recieving wallet """

    status = "OK"
    detail = "Nothing yet"
    
    # Need to generalize the parameters below
    # transmit_consultation.originating_kind = 34001
    # transmit_consultation.final_kind = 34002

    
    print(f"transmit nauth: {transmit_consultation.nauth} record name: {transmit_consultation.record_name}")

    try:


        parsed_nauth = parse_nauth(transmit_consultation.nauth)
        pubhex = parsed_nauth['values']['pubhex']
        npub_recipient = hex_to_npub(pubhex)
        scope = parsed_nauth['values']['scope']
        nonce = parsed_nauth['values'].get('nonce', generate_nonce(1))
        auth_kind = parsed_nauth['values'].get('auth_kind', settings.AUTH_KIND)
        auth_relays = parsed_nauth['values'].get('auth_relays', settings.AUTH_RELAYS)


        
        transmittal_pubhex = parsed_nauth['values']['transmittal_pubhex']
        transmittal_npub = hex_to_npub(transmittal_pubhex)
        
        
        transmittal_kind = parsed_nauth['values'].get('transmittal_kind', settings.TRANSMITTAL_KIND)
        transmittal_relays = parsed_nauth['values'].get('transmittal_relays', settings.TRANSMITTAL_RELAYS)

        # print(f" session nonce {safebox_found.session_nonce} {nonce}")
        #TODO Need to figure out session nonce when authenticating from other side
        # Need to update somewhere in the process leave out for now
        # if safebox_found.session_nonce != nonce:
        #     raise Exception("Invalid session!")

        # PQC Step 2a
        print(f"PQC Step 2a {transmit_consultation.kem_public_key} {transmit_consultation.kemalg}")
        pqc = oqs.KeyEncapsulation(transmit_consultation.kemalg,bytes.fromhex(config.PQC_KEM_SECRET_KEY))
        kem_ciphertext, kem_shared_secret = pqc.encap_secret(bytes.fromhex(transmit_consultation.kem_public_key))
        kem_shared_secret_hex = kem_shared_secret.hex()
        kem_ciphertext_hex = kem_ciphertext.hex()

        k_nip44 = Keys(priv_k=kem_shared_secret_hex)

        print(f"kem shared secret: {kem_shared_secret_hex} ciphertext: {kem_ciphertext_hex}")
        try:
            pass
            my_enc = ExtendedNIP44Encrypt(k_nip44)
            print(f"my NIP44 enc: {my_enc}")
        except:
            pass

        records_to_transmit = await acorn_obj.get_user_records(record_kind=transmit_consultation.originating_kind)
        for each_record in records_to_transmit:

            # Issue record here:
            
            issued_record: Event  = await acorn_obj.issue_private_record(content=each_record['payload'],holder=transmittal_npub, kind=transmit_consultation.final_kind)
            
            issued_record_str = json.dumps(issued_record.data())
            print(f"issued record here before transmitting: {issued_record_str}")

            # PQC Encrypt Payload
            
            
            pqc_encrypted_payload = my_enc.encrypt(to_pub_k=k_nip44.public_key_hex(),plain_text=issued_record_str)
            print(f"pqc encrypted payload: {pqc_encrypted_payload}")

           
            
            if each_record['tag'][0] == transmit_consultation.record_name:
                print(f"transmitting: {each_record['tag'][0]} {each_record['payload']}")

                record_obj = { "tag"   : [each_record['tag']],
                                "type"  : str(transmit_consultation.final_kind),
                                "payload": "This record is quantum-safe",
                                "timestamp": int(datetime.now(timezone.utc).timestamp()),
                                "endorsement": acorn_obj.pubkey_bech32,
                                "ciphertext": kem_ciphertext_hex,
                                "kemalg": transmit_consultation.kemalg,
                                "pqc_encrypted_payload": pqc_encrypted_payload
                            }
                print(f"record obj: {record_obj}")
                # await acorn_obj.secure_dm(npub,json.dumps(record_obj), dm_relays=relay)
                # 32227 are transmitted as kind 1060

                # The PQC payload wrapping occurs here
                print(f"payload is additionally encrypted {kem_shared_secret_hex}" )
                
                msg_out = await acorn_obj.secure_transmittal(transmittal_npub,json.dumps(record_obj), dm_relays=transmittal_relays,kind=transmittal_kind)

        detail = f"Successfully transmitted kind {transmit_consultation.final_kind} to {transmittal_npub} via {transmittal_relays}"
        
    except Exception as e:
        status = "ERROR"
        detail = f"Error: {e}"
    

    return {"status": status, "detail": detail} 

@router.get("/present", tags=["records", "protected"])
async def my_present_records(       request: Request, 
                                nauth: str = None,
                                nonce: str = None,
                                record_kind: int = None,
                                acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to private data stored in home relay"""
    nauth_response = None
    record_select = False
    
    if not acorn_obj:
        return RedirectResponse("/safebox/access")
    
    grant_kinds = settings.GRANT_KINDS
    if not record_kind:
        record_kind = grant_kinds[0][0]


    if nauth:
        
        print("nauth")

        

        parsed_result = parse_nauth(nauth)
        npub_initiator = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values'].get('nonce', '0')
        auth_kind = parsed_result['values'].get("auth_kind", settings.AUTH_KIND)
        auth_relays = parsed_result['values'].get("auth_relays", settings.AUTH_RELAYS)
        transmittal_npub = parsed_result['values'].get("transmittal_npub")
        transmittal_kind = parsed_result['values'].get("transmittal_kind", settings.TRANSMITTAL_KIND)
        transmittal_relays = parsed_result['values'].get("transmittal_relays", settings.TRANSMITTAL_RELAYS)
        scope = parsed_result['values'].get("scope")
    
        if "verifier" in scope:
            record_select = True
            record_kind = int(scope.split(":")[1])
            nauth_response = nauth
        
        else:
            pass

        
            # also need to set transmittal npub 

            
        nauth_presenter = create_nauth(  npub=acorn_obj.pubkey_bech32,
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
        # need to add in the PQC Step 1

        

        msg_out = await acorn_obj.secure_transmittal(nrecipient=npub_initiator,message=nauth_presenter,dm_relays=auth_relays,kind=auth_kind)

    else:
       pass

    try:
        user_records = await acorn_obj.get_user_records(record_kind=record_kind )
    except:
        user_records = None
    
    #FIXME don't need the grant kinds
    
    grant_kinds = settings.GRANT_KINDS

    # Need to determine what to present
    out_records = []
    is_valid = "Cannot Validate"
    for each in user_records:        

        if isinstance(each["payload"], dict):

            
                        
            event_to_validate: Event = Event().load(each["payload"])
            print(f"event to validate tags: {event_to_validate.tags}")
            tag_owner = get_tag_value(event_to_validate.tags, "safebox_owner")
            tag_safebox = get_tag_value(event_to_validate.tags, "safebox_issuer")
            type_name = get_label_by_id(settings.GRANT_KINDS,event_to_validate.kind)
            # owner_name = tag_owner
            owner_info, picture = await get_profile_for_pub_hex(tag_owner,settings.RELAYS)
            print(f"safebox owner: {tag_owner} {owner_info}")
            # Need to check signature too
            print("let's check signature")  
            print(f"event to validate: {event_to_validate.data()}")
    
            if event_to_validate.is_valid():
                is_valid = "True"

            is_trusted = "TBD"
            content = f"{event_to_validate.content}"
            each["content"] = content
            print(f"line 418 {content}")
            each["verification"] = f"\n\n{'_'*40}\n\nIssued From: {tag_safebox[:6]}:{tag_safebox[-6:]} \nOwner: {owner_info} [{tag_owner[:6]}:{tag_owner[-6:]}] \nValid: {is_valid} | Trusted: {is_trusted} \nType:{type_name} Kind: {event_to_validate.kind} \nCreated at: {event_to_validate.created_at}"
            each["picture"]=picture
        else:
            each["content"] = each["payload"] 
            each["verification"] = f"\n\n{'_'*40}\n\nPlain Text {is_valid}"
            each["picture"]=None
        
        
        out_records.append(each)

    print("present records")
    record_label = get_label_by_id(grant_kinds, record_kind)

    # FIXME this is what is being replaced in present.html
    # const ws_present = new WebSocket(`wss://{{request.url.hostname}}/records/ws/present/{{nauth}}`);

    host = request.url.hostname
    scheme = "ws" if host in ("localhost", "127.0.0.1") else "wss"
    port = f":{request.url.port}" if request.url.port not in (None, 80) else ""
    ws_url = f"{scheme}://{host}{port}/records/ws/present/{nauth}"
    
    return templates.TemplateResponse(  "records/present.html", 
                                        {   "request": request,
                                            
                                            
                                            "user_records": out_records ,
                                            "nauth": nauth_response,
                                            "record_select": record_select,
                                            "record_kind": record_kind,
                                            "record_label": record_label,
                                            "select_kinds": grant_kinds,
                                            "kem_public_key": config.PQC_KEM_PUBLIC_KEY,
                                            "kemalg": settings.PQC_KEMALG,
                                            "ws_url": ws_url

                                        })

@router.get("/retrieve", tags=["records", "protected"])
async def my_retrieve_records(       request: Request, 
                                nauth: str = None,
                                nonce: str = None,
                                record_kind: int = 34002,
                                acorn_obj = Depends(get_acorn)
                    ):
    """Protected access to private data stored in home relay"""
    nauth_response = None
    record_select = False
    



    if nauth:
        
        print("nauth")

        

        parsed_result = parse_nauth(nauth)
        npub_initiator = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values'].get('nonce', '0')
        auth_kind = parsed_result['values'].get("auth_kind", settings.AUTH_KIND)
        auth_relays = parsed_result['values'].get("auth_relays",settings.AUTH_RELAYS)
        transmittal_npub = parsed_result['values'].get("transmittal_npub")
        transmittal_kind = parsed_result['values'].get("transmittal_kind", settings.TRANSMITTAL_KIND)
        transmittal_relays = parsed_result['values'].get("transmittal_relays",settings.TRANSMITTAL_RELAYS)
        scope = parsed_result['values'].get("scope")
    
        if "verifier" in scope:
            record_select = True
            record_kind = int(scope.split(":")[1])
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

    try:
        user_records = await acorn_obj.get_user_records(record_kind=record_kind )
    except:
        user_records = None
    
    print(f"present records: {user_records}")
    present_records = []
    for record in user_records: 

        try:
            
            content = record["payload"]
            
            private_record = record["payload"]
            event_to_validate: Event = Event().load(private_record)
            
            
            # tag_owner = get_tag_value(private_record["tags"], "safebox_owner")
            # tag_safebox = get_tag_value(private_record["tags"], "safebox")
            tag_owner = get_tag_value(event_to_validate.tags, "safebox_owner")
            tag_safebox = get_tag_value(event_to_validate.tags, "safebox")
            type_name = get_label_by_id(settings.GRANT_KINDS,event_to_validate.kind)
            # Need to check signature too
            print("let's check signature")
           
            
            print(f"event to validate: {event_to_validate.data()}")
            
            event_is_valid = event_to_validate.is_valid()
            is_trusted = "TBD"

            content = f"{event_to_validate.content}\n\n{'_'*40}\n\nIssued From: {tag_safebox[:6]}:{tag_safebox[-6:]} \nOwner: {tag_owner[:6]}:{tag_owner[-6:]} \nValid: {event_is_valid} | Trusted: {is_trusted} \nType:{type_name} Kind: {event_to_validate.kind} \nCreated at: {event_to_validate.created_at}"
            record["content"] = content
        except:
            record["content"] = record
        present_records = record
    
    #FIXME don't need the grant kinds
    
    grant_kinds = settings.GRANT_KINDS
  
    record_label = get_label_by_id(grant_kinds, record_kind)
    
    return templates.TemplateResponse(  "records/retrieve.html", 
                                        {   "request": request,
                                            
                                            
                                            "user_records": present_records ,
                                            "nauth": nauth_response,
                                            "record_select": record_select,
                                            "record_kind": record_kind,
                                            "record_label": record_label,
                                            "select_kinds": grant_kinds

                                        })

@router.get("/grantlist", tags=["records", "protected"])
async def retrieve_grant_list(       request: Request, 
                                nauth: str = None,
                                nonce: str = None,
                                record_kind: int = None,
                                acorn_obj = Depends(get_acorn)
                    ):
    """Protected access to private data stored in home relay"""
    nauth_response = None
    record_select = False
    
    if not record_kind:
        record_kind = settings.GRANT_KINDS[0][0]


    if nauth:
        
        print("nauth")

        

        parsed_result = parse_nauth(nauth)
        npub_initiator = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values'].get('nonce', '0')
        auth_kind = parsed_result['values'].get("auth_kind", settings.AUTH_KIND)
        auth_relays = parsed_result['values'].get("auth_relays", settings.AUTH_RELAYS)
        transmittal_npub = parsed_result['values'].get("transmittal_npub")
        transmittal_kind = parsed_result['values'].get("transmittal_kind", settings.TRANSMITTAL_KIND)
        transmittal_relays = parsed_result['values'].get("transmittal_relays", settings.TRANSMITTAL_RELAYS)
        scope = parsed_result['values'].get("scope")
    
        if "verifier" in scope:
            record_select = True
            record_kind = int(scope.split(":")[1])
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

    try:
        user_records = await acorn_obj.get_user_records(record_kind=record_kind )
    except:
        user_records = None
    
    #FIXME don't need the grant kinds
   
    
    grant_kinds = settings.GRANT_KINDS

    # Inspect the user records and see what we can do with them
    

  
    record_label = get_label_by_id(grant_kinds, record_kind)

    host = request.url.hostname
    scheme = "ws" if host in ("localhost", "127.0.0.1") else "wss"
    port = f":{request.url.port}" if request.url.port not in (None, 80) else ""
    ws_url = f"{scheme}://{host}{port}/records/ws/offer/{nauth}"

    # this is the hardcoded one from grantlist.html
    # ws_url = "wss://{{request.url.hostname}}/records/ws/offer/${global_nauth}"
    
    return templates.TemplateResponse(  "records/grantlist.html", 
                                        {   "request": request,
                                            
                                            
                                            "user_records": user_records ,
                                            "nauth": nauth_response,
                                            "record_select": record_select,
                                            "record_kind": record_kind,
                                            "record_label": record_label,
                                            "select_kinds": grant_kinds,
                                            "ws_url": ws_url

                                        })

@router.get("/accept", tags=["records", "protected"])
async def accept_records(            request: Request,
                                nauth: str = None,                         
                                acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to inbox in home relay"""
    nprofile_parse = None
    scope = ""
    grant = ""
 

    
    # acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    # await acorn_obj.load_data()
    # since = None
    since = util_funcs.date_as_ticks(datetime.now())
   
    if acorn_obj == None:
        return



    user_records_with_label = []
    offer_kind = 0
    offer_kind_label=""
    grant_kind = 0
    grant_kind_label = ""
    transmittal_kind = 0

    host = request.url.hostname
    scheme = "ws" if host in ("localhost", "127.0.0.1") else "wss"
    port = f":{request.url.port}" if request.url.port not in (None, 80) else ""
    ws_url = f"{scheme}://{host}{port}/records/ws/accept?nauth={nauth}"

    

    return templates.TemplateResponse(  "records/acceptrecord.html", 
                                        {   "request": request,
                                            
                                            "user_records": user_records_with_label,
                                            "offer_kind": offer_kind,
                                            "offer_kind_label": offer_kind_label,
                                            "grant_kind": grant_kind,
                                            "grant_kind_label": grant_kind_label,
                                            "transmittal_kind": transmittal_kind,
                                            "nauth": nauth,
                                            "ws_url": ws_url

                                        })


@router.websocket("/ws/accept")
async def websocket_accept(websocket: WebSocket,  nauth: str, acorn_obj: Acorn = Depends(get_acorn)):

 
    global global_websocket
    user_records = []
    await websocket.accept()
    await acorn_obj.load_data()
    
    
    global_websocket = websocket

    since_now = int(datetime.now(timezone.utc).timestamp())

    kem_public_key = config.PQC_KEM_PUBLIC_KEY

    print("This is the records websocket")
    
    print("This is the records websocket after sleep")
    print("nauth")
    parsed_result = parse_nauth(nauth)
    npub_initiator = hex_to_npub(parsed_result['values']['pubhex'])
    nonce = parsed_result['values'].get('nonce', '0')
    auth_kind = parsed_result['values'].get("auth_kind",settings.AUTH_KIND)
    auth_relays = parsed_result['values'].get("auth_relays",settings.AUTH_RELAYS)
    transmittal_kind = parsed_result['values'].get("transmittal_kind",settings.TRANSMITTAL_KIND)
    transmittal_relays = parsed_result['values'].get("transmittal_relays",settings.TRANSMITTAL_RELAYS)
    scope = parsed_result['values'].get("scope",None)
    grant = parsed_result['values'].get("grant",None)
    
    
    
    print(f"scope: {scope} grant: {grant}")
    # create the response nauth
    response_nauth = create_nauth(    npub=acorn_obj.pubkey_bech32,
                                nonce=nonce,
                                auth_kind= auth_kind,
                                auth_relays=auth_relays,
                                transmittal_npub=acorn_obj.pubkey_bech32,
                                transmittal_kind=transmittal_kind,
                                transmittal_relays=transmittal_relays,
                                name=acorn_obj.handle,
                                scope=scope,
                                grant=grant
    )

    # send the recipient nauth message
    # this is PQC Step 1 for KEM key agreement - need to send public key only
    kemalg = settings.PQC_KEMALG
    
    print(f"this is where we add in the ML_KEM key agreement using: {kemalg} {settings.PQC_KEMALG}")
   
    # pqc = oqs.KeyEncapsulation(settings.PQC_KEMALG,bytes.fromhex(config.PQC_KEM_SECRET_KEY))
    
    # pqc_public_key_from_nauth = bytes.fromhex(config.PQC_KEM_PUBLIC_KEY)
    # ciphertext, shared_secret = pqc.encap_secret(pqc_public_key_from_nauth)
    # shared_secret_hex = shared_secret.hex()
    # print(f"pqc shared secret: {shared_secret_hex} ciphertext: {ciphertext.hex()}")

    pqc_to_send = { "kem_public_key": config.PQC_KEM_PUBLIC_KEY,
                    "kemalg": settings.PQC_KEMALG
    }
    nembedpqc = create_nembed_compressed(pqc_to_send)
    response_nauth_with_kem= f"{response_nauth}:{nembedpqc}"
    print(f"response nauth with kem {response_nauth_with_kem}")

    msg_out = await acorn_obj.secure_transmittal(nrecipient=npub_initiator,message=response_nauth_with_kem,dm_relays=auth_relays,kind=auth_kind)
    print("let's poll for the records")
    # await asyncio.sleep(10)
    #FIXME - add in an ack here using auth relays

    # This is the same acceptance code that has to go into NWC relay offer_record

    while user_records == []:
        user_records = await acorn_obj.get_user_records(record_kind=transmittal_kind, relays=transmittal_relays,since=since_now)
        await asyncio.sleep(1)

    if user_records == []:
        first_type = 34002        
    else:
        first_type = int(user_records[0].get('type',34002))
        

    for each_record in user_records:
        type = int(each_record['type'])
        print(f"incoming record: {each_record} type: {type}")
        # await acorn_obj.secure_dm(npub,json.dumps(record_obj), dm_relays=relay)
        # 32227 are transmitted as kind 1060
        # await acorn_obj.secure_transmittal(npub,json.dumps(record_obj), dm_relays=relay,transmittal_kind=1060)
        
        print(each_record)
        print(each_record['tag'][0][0],each_record['payload'] )
            # acorn_obj.put_record(record_name=each_record['tag'][0][0],record_value=each_record['payload'],record_type='health',record_kind=37375)
            # record_name = f"{each_record['tag'][0][0]} {each_record['created_at']}" 
        record_name = f"{each_record['tag'][0][0]}" 
        record_value = each_record['payload']
        record_timestamp = each_record.get("timestamp",0)
        record_endorsement = each_record.get("endorsement","")
        endorse_trunc = record_endorsement[:8] + "..." + record_endorsement[-8:]
        final_record = f"{record_value} \n\n[{datetime.fromtimestamp(record_timestamp)} offered by: {endorse_trunc}]" 
        print(f"record_name: {record_name} record value: {final_record} type: {type}")
        # PQC Step 3 Accept
        
        record_ciphertext = each_record.get("ciphertext", None)
        record_kemalg = each_record.get("kemalg", None)
        pqc = oqs.KeyEncapsulation(record_kemalg,bytes.fromhex(config.PQC_KEM_SECRET_KEY))
        shared_secret = pqc.decap_secret(bytes.fromhex(record_ciphertext))
        print(f"PQC Step 3: shared secret {shared_secret.hex()} cipertext: {record_ciphertext} kemalg: {record_ciphertext}")
        k_pqc = Keys(shared_secret.hex())
        my_enc = ExtendedNIP44Encrypt(k_pqc)
        payload_to_decrypt = each_record.get("pqc_encrypted_payload", None)
        if payload_to_decrypt:            
            decrypted_payload = my_enc.decrypt(payload=payload_to_decrypt, for_pub_k=k_pqc.public_key_hex())
            print(f"decrypted payload: {decrypted_payload}")
            record_value = decrypted_payload

        # Just add in record_value instead of final value
        
        await acorn_obj.put_record(record_name=record_name, record_value=record_value, record_kind=type, record_origin=npub_initiator)

    await websocket.send_json({"status": "OK", "detail":f"all good {acorn_obj.handle} {scope} {grant} {user_records}", "grant_kind": first_type})
   

@router.post("/acceptincomingrecord", tags=["records", "protected"])
async def accept_incoming_record(       request: Request, 
                                        incoming_record: incomingRecord,
                                        acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """ accept incoming NPI-17 1060 health record and store as a 32225 record"""

    status = "OK"
    detail = "Nothing yet"



    try:
        parsed_result = parse_nauth(incoming_record.nauth)
        npub_initiator = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values'].get('nonce', '0')
        auth_kind = parsed_result['values'].get("auth_kind", settings.AUTH_KIND)
        auth_relays = parsed_result['values'].get("auth_relays", settings.AUTH_RELAYS)
        transmittal_kind = parsed_result['values'].get("transmittal_kind", settings.TRANSMITTAL_KIND)
        transmittal_relays = parsed_result['values'].get("transmittal_relays",settings.TRANSMITTAL_RELAYS)

        # acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
        # await acorn_obj.load_data()
        scope = parsed_result['values'].get("scope", None)
        grant = parsed_result['values'].get("grant", None)
        grant_kind = int(grant.replace("record:",""))

        print(f"incoming record scope: {scope} grant: {grant}")
        
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
                grant_record = GrantRecord(tag=[record_name], type="generic",payload=record_value)
                print(f"grant record: {grant_record}")
                await acorn_obj.put_record(record_name=record_name, record_value=record_value, record_kind=grant_kind)
                
                detail = f"Matched record {incoming_record.id} accepted!"

        
        
    except Exception as e:
        status = "ERROR"
        detail = f"Error: {e}"
    

    return {"status": status, "detail": detail}  

@router.get("/displayrecord", tags=["records", "protected"])
async def display_record(     request: Request, 
                            card: str = None,
                            kind: int = 34002,
                            action_mode: str = None,
                            acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to updating the card"""

    label_hash = None
    template_to_use = "records/record.html"
    content = ""
    
    if action_mode == 'edit':

        record = await acorn_obj.get_record(record_name=card, record_kind=kind)
        print(f"display record: {record}")
        label_hash = await acorn_obj.get_label_hash(label=card)

        try:
            content = record["payload"]
        except:
            content = record
        
    elif action_mode == 'offer':

        record = await acorn_obj.get_record(record_name=card, record_kind=kind)
        label_hash = await acorn_obj.get_label_hash(label=card)
        template_to_use = "records/recordoffer.html"

        try:
            content = record["payload"]
        except:
            content = record    
    
    elif action_mode =='add':
        card = ""
        content =""
    
    credential_record = {"card":card, "content": content}

    select_kinds = settings.OFFER_KINDS
    select_kind = get_label_by_id(select_kinds, kind)

    offer_kinds = settings.OFFER_KINDS
    offer_label = get_label_by_id(offer_kinds, kind)
    referer = f"{urllib.parse.urlparse(request.headers.get('referer')).path}?record_kind={kind}"
   

    return templates.TemplateResponse(  template_to_use, 
                                        {   "request": request,
                                            
                                            "card": card,
                                            "record_kind": kind,
                                            "offer_kind": kind,
                                            "grant_kind": kind+1,
                                            "offer_label": offer_label,
                                            "select_kind": select_kind,
                                            "referer": referer,
                                            "label_hash": label_hash,
                                            "action_mode":action_mode,
                                            "content": content,
                                            "credential_record": credential_record
                                            
                                        })

@router.get("/displaygrant", tags=["records", "protected"])
async def display_grant(     request: Request, 
                            card: str = None,
                            kind: int = None,
                            action_mode: str = None,
                            acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to updating the card"""

    label_hash = None
    template_to_use = "records/grant.html"
    content = ""
    
    

    if not kind:
        kind = settings.GRANT_KINDS[0][0]
    
    if action_mode == 'edit':

        record = await acorn_obj.get_record(record_name=card, record_kind=kind)
        label_hash = await acorn_obj.get_label_hash(label=card)
        grant_record = GrantRecord(**record)
        print(f"safebox record: {record} {grant_record}")

        try:
            grant_record = GrantRecord(**record)
            # content = record["payload"]
            # content=grant_record.payload
            private_record = record["payload"]
            event_to_validate: Event = Event().load(private_record)
            
            
            # tag_owner = get_tag_value(private_record["tags"], "safebox_owner")
            # tag_safebox = get_tag_value(private_record["tags"], "safebox")
            tag_owner = get_tag_value(event_to_validate.tags, "safebox_owner")
            tag_safebox = get_tag_value(event_to_validate.tags, "safebox")
            type_name = get_label_by_id(settings.GRANT_KINDS,event_to_validate.kind)
            # Need to check signature too
            print("let's check signature")
           
            
            print(f"event to validate: {event_to_validate.data()}")
            
            event_is_valid = event_to_validate.is_valid()
            is_trusted = "TBD"

            content = f"{event_to_validate.content}\n\n{'_'*40}\n\nIssued From: {tag_safebox[:6]}:{tag_safebox[-6:]} \nOwner: {tag_owner[:6]}:{tag_owner[-6:]} \nValid: {event_is_valid} | Trusted: {is_trusted} \nType:{type_name} Kind: {event_to_validate.kind} \nCreated at: {event_to_validate.created_at}"
        except:
            content = record
        
    elif action_mode == 'offer':

        record = await acorn_obj.get_record(record_name=card, record_kind=kind)
        label_hash = await acorn_obj.get_label_hash(label=card)
        template_to_use = "records/recordoffer.html"

        try:
            #content = record["payload"]
            content = record["payload"]["content"]
        except:
            content = record    
    
    elif action_mode =='add':
        card = ""
        content =""
    
   



    grant_kinds = settings.GRANT_KINDS
    grant_label = get_label_by_id(grant_kinds, kind)
    referer = f"{urllib.parse.urlparse(request.headers.get('referer')).path}?record_kind={kind}"
   

    return templates.TemplateResponse(  template_to_use, 
                                        {   "request": request,
                                            
                                            "card": card,
                                            "record_kind": kind,
                                            "grant_label": grant_label,
                                            "referer": referer,
                                            "label_hash": label_hash,
                                            "content": content
                                            
                                            
                                        })



@router.get("/displayoffer", tags=["records", "protected"])
async def display_offer(     request: Request, 
                            card: str = None,
                            kind: int = 34002,
                            action_mode: str = None,
                            acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to updating the card"""
    #FIXME remove action mode because this path is now for offer only
    label_hash = None
   
    content = ""
    

    record = await acorn_obj.get_record(record_name=card, record_kind=kind)
    label_hash = await acorn_obj.get_label_hash(label=card)
    template_to_use = "records/offer.html"

    try:
        content = record["payload"]
    except:
        content = record    
    

    
    credential_record = {"card":card, "content": content}

    select_kinds = settings.OFFER_KINDS
    select_kind = get_label_by_id(select_kinds, kind)

    offer_kinds = settings.OFFER_KINDS
    offer_label = get_label_by_id(offer_kinds, kind)
    referer = f"{urllib.parse.urlparse(request.headers.get('referer')).path}?record_kind={kind}"

    #FIXME hard-coded to replace in offer.html
    # `wss://{{request.url.hostname}}/records/ws/listenfornauth/${global_nauth}`
    host = request.url.hostname
    scheme = "ws" if host in ("localhost", "127.0.0.1") else "wss"
    port = f":{request.url.port}" if request.url.port not in (None, 80) else ""
    ws_url = f"{scheme}://{host}{port}/records/ws/listenfornauth/"
    # need to add in global_nauth in the page

    return templates.TemplateResponse(  template_to_use, 
                                        {   "request": request,
                                            
                                            "card": card,
                                            "record_kind": kind,
                                            "offer_kind": kind,
                                            "grant_kind": kind+1,
                                            "offer_label": offer_label,
                                            "select_kind": select_kind,
                                            "referer": referer,
                                            "label_hash": label_hash,
                                            "action_mode":action_mode,
                                            "content": content,
                                            "credential_record": credential_record,
                                            "ws_url": ws_url
                                            
                                        })

@router.get("/manageoffer", tags=["records", "protected"])
async def manage_offer(     request: Request, 
                            card: str = None,
                            kind: int = 34002,
                            label: str = "default",
                            action_mode: str = None,
                            acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to updating the card"""

    label_hash = None
    template_to_use = "records/manageoffer.html"
    content = ""
    
    if action_mode == 'edit':

        record = await acorn_obj.get_record(record_name=card, record_kind=kind)
        label_hash = await acorn_obj.get_label_hash(label=card)

        try:
            content = record["payload"]
        except:
            content = record
        
    elif action_mode == 'offer':

        record = await acorn_obj.get_record(record_name=card, record_kind=kind)
        label_hash = await acorn_obj.get_label_hash(label=card)
        template_to_use = "records/recordoffer.html"

        try:
            content = record["payload"]
        except:
            content = record    
    
    elif action_mode =='add':
        card = label
        content =""
    
    credential_record = {"card":card, "content": content}

    select_kinds = settings.OFFER_KINDS
    select_kind = get_label_by_id(select_kinds, kind)

    offer_kinds = settings.OFFER_KINDS
    offer_label = get_label_by_id(offer_kinds, kind)
    referer = f"{urllib.parse.urlparse(request.headers.get('referer')).path}?record_kind={kind}"
   

    return templates.TemplateResponse(  template_to_use, 
                                        {   "request": request,
                                            
                                            "card": card,
                                            "record_kind": kind,
                                            "offer_kind": kind,
                                            "grant_kind": kind+1,
                                            "offer_label": offer_label,
                                            "select_kind": select_kind,
                                            "referer": referer,
                                            "label_hash": label_hash,
                                            "action_mode":action_mode,
                                            "content": content,
                                            "credential_record": credential_record
                                            
                                        })

@router.post("/updaterecord", tags=["records", "protected"])
async def update_record(    request: Request, 
                            update_card: updateCard,
                            acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Update card in safebox"""
    status = "OK"
    detail = "Nothing yet"


    
    
    # This is where we can do specialized handling for records that need to be transmittee

    try:

        await acorn_obj.put_record(record_name=update_card.title,record_value=update_card.content, record_kind=update_card.final_kind)
        detail = "Update successful!"
    except Exception as e:
        status = "ERROR"
        detail = f"Error: {e}"
    

    return {"status": status, "detail": detail} 

@router.post("/deleterecord", tags=["safebox", "protected"])
async def delete_card(         request: Request, 
                            delete_card: deleteCard,
                            acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Delete card from safebox"""
    status = "OK"
    detail = "Nothing yet"

    
    try:

        msg_out = await acorn_obj.delete_record(label=delete_card.title, record_kind=delete_card.kind)
        detail = f"Success! {msg_out}"
    except Exception as e:
        status = "ERROR"
        detail = f"Error: {e}"
    

    return {"status": status, "detail": detail} 

@router.post("/nauth", tags=["records", "protected"])
async def generate_nauth(    request: Request, 
                        nauth_request: nauthRequest,
                        acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Protected access to private data stored in home relay"""
    status = "OK"
    detail = "None"
    print(f"nauth request: {nauth_request}")
    nonce = None

    
    # acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    # await acorn_obj.load_data()
    # figure out to use the owner key or the wallet key
    # just use the wallet
    print("this is the records/nauth")

    # pub_hex_to_use = acorn_obj.pubkey_hex
    npub_to_use = acorn_obj.pubkey_bech32
    
    print(f"scope: {nauth_request.scope} nonce: {nonce}")
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.npub==acorn_obj.pubkey_bech32)
        safeboxes = session.exec(statement)
        safebox_for_nonce = safeboxes.first()
        safebox_for_nonce.session_nonce = nonce
        session.add(safebox_for_nonce)
        session.commit()

    try:

        
        transmittal_npub = acorn_obj.pubkey_bech32

        if nauth_request.transmittal_kind:
            transmittal_kind = nauth_request.transmittal_kind
        else:
            transmittal_kind = settings.RECORD_TRANSMITTAL_KIND
       
        if nauth_request.compact:
            nonce = generate_nonce(length=1)
            auth_relays = None
            transmittal_relays=None
            
            
        else:
           
            auth_relays=settings.AUTH_RELAYS  
            transmittal_relays=settings.RECORD_TRANSMITTAL_RELAYS
            nonce = generate_nonce(length=16)

        detail = create_nauth(  npub=npub_to_use,
                                nonce=nonce,
                                auth_kind=settings.AUTH_KIND,
                                auth_relays=auth_relays,
                                transmittal_npub=transmittal_npub,
                                transmittal_kind = transmittal_kind,
                                transmittal_relays=transmittal_relays,
                                name=acorn_obj.handle,
                                scope=nauth_request.scope, 
                                grant=nauth_request.grant

                               
                            )
        

        print(f"scope: {nauth_request.scope} grant: {nauth_request.grant}")
        print(f"generated nauth: {detail} {len(detail)}")
      
    except:
        detail = "Not created"

    return {"status": status, "detail": detail}

@router.post("/sendrecord", tags=["records", "protected"])
async def post_send_record(      request: Request, 
                                record_parms: sendCredentialParms,                                
                                acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """Select record for verification"""
    nauth_response = None
    print(f"send record {record_parms}")

    if record_parms.nauth:
        parsed_nauth = parse_nauth(record_parms.nauth)

        scope = parsed_nauth['values']['scope']
        grant = parsed_nauth['values'].get("grant")
        

        
        pubhex = parsed_nauth['values']['pubhex']
        npub_recipient = hex_to_npub(pubhex)
        nonce = parsed_nauth['values'].get('nonce', '0')
        auth_kind = parsed_nauth['values'].get('auth_kind', settings.AUTH_KIND)
        auth_relays = parsed_nauth['values'].get('auth_relays', settings.AUTH_RELAYS)
        transmittal_pubhex = parsed_nauth['values'].get('transmittal_pubhex',acorn_obj.pubkey_hex)
        transmittal_kind = parsed_nauth['values'].get('transmittal_kind', settings.TRANSMITTAL_KIND)
        transmittal_relays = parsed_nauth['values'].get('transmittal_relays', settings.TRANSMITTAL_RELAYS)

        print(f"send record to transmittal_pubhex: {transmittal_pubhex} scope: {scope} grant:{grant}")

        # Need to inspect scope to determine what to do
        #TODO refactor this code
        if "prover" in scope:
            # this means the presentation has the corresponding record hash
            transmittal_npub = hex_to_npub(transmittal_pubhex)
            print(f"grant: {record_parms.grant}")
            # record_hash = scope.replace("prover:","")
            # print(f"need to select credential with record hash {record_hash}")
            # record_out = await acorn_obj.get_record(record_kind=34002, record_by_hash=record_hash)
            record_out = await acorn_obj.get_record(record_name=record_parms.grant, record_kind=34002)
            
        elif "verifier" in scope:
            transmittal_npub = hex_to_npub(transmittal_pubhex)
            #need to figure how to pass in the label to look up
            verifier_kind = int(scope.split(":")[1])
            print(f"grant: {record_parms.grant}")
            record_out = await acorn_obj.get_record(record_name=record_parms.grant, record_kind=verifier_kind)
            # record_out = {"tag": "TBD", "payload" : "This will be a real credential soon!"}
        else:
            record_out = {"tag": "TBD", "payload" : "This will be a real credential soon!"}

        

        # Add in PQC stuff
        print(f"PQC Step 2a {record_parms.kem_public_key} {record_parms.kemalg}")
        pqc = oqs.KeyEncapsulation(record_parms.kemalg,bytes.fromhex(config.PQC_KEM_SECRET_KEY))
        kem_ciphertext, kem_shared_secret = pqc.encap_secret(bytes.fromhex(record_parms.kem_public_key))
        kem_shared_secret_hex = kem_shared_secret.hex()
        kem_ciphertext_hex = kem_ciphertext.hex()

        k_nip44 = Keys(priv_k=kem_shared_secret_hex)
        print(f"kem shared secret: {kem_shared_secret_hex} ciphertext: {kem_ciphertext_hex}")
        try:
            pass
            my_enc = ExtendedNIP44Encrypt(k_nip44)
            print(f"my NIP44 enc: {my_enc}")
        except:
            pass
        # Now add to record
        record_out['ciphertext']    = kem_ciphertext_hex
        record_out['kemalg']        = record_parms.kemalg

        payload = record_out['payload']
        record_out['pqc_encrypted_payload'] =  my_enc.encrypt(payload, to_pub_k=k_nip44.public_key_hex())
        record_out['payload'] = "This record is quantum-safe"
        print(f"This is the record to be sent for verification:{record_out}")

        try:
            nembed = create_nembed_compressed(record_out)
        except:
            nembed = create_nembed_compressed({"test": "test"})
        # print(nembed)

        #TODO Need to select the right credential and send over the to verifier
        # just send scope for now

        # Need to get the PQC public key of the requestor

        print(f"we are sending a record to verify: {record_out}")
        msg_out = await acorn_obj.secure_transmittal(transmittal_npub,nembed, dm_relays=transmittal_relays,kind=transmittal_kind)

    return {"status": "OK", "result": True, "detail": f"Successfully sent to {transmittal_npub}for verification!"}

@router.get("/recordrequest", tags=["records", "protected"])
async def record_request(      request: Request,
                          
                                    acorn_obj: Acorn = Depends(get_acorn)
                    ):
    """This function display the verification page"""
    """The page sets up a websocket to listen for the incoming credential"""

    
    
    grant_kinds = settings.GRANT_KINDS

    return templates.TemplateResponse(  "records/recordrequest.html", 
                                        {   "request": request,  
                                            "grant_kinds": grant_kinds

                                        })


@router.websocket("/ws/recorddata")
async def ws_record_data( websocket: WebSocket,                                          
                                        acorn_obj = Depends(get_acorn)
                                        ):
    await websocket.accept()
    return

@router.websocket("/ws/present/{nauth}")
async def ws_record_present( websocket: WebSocket, 
                                        nauth:str=None, 
                                        acorn_obj: Acorn = Depends(get_acorn)
                                        ):
    print(f"websocket opened for /ws/present {nauth}")
    since_now = int(datetime.now(timezone.utc).timestamp())
    requester_nauth = None
    requester_nembed = None
    
    if nauth:
        parsed_nauth = parse_nauth(nauth) 
        pubhex_initiator =   parsed_nauth['values'] ['pubhex'] 
        auth_kind = parsed_nauth['values'].get('auth_kind', settings.AUTH_KIND)  
        auth_relays = parsed_nauth['values'].get('auth_relays', settings.AUTH_RELAYS)
        print(f"npub initiator: {hex_to_npub(pubhex_initiator)}")
    
    await websocket.accept()
    
    print("start listening for requester data")
    requester_nauth, requester_nembed = await acorn_obj.listen_for_record_sub(record_kind=auth_kind,since=None,relays=auth_relays,timeout=settings.LISTEN_TIMEOUT)
    print(f"requester nauth: {requester_nauth} requester nembed: {requester_nembed}")
    if requester_nembed:
        parsed_nembed = parse_nembed_compressed(requester_nembed)
        kem_public_key = parsed_nembed['kem_public_key']
        kemalg = parsed_nembed['kemalg']
        print(f"From the requester provided to the presenter: kem public key: {kem_public_key} kemalg {kemalg}")
        kem_material = {'kem_public_key': kem_public_key, 'kemalg': kemalg}
        await websocket.send_json(kem_material)

    

@router.websocket("/ws/offer/{nauth}")
async def ws_record_offer( websocket: WebSocket, 
                                        nauth:str=None, 
                                        acorn_obj = Depends(get_acorn)
                                        ):

    print(f"ws nauth: {nauth}")
    auth_relays = None

    await websocket.accept()

    if nauth:
        parsed_nauth = parse_nauth(nauth) 
        npub_initiator =   parsed_nauth['values'] ['npub'] 
        auth_kind = parsed_nauth['values'] ['auth_kind']   
        auth_relays = parsed_nauth['values']['auth_relays']
        print(f"npub initiator: {npub_initiator}")



        msg_out = await acorn_obj.secure_transmittal(nrecipient=npub_initiator,message=nauth,dm_relays=auth_relays,kind=auth_kind)

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
                client_nauth, presenter,kem_public_key = await listen_for_request(acorn_obj=acorn_obj,kind=auth_kind, since_now=since_now, relays=auth_relays)
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

@router.websocket("/ws/listenforrequestor/{nauth}")
async def ws_listen_for_requestor( websocket: WebSocket, 
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
        if datetime.now() - start_time > timedelta(seconds=settings.LISTEN_TIMEOUT):
            print("1 minute has passed. Exiting loop.")
            await websocket.send_json({"status":"TIMEOUT"})
            break
        try:
            # Error handling
            
            try:
                client_nauth, presenter, ken_public_key = await listen_for_request(acorn_obj=acorn_obj,kind=auth_kind, since_now=since_now, relays=auth_relays)
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

@router.websocket("/ws/request/{nauth}")
async def ws_listen_for_presentation( websocket: WebSocket, 
                                        nauth:str=None, 
                                        acorn_obj: Acorn = Depends(get_acorn)
                                        ):

    print(f"listen with: {nauth}")
    auth_relays = None

    await websocket.accept()


    if nauth:
        parsed_nauth = parse_nauth(nauth)   
        auth_kind = parsed_nauth['values'].get('auth_kind', settings.AUTH_KIND)  
        auth_relays = parsed_nauth['values'].get('auth_relays', settings.AUTH_RELAYS)
        transmittal_kind = parsed_nauth['values'].get('transmittal_kind', settings.TRANSMITTAL_KIND)  
        transmittal_relays = parsed_nauth['values'].get('transmittal_relays', settings.TRANSMITTAL_RELAYS)
        print(f"ws transmittal relays: {transmittal_relays}")


    # since_now = None
    since_now = int(datetime.now(timezone.utc).timestamp())
    start_time = datetime.now()
    


    

    naddr = acorn_obj.pubkey_bech32
    incoming_record_old = None

    # Need to:
    # 1. listen for nauth of presenting safebox
    # 2. send kem public key and kemalg
    # 3. listen for incoming records

    
    print(f"#1 listen for nauth ")
    presenter_nauth, presenter_nembed = await acorn_obj.listen_for_record_sub(record_kind=auth_kind, since=since_now, relays=auth_relays,timeout=settings.LISTEN_TIMEOUT)
    parsed_nauth = parse_nauth(presenter_nauth)

    
    print(f"we've got presenter nauth {presenter_nauth}")
    presenter_nauth_parsed = parse_nauth(presenter_nauth)
    presenter_npub = hex_to_npub(presenter_nauth_parsed['values']['pubhex'])
    presenter_auth_kind = presenter_nauth_parsed['values'].get('auth_kind', settings.AUTH_KIND)
    presenter_auth_relays = presenter_nauth_parsed['values'].get('auth_relays', settings.AUTH_RELAYS)
    
    print("we can now send the kem public key and kemalg")

    kem_material = {    'kem_public_key': config.PQC_KEM_PUBLIC_KEY,
                        'kemalg': settings.PQC_KEMALG
                        }
    nembed_to_send = create_nembed_compressed(kem_material)
    message = f"{nauth}:{nembed_to_send}"
    print(f"send to presenter npub: {presenter_npub}")

    msg_out = await acorn_obj.secure_transmittal(nrecipient=presenter_npub,message=message,kind=presenter_auth_kind,dm_relays=presenter_auth_relays)
    print(f"msg out {msg_out}")
    


    print(f"now let's wait for the presenting records...")
    while True:
        if datetime.now() - start_time > timedelta(minutes=1):
            print("1 minute has passed. Exiting loop.")
            await websocket.send_json({"status":"TIMEOUT"})
            break
        try:
            # await acorn_obj.load_data()
            try:
                incoming_record,presenter,kem_public_key = await listen_for_request(acorn_obj=acorn_obj,kind=transmittal_kind, since_now=since_now, relays=transmittal_relays)
            except Exception as e:
                incoming_record=None
            


            if incoming_record != incoming_record_old: 
                # parsed_nauth = parse_nauth(client_nauth)
                # transmittal_kind = parsed_nauth['values'].get('transmittal_kind')
                # transmittal_relays = parsed_nauth['values'].get('transmittal_relays')
                record_json = parse_nembed_compressed(incoming_record)
                print(f"parse record json: {record_json}")
                #### Do the verification here... ####
                verify_result = "Done"
                #### Finish verification ####
                

                #FIXME Record coming via QR code is single from NFC is a List
                if not isinstance(record_json, list):
                    record_json = [record_json]

                # Check each record payload and decide how to validate
                # Payload is either plain text or dict.
                # If payload is dict, then it is a signed nostr event embedded in the payload
                # determine content to display and verification result

                out_records =[]
                is_valid = "Cannot Validate"
                is_presenter = False
                #TODO This needs to be refactored into a verification function
                for each in record_json:
                    # Add in PQC stuff here
                    record_ciphertext = each.get("ciphertext", None)
                    record_kemalg = each.get("kemalg", None) 
                    if record_ciphertext:
                        pqc = oqs.KeyEncapsulation(record_kemalg,bytes.fromhex(config.PQC_KEM_SECRET_KEY))
                        kem_shared_secret = pqc.decap_secret(bytes.fromhex(record_ciphertext))
                        kem_shared_secret_hex = kem_shared_secret.hex()
                        print(f"This is the shared secret: {kem_shared_secret_hex}")
                        k_pqc = Keys(priv_k=kem_shared_secret_hex)
                        my_enc = ExtendedNIP44Encrypt(k_pqc)
                        payload_to_decrypt = each.get("pqc_encrypted_payload", None)
                        if payload_to_decrypt:            
                            decrypted_payload = my_enc.decrypt(payload=payload_to_decrypt, for_pub_k=k_pqc.public_key_hex())
                            print(f"decrypted payload to put in content: {decrypted_payload} compare to content: {each['payload']}")
                            each['payload'] = decrypted_payload
                        
                    

                    print(f"each to present: {each} {presenter}")
                    try:
                        payload_to_use = json.loads(each['payload'])
                    except:
                        payload_to_use = each['payload']

                    print(f"each ciphertext {each.get('ciphertext','None')}")
                    is_valid = "Cannot Validate"
                    if isinstance(payload_to_use, dict):
                        
                        event_to_validate: Event = Event().load(each["payload"])
                        print(f"event to validate tags: {event_to_validate.tags}")
                        tag_owner = get_tag_value(event_to_validate.tags, "safebox_owner")
                        tag_issuer = get_tag_value(event_to_validate.tags, "safebox_issuer")
                        tag_holder = get_tag_value(event_to_validate.tags, "safebox_holder")
                        
                        type_name = get_label_by_id(settings.GRANT_KINDS,event_to_validate.kind)
                        # owner_name = tag_owner
                        owner_info, picture = await get_profile_for_pub_hex(tag_owner,settings.RELAYS)
                        print(f"safebox issuer: {tag_owner} {owner_info}")
                        # Need to check signature too
                        print("let's check signature")  
                        print(f"event to validate: {event_to_validate.data()}")
                
                        if event_to_validate.is_valid():
                            is_valid = "True"

                        
                        is_attested = await get_attestation(owner_npub=tag_owner,safebox_npub=acorn_obj.pubkey_bech32, relays=settings.RELAYS)
                        
                        # authorities = await acorn_obj.get_authorities(kind=event_to_validate.kind)
                        # trust_list = "npub1vqddl2xav68jyyg669r8eqnv5akx6n5fgky698tfr3d4vy30enpse34f7m # npub1q6mcr8tlr3l4gus3sfnw6772s7zae6hqncmw5wj27ejud5wcxf7q0nx7d5"
                        # await acorn_obj.set_trusted_entities(pub_list_str=trust_list)
                        trusted_entities = await acorn_obj.get_trusted_entities(relays=settings.RELAYS)
                        # trusted_entities = ['06b7819d7f1c7f5472118266ed7bca8785dceae09e36ea3a4af665c6d1d8327c', '601adfa8dd668f22111ad1467c826ca76c6d4e894589a29d691c5b56122fccc3']

                        print(f"trusted_entities: {trusted_entities} tag owner {tag_owner}")
                        if tag_owner in trusted_entities:
                            is_trusted = True
                        else:
                            is_trusted = False

                        print(f"test for presenter: {presenter} tag holder: {tag_holder}")
                        if presenter == tag_holder:
                            is_presenter = True

                        print(f"is attested: {is_attested}")
                        rating = "TBD"
                        wot_scores = await acorn_obj.get_wot_scores(pub_key_to_score=tag_owner, relays=settings.WOT_RELAYS)
                        # print(f"rating of owner is: {rating}")
                        wot_scores_to_show = "\n".join(f"⭐️ {label}: {value}" for label, value in wot_scores)

                        content = f"{event_to_validate.content}"
                        each["content"] = content
                        each["verification"] = f"\nIssuer: {owner_info}\n[{tag_owner[:6]}:{tag_owner[-6:]}]  \nKind: {event_to_validate.kind} \nCreated at: {event_to_validate.created_at} \n\n|{'✅' if is_valid else '❌'} Valid|{'✅' if is_presenter else '❌'} Self-Presented|\n{'✅' if is_attested else '❌'} Attested By Issuer|{'✅' if is_trusted else '❌'} Recognized|\nIssuer WoT Scores\n ------\n{wot_scores_to_show}\n-----"
                        each["picture"] = picture
                        each["is_attested"] = is_attested

                        # PQC Stuff here

            
                       


                    else:
                        each["content"] = each["payload"]   
                        each["verification"] = f"\n\n{'_'*40}\n\nPlain Text {is_valid}"
                        each["picture"] = None
                        each["is_attested"] = False

                    out_records.append(each)
                    print(f"out records: {out_records}")


                msg_out =   {   "status": "VERIFIED",
                                "detail": None, 
                                "records": out_records,
                                "result": is_valid
                               
                               }
                # print(f"send {incoming_record} {record_json}") 
                # print(f"msg out: {msg_out}") 
                await websocket.send_json(msg_out)
                incoming_record_old = incoming_record
                print("incoming record  successful!")
                break
           
        
        except Exception as e:
            print(f"Websocket message: {e}")
            break
        
        await asyncio.sleep(5)
     
        
    print("websocket connection closed")

@router.websocket("/ws/listenfornauth/{nauth}")
async def ws_listen_for_nauth( websocket: WebSocket, 
                                        nauth:str=None, 
                                        acorn_obj = Depends(get_acorn)
                                        ):

    print(f"ws nauth: {nauth}")
    auth_relays = None

    await websocket.accept()

    if nauth:
        parsed_nauth = parse_nauth(nauth)   
        auth_kind = parsed_nauth['values'].get('auth_kind',   settings.AUTH_KIND)
        auth_relays = parsed_nauth['values'].get("auth_relays", settings.AUTH_RELAYS)
        print(f"ws auth relays: {auth_relays}")



    # acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    # await acorn_obj.load_data()

    naddr = acorn_obj.pubkey_bech32
    nauth_old = None
    # since_now = None
    since_now = int(datetime.now(timezone.utc).timestamp())

    # This is PQC Step 2 in the KEM iteraction 
    while True:
        try:
            # await acorn_obj.load_data()
            try:
                client_nauth,presenter,kem_public_key_nauth = await listen_for_request(acorn_obj=acorn_obj,kind=auth_kind, since_now=since_now, relays=auth_relays)
                
                kem_parsed = parse_nembed_compressed(kem_public_key_nauth)
                kem_public_key = kem_parsed['kem_public_key']
                kem_public_key_bytes = bytes.fromhex(kem_public_key)

                kemalg = kem_parsed['kemalg']



                print(f"this is the kem public key: {kem_public_key} kemalg: {kemalg}")
                # These paramaters get passed along to Step 2a via the browser

            except:
                client_nauth=None
            

            
            # parsed_nauth = parse_nauth(client_nauth)
            # name = parsed_nauth['name']
            # print(f"client nauth {client_nauth}")
            

            if client_nauth != nauth_old: 
                parsed_nauth = parse_nauth(client_nauth)
                pubhex = parsed_nauth['values'].get('pubhex')
                transmittal_pubhex = parsed_nauth['values'].get('transmittal_pubhex')
                transmittal_kind = parsed_nauth['values'].get('transmittal_kind',settings.TRANSMITTAL_KIND)
                transmittal_relays = parsed_nauth['values'].get('transmittal_relays', settings.TRANSMITTAL_RELAYS)
                
                # Need to create a new nauth where the transmittal npub points back to the initiator
                new_nauth = create_nauth (  npub= hex_to_npub(pubhex),
                                            nonce = parsed_nauth['values'].get('nonce'),
                                            auth_kind = parsed_nauth['values'].get('auth_kind',settings.AUTH_KIND),
                                            auth_relays = parsed_nauth['values'].get('auth_relays',settings.AUTH_RELAYS),
                                            transmittal_npub = hex_to_npub(pubhex),
                                            transmittal_kind=  transmittal_kind,
                                            transmittal_relays= transmittal_relays,
                                            scope= parsed_nauth['values'].get('scope'),
                                            grant = parsed_nauth['values'].get('grant')

                ) 

                #FIXME use a better variable name than nprofile. Also some extra parameters not needed.
                nprofile = {'nauth': new_nauth, 'name': acorn_obj.handle, 'transmittal_kind': transmittal_kind, 'transmittal_relays': transmittal_relays, "kem_public_key": kem_public_key, 'kemalg': kemalg}
                print(f"send {client_nauth}") 
                await websocket.send_json(nprofile)
                nauth_old = client_nauth
                break
           
        
        except Exception as e:
            print(f"Websocket message: {e}")
            break
        
        await asyncio.sleep(5)
        
        
    print("websocket connection closed")    

@router.post("/acceptprooftoken", tags=["records", "protected"])
async def accept_proof_token( request: Request, 
                                proof_token: proofByToken,
                                acorn_obj: Acorn = Depends(get_acorn)
                    ):
   

    k = Keys(config.SERVICE_NSEC)

    status = "OK"
    detail = "done"
  
    
    token_to_use = proof_token.proof_token
    label_to_use = proof_token.label
    record_kind_to_use = proof_token.kind
    
    
    token_split = token_to_use.split(':')
    parsed_nembed = parse_nembed_compressed(token_to_use)
    host = parsed_nembed["h"]
    vault_url = f"https://{host}/.well-known/proof"
    proof_token_to_use = parsed_nembed["k"]
    nfc_default = parsed_nembed.get("n",["Holder","default"])

    print(f"proof token: {token_to_use} acquired pin: {proof_token.pin} record kind {record_kind_to_use} label to use: {label_to_use} nfc default: {nfc_default}")

    # If Holder is specified using kind 9999 then look up default
    if record_kind_to_use == 99999:
        record_kind_to_use = get_id_by_label(settings.GRANT_KINDS, nfc_default[0])
        label_to_use = nfc_default[1]
        
    print(f"record kind to use: {record_kind_to_use} {type(record_kind_to_use)} {label_to_use} {type(label_to_use)}")
    
    sig = sign_payload(proof_token_to_use, k.private_key_hex())
    pubkey = k.public_key_hex()

    # need to send off to the vault for processing
    submit_data = { "nauth": proof_token.nauth, 
                    "token": proof_token_to_use,
                    "label": label_to_use,
                    "kind": record_kind_to_use,
                    "pin": proof_token.pin,
                    "pubkey": pubkey,
                    "sig": sig

                    }
    
    headers = { "Content-Type": "application/json"}
    print(f"vault url: {vault_url} submit data: {submit_data}")

    response = requests.post(url=vault_url, json=submit_data, headers=headers)
    
    print(response.json())
    vault_response = response.json()

    # add in the polling task here
   
    # task = asyncio.create_task(handle_payment(acorn_obj=acorn_obj,cli_quote=cli_quote, amount=final_amount, tendered_amount=payment_token.amount, tendered_currency=payment_token.currency, mint=HOME_MINT, comment=payment_token.comment))

    return {"status": vault_response['status'], "detail": vault_response['detail']}  

@router.post("/acceptoffertoken", tags=["records", "protected"])
async def accept_offer_token( request: Request, 
                                offer_token: OfferToken,
                                acorn_obj: Acorn = Depends(get_acorn)
                    ):
   

    k = Keys(config.SERVICE_NSEC)

    status = "OK"
    detail = "done"
  
    
    token_to_use = offer_token.offer_token
    
    token_split = token_to_use.split(':')
    parsed_nembed = parse_nembed_compressed(token_to_use)
    host = parsed_nembed["h"]
    offer_url = f"https://{host}/.well-known/offer"
    offer_token_to_use = parsed_nembed["k"]

    print(f"proof token: {token_to_use}")


    
    sig = sign_payload(offer_token_to_use, k.private_key_hex())
    pubkey = k.public_key_hex()

    # need to send off to the vault for processing
    # also need to send along kem_public_key and kemalg
    kem_public_key = config.PQC_KEM_PUBLIC_KEY
    kemalg = settings.PQC_KEMALG

    submit_data = { "nauth": offer_token.nauth, 
                    "token": offer_token_to_use,                    
                    "pubkey": pubkey,
                    "sig": sig,
                    "kem_public_key": kem_public_key,
                    "kemalg": kemalg

                    }
    print(f"data: {submit_data}")
    headers = { "Content-Type": "application/json"}
    print(f"offer url: {offer_url} submit data: {submit_data}")

    response = requests.post(url=offer_url, json=submit_data, headers=headers)
    
    print(f"response from vault: {response.json()}")

    print("Now need to issue the private records")


    # add in the polling task here
   
    # task = asyncio.create_task(handle_payment(acorn_obj=acorn_obj,cli_quote=cli_quote, amount=final_amount, tendered_amount=payment_token.amount, tendered_currency=payment_token.currency, mint=HOME_MINT, comment=payment_token.comment))

    return {"status": status, "detail": detail}  