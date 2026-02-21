import asyncio
import logging
import inspect
from monstr.relay.relay import Relay
from monstr.event.persist_sqlite import RelaySQLiteEventStore
from monstr.client.client import Client
from typing import List
from monstr.encrypt import NIP4Encrypt, Keys
from monstr.event.event import Event

from app.utils import hex_to_npub, parse_nauth, create_nauth, create_nembed_compressed, get_label_by_id, starts_with
from app.appmodels import RegisteredSafebox
from filelock import FileLock, Timeout
from datetime import datetime, timezone, timedelta

from safebox.acorn import Acorn
from safebox.models import TxHistory, cliQuote
from safebox.monstrmore import ExtendedNIP44Encrypt
import signal
import json
import bolt11
from typing import Optional

from app.appmodels import RegisteredSafebox, NWCEvent, NWCSecret
from sqlmodel import Field, Session, SQLModel, select
from sqlalchemy.exc import IntegrityError

from app.tasks import handle_payment, safe_handle_payment, handle_nwc_payment
from app.db import engine

import os
from app.config import Settings, ConfigWithFallback
from aiohttp.client_exceptions import WSMessageTypeError
from aiohttp import ClientSession, ClientConnectionError
import warnings
warnings.filterwarnings("ignore", message="coroutine.*was never awaited", category=RuntimeWarning)

import oqs

settings = Settings()
config = ConfigWithFallback()

RELAYS = settings.RELAYS
TIMEDELTA_SECONDS = 60
SERVICE_NWC_KEYS: Keys | None = Keys(config.NWC_NSEC) if config.NWC_NSEC else None

import asyncio
import logging
from aiohttp import ClientSession
from aiohttp.client_exceptions import WSMessageTypeError, ClientConnectorError
from aiohttp import WSMsgType, WSMessageTypeError
import contextlib, sys,io
from contextlib import suppress



def _is_expected_ws_close_exc(exc: BaseException) -> bool:
    return isinstance(exc, WSMessageTypeError) and "not WSMsgType.TEXT" in str(exc)


async def _close_client(c: Client) -> None:
    """Handle monstr client end() implementations that may be sync or async."""
    try:
        result = c.end()
        if inspect.isawaitable(result):
            await result
    except Exception as exc:
        if _is_expected_ws_close_exc(exc):
            logging.getLogger(__name__).debug("Suppressed expected websocket close during client end()")
            return
        raise


def add_nwc_event_if_not_exists(event_id: str) -> bool:
    with Session(engine) as session:
        # Check if the event_id already exists
        statement = select(NWCEvent).where(NWCEvent.event_id == event_id)
        existing_event: Optional[NWCEvent] = session.exec(statement).first()
        
        if existing_event:
            return False  # Event already exists

        # If not found, add the new event
        new_event = NWCEvent(event_id=event_id)
        session.add(new_event)

        try:
            session.commit()
            return True
        except IntegrityError:
            session.rollback()
            return False

def nwc_db_lookup_safebox(npub: str) -> RegisteredSafebox:
   
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.npub==npub)
        safeboxes = session.exec(statement)
        try:
            safebox_found = safeboxes.first()
        except:
            safebox_found = None
        
    return safebox_found


def nwc_lookup_npub_by_secret_pubkey(secret_pubkey_hex: str) -> Optional[str]:
    """
    Resolve a wallet npub by matching the incoming event pubkey against
    registered NWC secrets.
    """
    with Session(engine) as session:
        secrets = session.exec(select(NWCSecret)).all()

    for each in secrets:
        try:
            k = Keys(priv_k=each.nwc_secret)
            if k.public_key_hex() == secret_pubkey_hex:
                return each.npub
        except Exception:
            continue
    return None


def nwc_lookup_secret_by_pubkey(secret_pubkey_hex: str) -> Optional[NWCSecret]:
    """
    Resolve full NWCSecret row by matching a public key derived from nwc_secret.
    """
    with Session(engine) as session:
        secrets = session.exec(select(NWCSecret)).all()

    for each in secrets:
        try:
            k = Keys(priv_k=each.nwc_secret)
            if k.public_key_hex() == secret_pubkey_hex:
                return each
        except Exception:
            continue
    return None


async def nwc_handle_instruction(safebox_found: RegisteredSafebox, instruction_obj, evt: Event):
    print(f"nwc {safebox_found} pay instruction: {instruction_obj['method']}")
    k = Keys(priv_k=safebox_found.nsec)
    my_enc = NIP4Encrypt(key=k)
    nwc_reply = False

    acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
    await acorn_obj.load_data()
    print(f"nwc watch: {acorn_obj.handle} {instruction_obj['method']}")

    if instruction_obj['method'] == 'pay_invoice':
        invoice = instruction_obj['params']['invoice']
        invoice_decoded = bolt11.decode(invoice)
        invoice_amount = invoice_decoded.amount_msat//1000
        

        comment = instruction_obj['params'].get("comment", "Paid!")
        metadata = instruction_obj['params'].get("metadata", {})
        zap_comment = metadata.get("nostr", {}).get("content", comment)
        tendered_amount = instruction_obj['params'].get("tendered_amount", None)
        tendered_currency = instruction_obj['params'].get("tendered_currency", "SAT")
        nwc_msg = f"Zap: {zap_comment} "
        print(f"this is the invoice to pay: {invoice} and metadata: {nwc_msg}")
        
        print(f"balance {acorn_obj.balance}")
        try:
            msg_out, final_fees, payment_hash, payment_preimage, description_hash = await acorn_obj.pay_multi_invoice(invoice, comment=nwc_msg, tendered_amount=tendered_amount,tendered_currency=tendered_currency)
            
           
            #FIXME - need to add these parameters to pay_multi_invoice
            # await acorn_obj.add_tx_history(     tx_type="D", 
            #                                   amount=invoice_amount, 
            #                                    tendered_amount=tendered_amount,
            #                                    tendered_currency=tendered_currency,
            #                                    comment=nfc_msg, 
            #                                    fees=final_fees,
            #                                    invoice=invoice,
            #                                    payment_hash=payment_hash,
            #                                    payment_preimage=payment_preimage)
            
        except Exception as e:
            # raise Exception(f"Error {e}")
            print(f"Error {e}")

        
        response_json = {
                            "result_type": "pay_invoice",
                            "result": {
                                "preimage": payment_preimage, 
                                "fees_paid": final_fees * 1000
                                }
                        }

       
        nwc_reply = True


    elif instruction_obj['method'] == 'make_invoice':
        print(f"make invoice! {instruction_obj}")
        
        cli_quote: cliQuote
        amount = instruction_obj['params']['amount']//1000
        cli_quote = await asyncio.to_thread(acorn_obj.deposit, amount, settings.HOME_MINT)
        invoice_decoded = bolt11.decode(cli_quote.invoice)



        
        response_json = {
                "result_type": "make_invoice",
                "result": {
                    "type": "incoming", 
                    "invoice": cli_quote.invoice,
                    "description": invoice_decoded.description,
                    "description_hash": invoice_decoded.description_hash,
                    "payment_hash": invoice_decoded.payment_hash,
                    "amount": instruction_obj['params']['amount'],
                    "fees_paid": 0, 
                    "created_at": int((datetime.now() - timedelta(seconds=TIMEDELTA_SECONDS)).timestamp()),
                    "metadata": {}
                    }
                }
        print(f"make invoice response! {response_json}")
        nwc_reply = True


        


       

 
        
    
    elif instruction_obj['method'] == 'list_transactions':
        # print("we have a list_transactions!") 
        tx_history = await acorn_obj.get_tx_history()
        # print(tx_history)
        tx_nwc_history = []
        for each in tx_history[:10]:
            # print(f"each: {each}")
            if each['tx_type'] == 'C':
                tx_type = 'incoming'
            else:
                tx_type = 'outgoing'
            
            each_transaction = {
               "type": tx_type, 
              
               "invoice": each.get("invoice", "None"), 
               "description": each["comment"],
               "description_hash": each.get("description_hash", None), 
               "preimage": each.get("preimage", None), 
               "payment_hash":each.get("payment_hash", None), 
               "amount": each['amount'] * 1000, 
               "fees_paid": each['fees'] * 1000,
               "created_at": int(datetime.strptime(each['create_time'], '%Y-%m-%d %H:%M:%S').timestamp()), 

               "metadata": {"description": "test"} 
            }
            tx_nwc_history.append(each_transaction)
        
        # print(tx_nwc_history)
        
        response_json = {
                                "result_type": "list_transactions",
                                "result": {
                                "transactions": tx_nwc_history
                                 }

                                }  
        nwc_reply = True


        
    
    elif instruction_obj['method'] == 'get_balance':     
        response_json = {
                            "result_type": "get_balance",
                            "result": {
                            "balance": int(acorn_obj.balance * 1000), 
                                }
                            }
        # print(response_json)

        nwc_reply = True


    
    elif instruction_obj['method'] == 'get_info': 
        print("we have a get info event!")
        response_json = {
                            "result_type": "get_info",
                            "result": {
                                "pubkey": k.public_key_hex(),
                                "methods": ["pay_invoice", "get_balance", "list_transactions", "get_info", "make_invoice"],
                                "notifications":["payment_received", "payment_sent"]

                                }
                            }
        nwc_reply = True


        
    
    elif instruction_obj['method'] == 'present_record':
        print("we have a present record!")
        nauth = instruction_obj['params']['nauth']
        label = instruction_obj['params']['label']
        record_kind = int(instruction_obj['params']['kind'])
        pin_ok = instruction_obj['params'].get("pin_ok", False)
        print(f"we are going to present a record! label: {label} kind: {record_kind} pin ok: {pin_ok}")

        parsed_result = parse_nauth(nauth)
        npub_initiator = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values'].get('nonce', '0')
        auth_kind = parsed_result['values'].get("auth_kind", settings.AUTH_KIND)
        auth_relays = parsed_result['values'].get("auth_relays",settings.AUTH_RELAYS)
        transmittal_npub = parsed_result['values'].get("transmittal_npub")
        transmittal_kind = parsed_result['values'].get("transmittal_kind",settings.TRANSMITTAL_KIND)
        transmittal_relays = parsed_result['values'].get("transmittal_relays", settings.TRANSMITTAL_RELAYS)
        scope = parsed_result['values'].get("scope")
        print(f"present_record scope: {scope} label: {label}")

        #FIXME Need to determine which record kind should be used - in nauth or what is passed explicity
        # record_kind = int(scope.split(":")[1])
        
        
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
        
                
        #retrieve record
        # record_out = await acorn_obj.get_record(record_name=label, record_kind=record_kind,record_origin=npub_initiator)

        records_out = await acorn_obj.get_user_records(record_kind=record_kind)

        async def _enrich_with_original_record(each_record: dict, requested_label: str | None) -> dict:
            each_out = dict(each_record)
            tag_values = each_record.get("tag", [])
            raw_tag = tag_values[0] if isinstance(tag_values, list) and tag_values else None
            tag_filter = raw_tag.split(":", 1)[1] if isinstance(raw_tag, str) and ":" in raw_tag else raw_tag
            candidate_labels = []
            for candidate in [requested_label, tag_filter, raw_tag]:
                if isinstance(candidate, str) and candidate and candidate not in candidate_labels:
                    candidate_labels.append(candidate)
            for candidate_label in candidate_labels:
                try:
                    _, original_record = await acorn_obj.create_request_from_grant(
                        grant_name=candidate_label,
                        grant_kind=record_kind,
                    )
                    if original_record:
                        each_out["original_record"] = original_record.model_dump(exclude_none=True)
                        print(f"present_record original_record found for label={candidate_label}")
                        break
                except Exception as exc:
                    print(f"present_record original_record lookup failed for {candidate_label}: {exc}")
            return each_out

        filtered_records_out = []
        if label:
            print(f"need to filter out for label: {label} for {records_out}")
            for each in records_out:
                tag = each["tag"][0]
                tag_filter = tag.split(":", 1)[1] if ":" in tag else tag
                print(f"tag filter {tag_filter}")
                # if tag_filter == label:
                if starts_with(test=label, target=tag_filter):
                    each_out = await _enrich_with_original_record(each, label)
                    filtered_records_out.append(each_out)
        else:
            print("just add all the records")
            for each in records_out:
                each_out = await _enrich_with_original_record(each, None)
                filtered_records_out.append(each_out)



        # send the recipient nauth message
        msg_out = await acorn_obj.secure_transmittal(nrecipient=npub_initiator,message=nauth_response,dm_relays=auth_relays,kind=auth_kind)

        print(f"filtered records out: {filtered_records_out}")
        nembed_records = create_nembed_compressed(filtered_records_out)
        # print(f"nembed records: {nembed_records}")

        print(f"nwc record out for {label} {record_kind}: {filtered_records_out}")
        #TODO This error handling can be improved
        try:
            nembed = create_nembed_compressed(records_out)
        except:
            record_out = [{'tag': ['none'], 'type': 'generic', 'payload': 'Record is not found!'}]
            nembed = create_nembed_compressed(record_out)

        print(f"nembed: {nembed}")
        t_sleep = 0.1
        print(f"sleep for {t_sleep} seconds")
        await asyncio.sleep(t_sleep)
        print(f"done sleep for {t_sleep} seconds")
        msg_out = await acorn_obj.secure_transmittal(nrecipient=npub_initiator,message=nembed_records, dm_relays=transmittal_relays,kind=transmittal_kind)
        print(f"msg outx: {msg_out} dm relays: {transmittal_relays} kind: {transmittal_kind}")


    elif instruction_obj['method'] == 'offer_record':
        print("we have an offer record!")
        nauth = instruction_obj['params']['nauth']
        parsed_result = parse_nauth(nauth)
        npub_initiator = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values'].get('nonce', '0')
        auth_kind = parsed_result['values'].get("auth_kind",settings.AUTH_KIND)
        auth_relays = parsed_result['values'].get("auth_relays", settings.AUTH_RELAYS)
        transmittal_npub = parsed_result['values'].get("transmittal_npub")
        transmittal_kind = parsed_result['values'].get("transmittal_kind", settings.TRANSMITTAL_KIND)
        transmittal_relays = parsed_result['values'].get("transmittal_relays", settings.TRANSMITTAL_RELAYS)
        scope = parsed_result['values'].get("scope", None)
        grant = parsed_result['values'].get("grant", None)


        kem_public_key = config.PQC_KEM_PUBLIC_KEY
        kemalg = settings.PQC_KEMALG


        print(f"nwc offer_record scope: {scope} grant: {grant}")
        # record_kind = int(scope.split(":")[1])

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
        print(f"nwc response send to : {npub_initiator}")
        pqc_to_send = { "kem_public_key": config.PQC_KEM_PUBLIC_KEY,
                    "kemalg": settings.PQC_KEMALG
        }
        nembedpqc = create_nembed_compressed(pqc_to_send)
        response_nauth_with_kem= f"{response_nauth}:{nembedpqc}"

        since_now = int(datetime.now(timezone.utc).timestamp())
        # send the recipient nauth message
        msg_out = await acorn_obj.secure_transmittal(nrecipient=npub_initiator,message=response_nauth_with_kem,dm_relays=auth_relays,kind=auth_kind)
        
        # await asyncio.sleep(5)

        print("listen for records")

        # single_record = await acorn_obj.listen_for_record(record_kind=transmittal_kind, relays=transmittal_relays)
        user_records = []
        while user_records == []:
            user_records = await acorn_obj.get_user_records(record_kind=transmittal_kind, relays=transmittal_relays, since=since_now )
            await asyncio.sleep(0.1)
            print("done sleep")


        # print(f"user records: {user_records}")
        offer_kind = int(scope.replace("offer:",""))
        grant_kind = int(grant.replace("record:",""))
        offer_kind_label = get_label_by_id(settings.OFFER_KINDS,offer_kind)
        grant_kind_label = get_label_by_id(settings.GRANT_KINDS, grant_kind)
        user_records_with_label = []
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
            record_name = f"{each_record['tag'][0]}" 
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

            original_record_to_decrpyt = each_record.get("pqc_encrypted_original", None)

            if original_record_to_decrpyt:
                decrypted_original = my_enc.decrypt(payload=original_record_to_decrpyt, for_pub_k=k_pqc.public_key_hex())
                print(f"decrypted original: {decrypted_original}")   

        # Just add in record_value instead of final value
        
        await acorn_obj.put_record(record_name=record_name, record_value=record_value, record_kind=type, record_origin=npub_initiator)
        # Ingest original recored if there is one

        if original_record_to_decrpyt:
            blob_result = await acorn_obj.transfer_blob(
                record_name=record_name,
                record_kind=type,
                record_origin=npub_initiator,
                blobxfer=decrypted_original,
            )
            if blob_result.get("status") != "OK":
                print(
                    "transfer_blob non-fatal status",
                    record_name,
                    type,
                    blob_result.get("status"),
                    blob_result.get("reason"),
                )
    
        print(f"records finished added")
        # Not sure if I need the following line
        
        msg_out = await acorn_obj.secure_transmittal(nrecipient=npub_initiator,message=response_nauth,dm_relays=auth_relays,kind=auth_kind)

    elif instruction_obj['method'] == 'pay_ecash':
        print("we gotta pay ecash!")
        recipient_pubkey = instruction_obj['params']['recipient_pubkey']
        amount = instruction_obj['params']['amount']
        relays = instruction_obj['params']['relays']
        tendered_amount = instruction_obj['params']['tendered_amount']
        tendered_currency = instruction_obj['params']['tendered_currency']
        comment = instruction_obj['params']['comment']
        print(f"{amount} {recipient_pubkey} {relays}")
        # Need to create the nembed object
        try:
            cashu_token = await acorn_obj.issue_token(amount=amount, comment=comment)
        except Exception:
            cashu_token = "nsf"
            
        pay_obj =   {"token": cashu_token,
                            "amount": amount, 
                            "comment": comment,
                            "tendered_amount": tendered_amount,
                            "tendered_currency": tendered_currency}
        
        nembed_to_send = create_nembed_compressed(pay_obj)
        print(f"nwc nembed to send: {nembed_to_send} using {relays}")
        
        delivery_confirmed = False
        if cashu_token != "nsf":
            try:
                await acorn_obj.secure_transmittal(
                    nrecipient=hex_to_npub(recipient_pubkey),
                    message=nembed_to_send,
                    dm_relays=relays,
                    kind=21401,
                )
                delivery_confirmed = True
            except Exception as exc:
                print(f"pay_ecash secure_transmittal failed: {exc}")

            if not delivery_confirmed:
                # Best-effort rollback: re-accept locally if transmittal failed.
                try:
                    await acorn_obj.accept_token(
                        cashu_token=cashu_token,
                        comment=f"rollback undelivered nwc ecash: {comment}",
                    )
                    print("pay_ecash rollback accepted locally")
                except Exception as rollback_exc:
                    print(f"pay_ecash rollback failed: {rollback_exc}")
                    try:
                        recovery_label = f"ecash-recovery-{int(datetime.now(timezone.utc).timestamp())}"
                        await acorn_obj.put_record(
                            record_name=recovery_label,
                            record_value=json.dumps(
                                {
                                    "type": "ecash_delivery_uncertain",
                                    "amount": amount,
                                    "comment": comment,
                                    "recipient_pubkey": recipient_pubkey,
                                    "relays": relays,
                                    "cashu_token": cashu_token,
                                    "created_at": int(datetime.now(timezone.utc).timestamp()),
                                }
                            ),
                            record_kind=37375,
                        )
                        print(f"pay_ecash recovery record saved: {recovery_label}")
                    except Exception as rec_exc:
                        print(f"pay_ecash failed to save recovery record: {rec_exc}")
        else:
            await acorn_obj.add_tx_history(
                tx_type='X',
                amount=0,
                comment="Failed due to NSF",
                tendered_amount=0,
                tendered_currency="NAN",
            )

    elif instruction_obj['method'] == 'accept_ecash':
        print("we gotta accept ecash!")
        pass

    if nwc_reply:
        # print(f"we should be reply here for nwc {instruction_obj['method']} with {response_json}")
        async with Client(settings.NWC_RELAYS[0]) as c:
            n_msg = Event(kind=23195,
                        content= my_enc.encrypt(json.dumps(response_json), to_pub_k=evt.pub_key),
                        pub_key=k.public_key_hex(),
                        tags=[['e',evt.id],['p', evt.pub_key]],
                        created_at=int((datetime.now() - timedelta(seconds=0)).timestamp())
                        
                        )
            n_msg.sign(k.private_key_hex())
            c.publish(n_msg)
            await asyncio.sleep(3)

    if nwc_reply and instruction_obj["method"] == "make_invoice":
        print("do the make_invoice task here")

        await handle_nwc_payment(  acorn_obj=acorn_obj,
                                                   cli_quote=cli_quote,
                                                    amount=amount,
                                                    mint=settings.HOME_MINT,
                                                    callback=paid_callback,
                                                    evt=evt
                                                   
                                                    ) 

        


def paid_callback(nsec: str, payment_hash, evt: Event):  

    print("This is the callback!")   
    
    # asyncio.run(paid_response(nsec,payment_hash,evt))

async def paid_response(nsec: str, payment_hash:str, evt: Event):
        
    k = Keys(priv_k=nsec)
    my_enc = NIP4Encrypt(key=k)
    response_json = {
        "notification_type": "payment_received", 
        "notification": {
    "payment_hash": payment_hash 
        }
    }
    print(f"payment notification {response_json}")
    await asyncio.sleep(5)
    async with Client(settings.NWC_RELAYS[0]) as c:
        n_msg = Event(kind=23196,
                    content= my_enc.encrypt(json.dumps(response_json), to_pub_k=evt.pub_key),
                    pub_key=k.public_key_hex(),
                    tags=[['p', evt.pub_key],["encryption", "nip04"]],
                    created_at=int((datetime.now() - timedelta(seconds=60)).timestamp())
                    
                    )
        n_msg.sign(k.private_key_hex())
        c.publish(n_msg)
        await asyncio.sleep(3)       

def my_handler(the_client: Client, sub_id: str, evt: Event):
    
    try:
        
        
        
        
        if add_nwc_event_if_not_exists(event_id=evt.id):
            
            print(f"we have a new event! {evt.created_at}, {evt.tags}")
            requested_npub = None
            target_pubkey = None
            try:
                target_pubkey = evt.p_tags[0]
                requested_npub = hex_to_npub(target_pubkey)
            except Exception:
                requested_npub = None

            # NWC target pubkey is in p-tag; sender pubkey can also be a mapped secret in client flows.
            mapped_target = nwc_lookup_secret_by_pubkey(target_pubkey) if target_pubkey else None
            mapped_sender = nwc_lookup_secret_by_pubkey(evt.pub_key)

            if mapped_target and mapped_sender and mapped_target.npub != mapped_sender.npub:
                print("NWC mapping mismatch between sender and target; rejecting event")
                return

            mapped = mapped_target or mapped_sender
            if not mapped:
                print("missing mapped NWC secret for event; rejecting")
                return

            safebox_npub = mapped.npub
            if not safebox_npub:
                print("could not determine safebox for incoming nwc event")
                return
        
            safebox_found = nwc_db_lookup_safebox(safebox_npub)
            if safebox_found:
                decrypt_key = mapped.nwc_secret
                decryptor = NIP4Encrypt(key=Keys(priv_k=decrypt_key))
                decrypt_event = decryptor.decrypt_event(evt=evt)
                pay_instruction = json.loads(decrypt_event.content)
                asyncio.create_task(nwc_handle_instruction(safebox_found, pay_instruction,evt))
            else:
                print('no wallet on file')
            
        else:
            print("this event has been handled")
            return
        
        

    except Exception as e:
        print(f"Error: {e}")



async def listen_notes(url):
    
    c = Client(url)
    asyncio.create_task(c.run())
   
    await c.wait_connect()

    print(f"listening for nwc at: {url}")

    c.subscribe(
        handlers=my_handler,
        filters={
            'limit': 1024,
            'kinds': [23194]
        }
    )

    try:
        # keep alive until cancelled
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        print(f"[PID {os.getpid()}] Listener cancelled. Shutting down client...")
        await _close_client(c)
        raise

    



async def listen_notes_connected(url):
    logger = logging.getLogger(__name__)
    while True:
        c = Client(url)
        run_task = asyncio.create_task(c.run())

        try:
            await c.wait_connect(timeout=10)
            logger.info("[%s] Connected and listening...", url)

            c.subscribe(
                handlers=my_handler,
                filters={
                    'limit': 4096,
                    'kinds': [23194]
                }
            )

            # Wait for run() to complete
            await run_task

        except asyncio.CancelledError:
            logger.info("[%s] listen_notes_connected cancelled", url)
            run_task.cancel()
            try:
                await run_task
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                if not _is_expected_ws_close_exc(exc):
                    logger.debug("[%s] Suppressed cancellation exception: %r", url, exc)
            await _close_client(c)
            raise  # must re-raise to properly propagate cancellation

        except Exception as exc:
            if _is_expected_ws_close_exc(exc):
                logger.debug("[%s] Suppressed expected websocket close exception", url)
            else:
                logger.warning("[%s] Listener error, restarting in 5s: %r", url, exc)

        finally:
            if not run_task.done():
                run_task.cancel()
                try:
                    await run_task
                except asyncio.CancelledError:
                    pass
                except Exception as exc:
                    if not _is_expected_ws_close_exc(exc):
                        logger.debug("[%s] Suppressed error from cancelled run_task: %r", url, exc)

            await _close_client(c)
            # During app shutdown we propagate CancelledError immediately and skip restart delay.
            with suppress(asyncio.CancelledError):
                await asyncio.sleep(5)



async def listen_notes_query(url):
    while True:
        c = Client(url)
        

        try:

            print("do a query")
            events = await c.query(
                
                filters={
                    'limit': 4096,
                    'kinds': [23194]
                    
                }
            )
            print(f"events: {events}")
            for each in events:
                my_handler(c,"test", each)

        except:
            pass


        await asyncio.sleep(5)  # short delay before retrying

async def listen_notes_periodic(url):
    while True:
        run_task = asyncio.create_task(listen_notes(url))
        try:
            # Let the task run for 60 seconds
            await asyncio.sleep(600)
        except asyncio.CancelledError:
            print("Periodic listener cancelled. Shutting down...")
            run_task.cancel()
            try:
                await run_task
            except Exception:
                pass
            raise
        else:
            print("Restarting listen_notes_connected...")

            # Cancel the task after the sleep if it's still running
            if not run_task.done():
                run_task.cancel()
                try:
                    await run_task
                except Exception:
                    pass


async def listen_nwc():
    print(f"listening for nwc {os.getpid()}")
    url = "wss://relay.getsafebox.app"
    asyncio.create_task(listen_notes(url))

if __name__ == '__main__':
    logging.getLogger().setLevel(logging.DEBUG)
    asyncio.run(listen_nwc())
