import asyncio
import logging
from monstr.relay.relay import Relay
from monstr.event.persist_sqlite import RelaySQLiteEventStore
from monstr.client.client import Client
from typing import List
from monstr.encrypt import NIP4Encrypt, Keys
from monstr.event.event import Event
from app.utils import hex_to_npub, parse_nauth, create_nauth, create_nembed_compressed, get_label_by_id
from app.appmodels import RegisteredSafebox
from filelock import FileLock, Timeout
from datetime import datetime, timezone, timedelta

from safebox.acorn import Acorn
from safebox.models import TxHistory, cliQuote
import signal
import json
import bolt11
from typing import Optional

from app.appmodels import RegisteredSafebox, NWCEvent
from sqlmodel import Field, Session, SQLModel, create_engine, select
from sqlalchemy.exc import IntegrityError

from app.tasks import handle_payment, safe_handle_payment, handle_nwc_payment

import os
from app.config import Settings
from aiohttp.client_exceptions import WSMessageTypeError
from aiohttp import ClientSession, ClientConnectionError
import warnings
warnings.filterwarnings("ignore", message="coroutine.*was never awaited", category=RuntimeWarning)



settings = Settings()

RELAYS = settings.RELAYS
TIMEDELTA_SECONDS = 60
k = Keys(settings.NWC_NSEC)
decryptor = NIP4Encrypt(k)

engine = create_engine(settings.DATABASE)

import asyncio
import logging
from aiohttp import ClientSession
from aiohttp.client_exceptions import WSMessageTypeError, ClientConnectorError
from aiohttp import WSMsgType, WSMessageTypeError
import contextlib, sys,io
from contextlib import suppress



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


async def nwc_handle_instruction(safebox_found: RegisteredSafebox, instruction_obj, evt: Event):
    print(f"nwc {safebox_found} pay instruction: {instruction_obj['method']}")
    k = Keys(priv_k=safebox_found.nsec)
    my_enc = NIP4Encrypt(key=k)
    nwc_reply = False

    acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
    await acorn_obj.load_data()

    if instruction_obj['method'] == 'pay_invoice':
        invoice = instruction_obj['params']['invoice']
        invoice_decoded = bolt11.decode(invoice)
        invoice_amount = invoice_decoded.amount_msat//1000
        

        comment = instruction_obj['params'].get("comment", "nwc pay")
        tendered_amount = instruction_obj['params'].get("tendered_amount", None)
        tendered_currency = instruction_obj['params'].get("tendered_currency", "SAT")
        print(f"this is the invoice to pay: {invoice}")
        
        print(f"balance {acorn_obj.balance}")
        try:
            msg_out, final_fees, payment_hash, payment_preimage, description_hash = await acorn_obj.pay_multi_invoice(invoice)
            nfc_msg = f"💳 {comment} "
           
            await acorn_obj.add_tx_history(     tx_type="D", 
                                                amount=invoice_amount, 
                                                tendered_amount=tendered_amount,
                                                tendered_currency=tendered_currency,
                                                comment=nfc_msg, 
                                                fees=final_fees,
                                                invoice=invoice,
                                                payment_hash=payment_hash,
                                                payment_preimage=payment_preimage)
            
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
        cli_quote = acorn_obj.deposit(amount, settings.HOME_MINT)
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
        nauth = instruction_obj['params']['nauth']
        label = instruction_obj['params']['label']
        print(f"we are going to present a proof! {nauth}")

        parsed_result = parse_nauth(nauth)
        npub_initiator = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values']['nonce']
        auth_kind = parsed_result['values'].get("auth_kind")
        auth_relays = parsed_result['values'].get("auth_relays")
        transmittal_npub = parsed_result['values'].get("transmittal_npub")
        transmittal_kind = parsed_result['values'].get("transmittal_kind")
        transmittal_relays = parsed_result['values'].get("transmittal_relays")
        scope = parsed_result['values'].get("scope")
        print(f"present_record scope: {scope} label: {label}")
        record_kind = int(scope.split(":")[1])
        
        
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

        record_out = await acorn_obj.get_record(record_name=label, record_kind=record_kind)

        print(f"record out: {record_out}")
        #TODO This error handling can be improved
        try:
            nembed = create_nembed_compressed(record_out)
        except:
            record_out = {'tag': ['none'], 'type': 'generic', 'payload': 'Record is not found!'}
            nembed = create_nembed_compressed(record_out)

        print(f"nembed: {nembed}")
        print("sleep for 5 seconds")
        await asyncio.sleep(5)
        msg_out = await acorn_obj.secure_transmittal(nrecipient=npub_initiator,message=nembed, dm_relays=transmittal_relays,kind=transmittal_kind)
        print(f"msg out: {msg_out} dm relays: {transmittal_relays} kind: {transmittal_kind}")
    elif instruction_obj['method'] == 'offer_record':
        print("we have an offer record!")
        nauth = instruction_obj['params']['nauth']
        parsed_result = parse_nauth(nauth)
        npub_initiator = hex_to_npub(parsed_result['values']['pubhex'])
        nonce = parsed_result['values']['nonce']
        auth_kind = parsed_result['values'].get("auth_kind")
        auth_relays = parsed_result['values'].get("auth_relays")
        transmittal_npub = parsed_result['values'].get("transmittal_npub")
        transmittal_kind = parsed_result['values'].get("transmittal_kind")
        transmittal_relays = parsed_result['values'].get("transmittal_relays")
        scope = parsed_result['values'].get("scope", None)
        grant = parsed_result['values'].get("grant", None)

        print(f"present_record scope: {scope} grant: {grant}")
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
        print(f"response nauth: {response_nauth}")

        # send the recipient nauth message
        msg_out = await acorn_obj.secure_transmittal(nrecipient=npub_initiator,message=response_nauth,dm_relays=auth_relays,kind=auth_kind)
        since_now = int(datetime.now(timezone.utc).timestamp())
        await asyncio.sleep(5)
        user_records = await acorn_obj.get_user_records(record_kind=transmittal_kind, relays=transmittal_relays )
        # print(f"user records: {user_records}")
        offer_kind = int(scope.replace("offer:",""))
        grant_kind = int(grant.replace("record:",""))
        offer_kind_label = get_label_by_id(settings.OFFER_KINDS,offer_kind)
        grant_kind_label = get_label_by_id(settings.GRANT_KINDS, grant_kind)
        user_records_with_label = []
        for each in user_records:
            each['label'] = get_label_by_id(settings.GRANT_KINDS, int(each['type']))
            user_records_with_label.append(each)

        for each_record in user_records_with_label:
            record_name = f"{each_record['tag'][0][0]}" 
            record_type = int(each_record['type'])
            record_value = each_record['payload']
            print(f'record name {record_name} record value {record_value} record type {record_type}' )
            if record_type == grant_kind:
                await acorn_obj.put_record(record_name=record_name, record_value=record_value, record_kind=grant_kind)
    
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
            cashu_token = await acorn_obj.issue_token(amount)
        except:
            cashu_token = "nsf"
            
        pay_obj =   {"token": cashu_token,
                            "amount": amount, 
                            "comment": comment,
                            "tendered_amount": tendered_amount,
                            "tendered_currency": tendered_currency}
        
        nembed_to_send = create_nembed_compressed(pay_obj)
        print(f"nembed to send: {nembed_to_send}")
               

        await acorn_obj.secure_transmittal(nrecipient=hex_to_npub(recipient_pubkey),message=nembed_to_send,dm_relays=relays,kind=21401)
        if cashu_token == "nsf":
            pass
            await acorn_obj.add_tx_history(tx_type='X', amount=0, comment="Failed due to NSF",tendered_amount=0,tendered_currency="NAN")
        else:
            await acorn_obj.add_tx_history(tx_type='D', amount=amount, comment=comment,tendered_amount=tendered_amount,tendered_currency=tendered_currency)

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
            safebox_npub = hex_to_npub(evt.p_tags[0])
        
            safebox_found = nwc_db_lookup_safebox(safebox_npub)
            if safebox_found:
                decryptor = NIP4Encrypt(key=Keys(safebox_found.nsec))
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
        await c.end()
        raise

    



async def listen_notes_connected(url):
    while True:
        c = Client(url)
        run_task = asyncio.create_task(c.run())

        try:
            await c.wait_connect(timeout=10)
            print(f"[{url}] Connected and listening...")

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
            print(f"[{url}] listen_notes_connected cancelled.")
            run_task.cancel()
            try:
                await run_task
            except asyncio.CancelledError:
                pass
            except Exception as e:
                print(f"[{url}] Exception while awaiting cancelled run_task: {e}")
            await c.end()
            raise  # must re-raise to properly propagate cancellation

        except Exception as e:
            print(f"[{url}] Listener error: {e}. Restarting in 5 seconds...")

        finally:
            if not run_task.done():
                run_task.cancel()
                try:
                    await run_task
                except asyncio.CancelledError:
                    pass
                except Exception as e:
                    print(f"[{url}] Suppressed error from cancelled run_task: {e}")

            await c.end()
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