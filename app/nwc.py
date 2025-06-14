import asyncio
import logging
from monstr.relay.relay import Relay
from monstr.event.persist_sqlite import RelaySQLiteEventStore
from monstr.client.client import Client
from typing import List
from monstr.encrypt import NIP4Encrypt, Keys
from monstr.event.event import Event
from app.utils import hex_to_npub
from app.appmodels import RegisteredSafebox
from filelock import FileLock, Timeout
from datetime import datetime

from safebox.acorn import Acorn
import signal
import json
import bolt11
from typing import Optional

from app.appmodels import RegisteredSafebox, NWCEvent
from sqlmodel import Field, Session, SQLModel, create_engine, select
from sqlalchemy.exc import IntegrityError

import os
from app.config import Settings

settings = Settings()

RELAYS = settings.RELAYS
k = Keys(settings.NWC_NSEC)
decryptor = NIP4Encrypt(k)

engine = create_engine(settings.DATABASE)

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


async def nwc_handle_pay_instruction(safebox_found: RegisteredSafebox, payinstruction_obj, evt: Event):
    # print(f"nwc {safebox_found} pay instruction {payinstruction_obj}")
    k = Keys(priv_k=safebox_found.nsec)
    my_enc = NIP4Encrypt(key=k)

    acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
    await acorn_obj.load_data()

    if payinstruction_obj['method'] == 'pay_invoice':
        invoice = payinstruction_obj['params']['invoice']
        invoice_decoded = bolt11.decode(invoice)
        invoice_amount = invoice_decoded.amount_msat//1000

        comment = payinstruction_obj['params'].get("comment", "nwc pay")
        print(f"this is the invoice to pay: {invoice}")
        
        print(f"balance {acorn_obj.balance}")
        try:
            msg_out, final_fees = await acorn_obj.pay_multi_invoice(invoice)
            nfc_msg = f"💳 {comment} "
            await acorn_obj.add_tx_history("D",invoice_amount, comment=nfc_msg, fees=final_fees)
            
        except Exception as e:
            # raise Exception(f"Error {e}")
            print(f"Error {e}")
    elif payinstruction_obj['method'] == 'list_transactions':
        print("we have a list_transactions!") 
        tx_history = await acorn_obj.get_tx_history()
        print(tx_history)
        tx_nwc_history = []
        for each in tx_history[:10]:
            print(each)
            each_transaction = {
               "type": "incoming" if each['tx_type'] == 'C' else "outgoing", 
               "invoice": "123", 
               "description": "456",
               "description_hash": "789", 
               "preimage": "123", 
               "payment_hash": "123", 
               "amount": each['amount'] * 1000, 
               "fees_paid": each['fees'] * 1000,
               "created_at": int(datetime.strptime(each['create_time'], '%Y-%m-%d %H:%M:%S').timestamp()), 
               "expires_at": int(datetime.now().timestamp()), 
               "settled_at": int(datetime.now().timestamp()), 
               "metadata": {} 
            }
            tx_nwc_history.append(each_transaction)

        result_transactions = {
                                "result_type": "list_transactions",
                                "result": {
                                "transactions": tx_nwc_history
                                 }

                                }  

        async with Client(settings.NWC_RELAYS[0]) as c:
            n_msg = Event(kind=23195,
                        content= my_enc.encrypt(json.dumps(result_transactions), to_pub_k=evt.pub_key),
                        pub_key=k.public_key_hex(),
                        tags=[['e',evt.id],['p', evt.pub_key]])


            n_msg.sign(k.private_key_hex())
            c.publish(n_msg)
            print(f"we published the transactin to {evt.pub_key} {n_msg.e_tags} {n_msg.p_tags} {settings.NWC_RELAYS[0]} ")

        
    
    elif payinstruction_obj['method'] == 'get_balance':     
        response_balance = {
                            "result_type": "get_balance",
                            "result": {
                            "balance": int(acorn_obj.balance * 1000), 
                                }
                            }
        print(response_balance)


        async with Client(settings.NWC_RELAYS[0]) as c:
            n_msg = Event(kind=23195,
                        content= my_enc.encrypt(json.dumps(response_balance), to_pub_k=evt.pub_key),
                        pub_key=k.public_key_hex(),
                        tags=[['e',evt.id],['p', evt.pub_key]])

          


            n_msg.sign(k.private_key_hex())
            c.publish(n_msg)
            print(f"we published the balance to {evt.pub_key} {n_msg.e_tags} {n_msg.p_tags} {settings.NWC_RELAYS[0]} ")

async def listen_notes(url):
    c = Client(url)
    asyncio.create_task(c.run())
    await c.wait_connect()

    print(f"listening for nwc at: {url}")

    def my_handler(the_client: Client, sub_id: str, evt: Event):
        
        try:
            
            
           
            
            if add_nwc_event_if_not_exists(event_id=evt.id):
                
                print(f"we have a new event! {evt.created_at}, {evt.tags}")
            else:
                print("this event has been handled")
                return
            
            safebox_npub = hex_to_npub(evt.p_tags[0])
            
            safebox_found = nwc_db_lookup_safebox(safebox_npub)
            if safebox_found:
                decryptor = NIP4Encrypt(key=Keys(safebox_found.nsec))
                decrypt_event = decryptor.decrypt_event(evt=evt)
                pay_instruction = json.loads(decrypt_event.content)
                asyncio.create_task(nwc_handle_pay_instruction(safebox_found, pay_instruction,evt))
            else:
                print('no wallet on file')

        except Exception as e:
            print(f"Error: {e}")

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

async def listen_nwc():
    print(f"listening for nwc {os.getpid()}")
    url = "wss://relay.getsafebox.app"
    asyncio.create_task(listen_notes(url))

if __name__ == '__main__':
    logging.getLogger().setLevel(logging.DEBUG)
    asyncio.run(listen_nwc())