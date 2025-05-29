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


async def nwc_pay_invoice(safebox_found: RegisteredSafebox, payinstruction_obj):
    # print(f"nwc {safebox_found} pay instruction {payinstruction_obj}")

    if payinstruction_obj['method'] == 'pay_invoice':
        invoice = payinstruction_obj['params']['invoice']
        invoice_decoded = bolt11.decode(invoice)
        print(f"this is the invoice to pay: {invoice}")
        acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay)
        await acorn_obj.load_data()
        print(f"balance {acorn_obj.balance}")
        try:
            msg_out, final_fees = await acorn_obj.pay_multi_invoice(invoice)
            await acorn_obj.add_tx_history("D",invoice_decoded.amount_msat//1000, comment=msg_out, fees=final_fees)
            
        except Exception as e:
            # raise Exception(f"Error {e}")
            print(f"Error {e}")
           



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
                asyncio.create_task(nwc_pay_invoice(safebox_found, pay_instruction))
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