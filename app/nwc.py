import asyncio
import logging
from monstr.relay.relay import Relay
from monstr.event.persist_sqlite import RelaySQLiteEventStore
from monstr.client.client import Client
from typing import List
from monstr.encrypt import NIP4Encrypt

from safebox.acorn import Acorn

import os
from app.config import Settings

settings = Settings()

RELAYS = settings.RELAYS

async def listen_for_nwc(acorn_obj: Acorn, kind: int = 23194,since_now:int=None, relays: List=None):
   
    def test():
        print('test')    
    
    test()

    records_out = await acorn_obj.get_user_records(record_kind=kind, since=since_now, relays=relays)
    
    
    return records_out

async def listen_nwc():
    print("this will be the nwc service")
    def test():
        print("test")
    
    test()
    try:
        acorn_obj = Acorn(nsec=settings.NWC_NSEC, home_relay=settings.NWC_RELAYS[0], relays=settings.NWC_RELAYS,mints=settings.MINTS )
        await acorn_obj.load_data()
        acorn_obj.get_profile()
    except Exception as e:
        print(f"error {e}, creating instance...")
        await acorn_obj.create_instance(keepkey=True)
    print("nwc listening...")

    # print(acorn_obj.get_profile())

if __name__ == '__main__':
    logging.getLogger().setLevel(logging.DEBUG)
    asyncio.run(listen_nwc())