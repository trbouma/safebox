import asyncio
import logging
from monstr.relay.relay import Relay
from monstr.event.persist_sqlite import RelaySQLiteEventStore
from monstr.client.client import Client

import os
from app.config import Settings

settings = Settings()

RELAYS = settings.RELAYS

async def listen_nwc():
    print("this is will be the nwc service")



if __name__ == '__main__':
    logging.getLogger().setLevel(logging.DEBUG)
    asyncio.run(listen_nwc())