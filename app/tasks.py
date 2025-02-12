from time import sleep, time
import asyncio

from safebox.acorn import Acorn
from sqlmodel import Field, Session, SQLModel, create_engine, select

import signal, sys, string, cbor2, base64,os
import aioconsole

from typing import Any, Dict, List, Optional, Union

from monstr.util import util_funcs
from monstr.encrypt import Keys
from monstr.giftwrap import GiftWrap
from monstr.signing.signing import BasicKeySigner
from monstr.event.event import Event
from monstr.client.client import Client, ClientPool

from datetime import datetime, timedelta
from app.appmodels import RegisteredSafebox, PaymentQuote
from safebox.acorn import Acorn
from app.config import Settings
settings = Settings()

# HOME_RELAY = 'wss://relay.getsafebox.app'
RELAYS = ['wss://relay.getsafebox.app']
MINTS = ['https://mint.nimo.cash']
LOGGING_LEVEL=20

engine = create_engine(settings.DATABASE)
# SQLModel.metadata.create_all(engine, checkfirst=True)

async def periodic_task():
    while True:
        # poll_for_payment()
        print("this is a period task")
        await asyncio.sleep(10)  # Simulate work every 10 seconds


async def service_poll_for_payment(acorn_obj: Acorn, quote: str, mint: str, amount: int ):
    #FIXME - this function is no longer used.
    start_time = time()  # Record the start time
    end_time = start_time + 60  # Set the loop to run for 60 seconds
    success = False
    mint = mint.replace("https://","")
    while time() < end_time:           
        print("the lion is asleep")
        # success = await acorn_obj.check_quote(quote=quote, amount=amount,mint=mint)
        if success:
            print("quote is paid")
            break
        sleep(3)  # Sleep for 3 seconds
        
    print("service polling done!")

    
    
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.access_key==acorn_obj.access_key)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.first()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            raise ValueError("Could not find safebox!")
    
        print(f"safebox! {safebox_found.handle} {safebox_found.balance} amount: {amount}")

        # safebox_found.balance = safebox_found.balance + amount
        safebox_found.balance = acorn_obj.balance
        session.add(safebox_found)
        session.commit()
    return

async def invoice_poll_for_payment(safebox_found: RegisteredSafebox, quote: str, mint: str, amount: int ):
    
    acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    
    await acorn_obj.load_data()
    #FIX ME DO THE POLLING HERE INSTEAD OF THE OBJECT
    await acorn_obj.poll_for_payment(quote=quote,amount=amount,mint=mint)
    print("We are done!!!!")
    
    
    
   

    # Update the cache amountt   
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.id ==safebox_found.id)
        safeboxes = session.exec(statement)
        safebox_update = safeboxes.first()
        safebox_update.balance = safebox_update.balance + amount
        session.add(safebox_update)
        session.commit()
    return



async def callback_done(task):
    print("callback function")


async def listen_nip17(self, url):


        AS_K = self.privkey_bech32

        tail = util_funcs.str_tails
        since = datetime.now().timestamp()
        since_ticks = util_funcs.date_as_ticks(datetime.now() - timedelta(minutes=1))
        # since_ticks = util_funcs.date_as_ticks(datetime.now())

        # nip59 gift wrapper
        my_k = Keys(AS_K)
        my_gift = GiftWrap(BasicKeySigner(my_k))


  

        # print(f'running as npub{tail(my_k.public_key_bech32()[4:])}, messaging npub{tail(send_k.public_key_bech32()[4:])}')
        print(f"listening for nip17 as {self.pubkey_bech32} using {url}. \nType 'exit' to stop")

        # q before printing events
        print_q = asyncio.Queue()

        # as we're using a pool we'll see the same events multiple times
        # DeduplicateAcceptor is used to ignore them
        # my_dd = DeduplicateAcceptor()


        # used for both eose and adhoc
        def my_handler(the_client: Client, sub_id: str, evt: Event):
            print_q.put_nowait(evt)

        def on_connect(the_client: Client):
            # oxchat seems to use a large date jitter... think 8 days is enough
            since = util_funcs.date_as_ticks(datetime.now() - timedelta(hours=24*8))

            the_client.subscribe(handlers=my_handler,
                                filters=[
                                    # can only get events for us from relays, we need to store are own posts
                                    {
                                        'kinds': [Event.KIND_GIFT_WRAP],
                                        '#p': [my_k.public_key_hex()]
                                    }
                                ]
                                )


        def on_auth(the_client: Client, challenge):
            print('auth requested')


        # create the client and start it running
        c = ClientPool(url,
                    on_connect=on_connect,
                    on_auth=on_auth,
                    on_eose=my_handler)
        asyncio.create_task(c.run())

        def sigint_handler(signal, frame):
            print('stopping listener...')
            c.end()
            sys.exit(0)

        signal.signal(signal.SIGINT, sigint_handler)

        async def output(since):
            # print("output")
            home_directory = os.path.expanduser('~')
            log_directory = '.safebox'
            log_file = 'log.txt'
            log_directory = os.path.join(home_directory, log_directory)
            file_path = os.path.join(home_directory, log_directory, log_file)

            while True:
                events: List[Event] = await print_q.get()
                # because we use from both eose and adhoc, when adhoc it'll just be single event
                # make [] to simplify code
                if isinstance(events, Event):
                    events = [events]

                events = [await my_gift.unwrap(evt) for evt in events]
                # can't be sorted till unwrapped
                events.sort(reverse=True)

                for c_event in events:
                    if c_event.created_at.timestamp() > since:
                        msg_out =''
                        print(c_event.id[:4],c_event.pub_key, c_event.created_at, c_event.content)
                        content = c_event.content                           

                        array_token = content.splitlines()                        
                            
                        for each in array_token:
                            if each.startswith("cashuA"):                                   
                                    
                                # print(f"found token! {each}")
                                msg_out = await self.nip17_accept(each)
                                # print(self.trusted_mints)
                                # await self._async_set_wallet_info(label="trusted_mints", label_info=json.dumps(self.trusted_mints))
                                # print(msg_out)
                                        
                                    
                            elif each.startswith("creqA"):
                                msg_out = "creqA"
                            
                        TO_K = c_event.pub_key
                        send_k = Keys(pub_k=TO_K)
                        # print(send_k, c_event.content)
                        msg_n = c_event.content
                        send_evt = Event(content=msg_n,
                            tags=[
                                ['p', send_k.public_key_hex()]
                            ])

                        wrapped_evt, trans_k = await my_gift.wrap(send_evt,
                                                    to_pub_k=send_k.public_key_hex())
                        c.publish(wrapped_evt)

                        with open(file_path, "a+") as f:   
                            pass    
                            f.write(f"{c_event.created_at} {c_event.pub_key} {content} {msg_out}\n")
                            f.flush()  # Ensure the log is written to disk


        asyncio.create_task(output(since_ticks))
        msg_n = ''
        while msg_n != 'exit':
            msg_n = await aioconsole.ainput('')
                  
            
            await asyncio.sleep(0.2)
            

           

        print('stopping...')
        c.end()

       

