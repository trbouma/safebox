from time import sleep, time
import asyncio

from safebox.acorn import Acorn
from sqlmodel import Field, Session, SQLModel, create_engine, select

import signal, sys, string, cbor2, base64,os
import aioconsole
import json, requests

from typing import Any, Dict, List, Optional, Union

from monstr.util import util_funcs
from monstr.encrypt import Keys
from monstr.giftwrap import GiftWrap
from monstr.signing.signing import BasicKeySigner
from monstr.event.event import Event
from monstr.client.client import Client, ClientPool

from datetime import datetime, timedelta
from app.appmodels import RegisteredSafebox, PaymentQuote, nfcPayOutRequest, nfcPayOutVault
from safebox.acorn import Acorn
from safebox.models import cliQuote
from app.config import Settings

from app.utils import send_zap_receipt

settings = Settings()

# HOME_RELAY = 'wss://relay.getsafebox.app'
RELAYS = settings.RELAYS
MINTS = settings.MINTS
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

async def invoice_poll_for_payment(acorn_obj: Acorn, quote: str, mint: str, amount: int ):
    
    # acorn_obj = Acorn(nsec=safebox_found.nsec,home_relay=safebox_found.home_relay, mints=MINTS)
    
    # await acorn_obj.load_data()
    #FIX ME DO THE POLLING HERE INSTEAD OF THE OBJECT
    await acorn_obj.poll_for_payment(quote=quote,amount=amount,mint=mint)
    print("We are done!!!!")

    await acorn_obj.add_tx_history(tx_type='C',amount=amount, comment="lightning invoice")
    
    await acorn_obj.load_data()

    # Update the cache amountt   
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.npub==acorn_obj.pubkey_bech32)
        safeboxes = session.exec(statement)
        safebox_update = safeboxes.first()
        safebox_update.balance = acorn_obj.balance 
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

       
async def handle_payment(   acorn_obj: Acorn,
                            cli_quote: cliQuote, 
                            amount: int, 
                            mint:str, 
                            tendered_amount: float|None = None,
                            tendered_currency: str = "SAT",                            
                            nostr: str = None, 
                            comment: str ="" ):

    success = False
    lninvoice = None
    success, lninvoice =  await acorn_obj.poll_for_payment(quote=cli_quote.quote, amount=amount,mint=mint)
    pass
    

    #FIXME Implement zaps here
    if nostr :
        if amount > 1:
            comment= "⚡️ " + json.loads(nostr)['content']
            # print(f"do the zap receipt here with {lninvoice}")
            task = asyncio.create_task(send_zap_receipt(nostr=nostr,lninvoice=lninvoice))
        else:
            comment = "⚡️ spam zap"

    await acorn_obj.load_data()

    # Update the cache amountt   
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.npub==acorn_obj.pubkey_bech32)
        safeboxes = session.exec(statement)
        safebox_update = safeboxes.first()
        safebox_update.balance = acorn_obj.balance
        session.add(safebox_update)
        session.commit()
  
    await acorn_obj.add_tx_history(tx_type='C',amount=amount, tendered_amount=tendered_amount, tendered_currency=tendered_currency, comment=comment)


async def handle_ecash(  acorn_obj: Acorn ):

    
    
    while True:
        # print(f"listen for ecash payment for {acorn_obj.handle}") 
        await acorn_obj.get_ecash_latest() 
        await asyncio.sleep(5)  
        # print("done getting ecash")


async def task_pay_to_nfc_tag(  acorn_obj: Acorn, 
                                vault_url:str, 
                                submit_data: object, 
                                headers: object,
                                nfc_pay_out_request: nfcPayOutRequest,
                                final_amount: int
                                ):
    print("pay to nfc tag")
    response = requests.post(url=vault_url, json=submit_data, headers=headers)
    print(f"safebox: {response.json()}")
    final_comment = f"\U0001F4B3 {nfc_pay_out_request.comment}"
    invoice = response.json()["invoice"]
    payee = response.json()["payee"]
    await acorn_obj.pay_multi_invoice(lninvoice=invoice, comment=nfc_pay_out_request.comment)
    await acorn_obj.add_tx_history(amount = final_amount,comment=final_comment, tendered_amount=nfc_pay_out_request.amount,tx_type='D', tendered_currency=nfc_pay_out_request.currency)
     
async def task_to_send_along_ecash(acorn_obj: Acorn, vault_url: str, submit_data: object, headers: object):
    cashu_token = await acorn_obj.issue_token(submit_data["amount"])
    submit_data["cashu_token"] = cashu_token
    
    print(f"submit data: {submit_data}")


    response = requests.post(url=vault_url, json=submit_data, headers=headers)
    print(f"response: {response.json()}")
    pass

async def task_to_accept_ecash(acorn_obj:Acorn, nfc_pay_out: nfcPayOutVault):
    comment_to_log = f"\U0001F4B3 {nfc_pay_out.comment}"
    print(f"cashu_token: {nfc_pay_out.cashu_token}")
    msg_out = await acorn_obj.accept_token(nfc_pay_out.cashu_token)
    await acorn_obj.add_tx_history(tx_type='C', amount=nfc_pay_out.amount, comment=comment_to_log,tendered_amount=nfc_pay_out.tendered_amount,tendered_currency=nfc_pay_out.tendered_currency,fees=0)

    pass  

    