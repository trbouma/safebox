from time import sleep, time
import asyncio

from safebox.acorn import Acorn
from sqlmodel import Field, Session, SQLModel, select

import signal, sys, string, cbor2, base64,os
import aioconsole
import json, requests
import httpx

from typing import Any, Dict, List, Optional, Union, Callable, Awaitable
from fastapi import WebSocket

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
from app.db import engine
from app.rates import get_currency_rate

import time
import logging

from app.utils import send_zap_receipt

settings = Settings()

# HOME_RELAY = 'wss://relay.getsafebox.app'
RELAYS = settings.RELAYS
MINTS = settings.MINTS
LOGGING_LEVEL=20

# SQLModel.metadata.create_all(engine, checkfirst=True)
logger = logging.getLogger(__name__)

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
    print(f"the mint: {mint}")
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

async def safe_handle_payment(*args, **kwargs):
    try:
        await handle_payment(*args, **kwargs)
    except Exception as e:
        # Log or handle the exception properly
        print(f"Error in handle_payment: {e}")

async def send_payment_message( nrecipient: str, acorn_obj: Acorn, message: str):
    print(f"send payment message {message}")
    await acorn_obj.secure_transmittal(nrecipient=nrecipient, message=message, dm_relays=settings.RELAYS, kind=1059)
            
    pass        
       
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
    try:

        print(f"handle payment: {mint}")
        success, lninvoice =  await acorn_obj.poll_for_payment(quote=cli_quote.quote, amount=amount,mint=mint)
        pass
    except TimeoutError as exc:
        logger.info("handle_payment poll timed out quote=%s mint=%s amount=%s", cli_quote.quote, mint, amount)
        success = False
    except Exception as e:
        logger.exception("handle_payment unexpected exception quote=%s mint=%s amount=%s", cli_quote.quote, mint, amount)

    

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
    if success: 
        with Session(engine) as session:
            statement = select(RegisteredSafebox).where(RegisteredSafebox.npub==acorn_obj.pubkey_bech32)
            safeboxes = session.exec(statement)
            safebox_update = safeboxes.first()
            safebox_update.balance = acorn_obj.balance
            session.add(safebox_update)
            session.commit()
    
        await acorn_obj.add_tx_history(tx_type='C',amount=amount, tendered_amount=tendered_amount, tendered_currency=tendered_currency, comment=comment)

    return success

async def handle_nwc_payment(   acorn_obj: Acorn,
                            cli_quote: cliQuote, 
                            amount: int, 
                            mint:str, 
                            tendered_amount: float|None = None,
                            tendered_currency: str = "SAT", 
                            comment: str ="",
                            callback: Callable[..., None]=None,
                            payment_hash: str = None,                    
                            evt: Event = None  ):
    success = False
    lninvoice = None
    try:

        print(f"handle nwc payment: {mint}")
        success, lninvoice =  await acorn_obj.poll_for_payment(quote=cli_quote.quote, amount=amount,mint=mint)
        pass
    except Exception as e:
        import traceback
        print(f"[handle_payment] Exception: {e}")
        traceback.print_exc()

  

    await acorn_obj.load_data()

    # Update the cache amountt   
    if success: 
        with Session(engine) as session:
            statement = select(RegisteredSafebox).where(RegisteredSafebox.npub==acorn_obj.pubkey_bech32)
            safeboxes = session.exec(statement)
            safebox_update = safeboxes.first()
            safebox_update.balance = acorn_obj.balance
            session.add(safebox_update)
            session.commit()
    
        await acorn_obj.add_tx_history(tx_type='C',amount=amount, tendered_amount=tendered_amount, tendered_currency=tendered_currency, comment=comment)
        if callback:
            pass
            
            callback(nsec=acorn_obj.privkey_bech32, payment_hash="test", evt=evt)

    return success

async def handle_ecash(
    acorn_obj: Acorn,
    websocket: WebSocket = None,
    relays: List[str] = None,
    nonce: str = None,
    notify_callback: Callable[[Dict[str, Any]], Awaitable[None]] | None = None,
):
    print(f"handle ecash listen for {acorn_obj.handle}")

    def _ecash_detail(each: tuple) -> str:
        tendered_amount = each[1] if len(each) > 1 else 0
        tendered_currency = each[2] if len(each) > 2 else "SAT"
        status_note = each[3] if len(each) > 3 else "Payment update"
        credited_sats = each[5] if len(each) > 5 else 0
        return f"Tendered Amount {tendered_amount} {tendered_currency} | Credited {credited_sats} sats | {status_note}"

    last_detail = "Payment complete!"

    start_time = time.time()
    # duration = 60  # 1 minutes in seconds
    ecash_listen_timeout = settings.ECASH_LISTEN_TIMEOUT
    #FIXME Need to add in a nonce so it is listening for the right ecash payment
    while time.time() - start_time < ecash_listen_timeout:
        print(f"listen for ecash payment for {acorn_obj.handle} using {relays}") 
        ecash_out = await acorn_obj.get_ecash_latest(relays=relays, nonce=nonce) 

        # Update local cache balance
        with Session(engine) as session:
            statement = select(RegisteredSafebox).where(RegisteredSafebox.npub==acorn_obj.pubkey_bech32)
            safeboxes = session.exec(statement)
            safebox_update = safeboxes.first()
            safebox_update.balance = acorn_obj.balance
            session.add(safebox_update)
            session.commit()


        if ecash_out != []:
            print(f"nonce: {nonce} ecash out: {ecash_out}")
            
            if websocket:
                for each in ecash_out: 
                    print(f"each for websocket: {each}") 
                    if each[0] in ["OK", "ADVISORY"]:             
                        last_detail = _ecash_detail(each)
                        await websocket.send_json({"status": each[0], "action": "nfc_token", "detail": last_detail})
                        await asyncio.sleep(5)
                        await websocket.send_json({"status": "OK", "action": "nfc_token", "detail": last_detail})                       
                    else:
                        pass
                        # await websocket.send_json({"status": each[0], "action": "nfc_token", "detail": f"{each[3]}"})
                break
            if notify_callback:
                for each in ecash_out:
                    if each[0] in ["OK", "ADVISORY"]:
                        last_detail = _ecash_detail(each)
                        payload = {
                            "status": each[0],
                            "action": "nfc_token",
                            "detail": last_detail,
                            "balance": acorn_obj.balance,
                        }
                        await notify_callback(payload)
                await notify_callback({
                    "status": "OK",
                    "action": "nfc_token",
                    "detail": last_detail,
                    "balance": acorn_obj.balance,
                })
            break

         
    
    print(f"done getting ecash. The balance is: {acorn_obj.balance}")


    # if websocket:
    #     await websocket.send_json({"status": "OK", "action": "nfc_token", "detail": f"Ready!"})


async def task_pay_to_nfc_tag(  acorn_obj: Acorn, 
                                vault_url:str, 
                                submit_data: object, 
                                headers: object,
                                nfc_pay_out_request: nfcPayOutRequest,
                                final_amount: int
                                ):
    print("pay to nfc tag")
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(url=vault_url, json=submit_data, headers=headers)
        response.raise_for_status()
        response_json = response.json()
    print(f"safebox: {response_json}")
    final_comment = f"\U0001F4B3 {nfc_pay_out_request.comment}"
    invoice = response_json["invoice"]
    payee = response_json["payee"]
    await acorn_obj.pay_multi_invoice(lninvoice=invoice, comment=nfc_pay_out_request.comment)
    await acorn_obj.add_tx_history(amount = final_amount,comment=final_comment, tendered_amount=nfc_pay_out_request.amount,tx_type='D', tendered_currency=nfc_pay_out_request.currency)
     
async def task_to_send_along_ecash(acorn_obj: Acorn, vault_url: str, submit_data: object, headers: object):
    amount = int(submit_data["amount"])
    comment = str(submit_data.get("comment", "ecash transfer"))
    cashu_token = await acorn_obj.issue_token(amount=amount, comment=comment)
    submit_data["cashu_token"] = cashu_token

    logger.info("task_to_send_along_ecash start amount=%s vault=%s", amount, vault_url)

    delivery_confirmed = False
    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            response = await client.post(url=vault_url, json=submit_data, headers=headers)
            response.raise_for_status()
            response_json = response.json()
        logger.info("task_to_send_along_ecash delivered status=%s", response_json.get("status"))
        delivery_confirmed = True
    except Exception as exc:
        logger.warning("task_to_send_along_ecash delivery failed: %s", exc)

    if not delivery_confirmed:
        # Best-effort rollback: if delivery failed before redemption, accept our own token back.
        try:
            rollback_msg, rollback_amount = await acorn_obj.accept_token(
                cashu_token=cashu_token,
                comment=f"rollback undelivered nfc ecash: {comment}",
            )
            logger.warning(
                "task_to_send_along_ecash rollback_ok amount=%s msg=%s",
                rollback_amount,
                rollback_msg,
            )
        except Exception as rollback_exc:
            logger.error("task_to_send_along_ecash rollback_failed: %s", rollback_exc)
            try:
                recovery_label = f"ecash-recovery-{int(time.time())}"
                await acorn_obj.put_record(
                    record_name=recovery_label,
                    record_value=json.dumps(
                        {
                            "type": "ecash_delivery_uncertain",
                            "amount": amount,
                            "comment": comment,
                            "vault_url": vault_url,
                            "cashu_token": cashu_token,
                            "created_at": int(time.time()),
                        }
                    ),
                    record_kind=37375,
                )
                logger.error("task_to_send_along_ecash recovery_record_saved label=%s", recovery_label)
            except Exception as record_exc:
                logger.critical("task_to_send_along_ecash recovery_record_failed: %s", record_exc)

    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.npub == acorn_obj.pubkey_bech32)
        safeboxes = session.exec(statement)
        safebox_update = safeboxes.first()
        safebox_update.balance = acorn_obj.get_balance()
        session.add(safebox_update)
        session.commit()

async def task_to_accept_ecash(acorn_obj:Acorn, nfc_pay_out: nfcPayOutVault):
    comment_to_log = f"\U0001F4B3 {nfc_pay_out.comment}"
    print(f"cashu_token: {nfc_pay_out.cashu_token}")
    msg_out = await acorn_obj.accept_token(cashu_token=nfc_pay_out.cashu_token,comment=nfc_pay_out.comment)

    # await acorn_obj.add_tx_history(tx_type='C', amount=nfc_pay_out.amount, comment=comment_to_log,tendered_amount=nfc_pay_out.tendered_amount,tendered_currency=nfc_pay_out.tendered_currency,fees=0)

    pass  

async def task_pay_multi(
    acorn_obj: Acorn,
    amount: int,
    lnaddress: str,
    comment: str,
    tendered_amount: float,
    tendered_currency: str,
    websocket: WebSocket | None = None,
    notify_callback: Callable[[Dict[str, Any]], Awaitable[None]] | None = None,
):
    fiat_currency = await get_currency_rate(acorn_obj.local_currency)
    currency_code  = fiat_currency.currency_code
    currency_rate = fiat_currency.currency_rate
    currency_symbol = fiat_currency.currency_symbol
    fiat_balance = f"{currency_symbol}{'{:.2f}'.format(currency_rate * acorn_obj.balance / 1e8)} {currency_code}"   

    if websocket:
            #FIXME - may not need this refernce
            try: 

            
                await websocket.send_json({"balance":acorn_obj.balance,"fiat_balance":fiat_balance, "message": "Payment in progress", "status": "PENDING"})
            except:
                pass
    if notify_callback:
        await notify_callback({
            "status": "PENDING",
            "action": "payment",
            "detail": "Payment in progress",
            "balance": acorn_obj.balance,
            "fiat_balance": fiat_balance,
        })

    status = "SENT"
    msg_out = "Payment sent."
    try:
        msg_out,fee = await acorn_obj.pay_multi(amount=amount,lnaddress=lnaddress,comment=comment, tendered_amount=amount,tendered_currency=tendered_currency)

    except Exception as e:
        msg_out =f"{e}"
        status = "ERROR"
        print(msg_out, status)
    finally:
        fiat_balance = f"{currency_symbol}{'{:.2f}'.format(currency_rate * acorn_obj.balance / 1e8)} {currency_code}"
        if websocket:
            #FIXME - may not need this refernce
            try:
                await websocket.send_json({"balance":acorn_obj.balance,"fiat_balance":fiat_balance, "message": msg_out, "status": status})
            except:
                pass
        if notify_callback:
            await notify_callback({
                "status": status,
                "action": "payment",
                "detail": msg_out,
                "balance": acorn_obj.balance,
                "fiat_balance": fiat_balance,
            })
   
async def task_pay_multi_invoice(
    acorn_obj: Acorn,
    lninvoice: str,
    comment: str,
    websocket: WebSocket | None = None,
    notify_callback: Callable[[Dict[str, Any]], Awaitable[None]] | None = None,
):
    fiat_currency = await get_currency_rate(acorn_obj.local_currency)
    currency_code  = fiat_currency.currency_code
    currency_rate = fiat_currency.currency_rate
    currency_symbol = fiat_currency.currency_symbol
    fiat_balance = f"{currency_symbol}{'{:.2f}'.format(currency_rate * acorn_obj.balance / 1e8)} {currency_code}"   
    
    if websocket:
            #FIXME - may not need this refernce
            try:
                await websocket.send_json({"balance":acorn_obj.balance,"fiat_balance":fiat_balance, "message": "Payment in progress", "status": "PENDING"})
            except:
                pass
    if notify_callback:
        await notify_callback({
            "status": "PENDING",
            "action": "payment",
            "detail": "Payment in progress",
            "balance": acorn_obj.balance,
            "fiat_balance": fiat_balance,
        })

    status = "SENT"
    msg_out = "Payment sent."
    try:
        # msg_out,fee = await acorn_obj.pay_multi(amount=amount,lnaddress=lnaddress,comment=comment, tendered_amount=amount,tendered_currency=tendered_currency)

        msg_out, final_fees,_,_,_ = await  acorn_obj.pay_multi_invoice(lninvoice=lninvoice, comment=comment)

    except Exception as e:
        msg_out =f"{e}"
        status = "ERROR"
        print(msg_out, status)
    finally:
        fiat_balance = f"{currency_symbol}{'{:.2f}'.format(currency_rate * acorn_obj.balance / 1e8)} {currency_code}"
        if websocket:
            #FIXME - may not need this refernce
            try:
                await websocket.send_json({"balance":acorn_obj.balance,"fiat_balance":fiat_balance, "message": msg_out, "status": status})
            except:
                pass
        if notify_callback:
            await notify_callback({
                "status": status,
                "action": "payment",
                "detail": msg_out,
                "balance": acorn_obj.balance,
                "fiat_balance": fiat_balance,
            })
    

    
