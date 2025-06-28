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
from datetime import datetime, timezone

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
        tendered_amount = payinstruction_obj['params'].get("tendered_amount", None)
        tendered_currency = payinstruction_obj['params'].get("tendered_currency", "SAT")
        print(f"this is the invoice to pay: {invoice}")
        
        print(f"balance {acorn_obj.balance}")
        try:
            msg_out, final_fees = await acorn_obj.pay_multi_invoice(invoice)
            nfc_msg = f"💳 {comment} "
            await acorn_obj.add_tx_history(     tx_type="D", 
                                                amount=invoice_amount, 
                                                tendered_amount=tendered_amount,
                                                tendered_currency=tendered_currency,
                                                comment=nfc_msg, 
                                                fees=final_fees)
            
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
    elif payinstruction_obj['method'] == 'present_record':
        nauth = payinstruction_obj['params']['nauth']
        label = payinstruction_obj['params']['label']
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
    elif payinstruction_obj['method'] == 'offer_record':
        print("we have an offer record!")
        nauth = payinstruction_obj['params']['nauth']
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