from time import sleep, time
import asyncio

from safebox.acorn import Acorn
from sqlmodel import Field, Session, SQLModel, create_engine, select

from app.appmodels import RegisteredSafebox, PaymentQuote

HOME_RELAY = 'wss://relay.openbalance.app'
RELAYS = ['wss://relay.openbalance.app']
MINTS = ['https://mint.nimo.cash']
LOGGING_LEVEL=20

engine = create_engine("sqlite:///data/database.db")
SQLModel.metadata.create_all(engine)

async def periodic_task():
    while True:
        # poll_for_payment()
        print("this is a period task")
        await asyncio.sleep(10)  # Simulate work every 10 seconds


def poll_for_payment():

    print("this is a poll for payment")
    with Session(engine) as session:
        statement = select(PaymentQuote)
        payment_quotes = session.exec(statement)
        record = payment_quotes.first()
        try:
            # acorn_obj = Acorn(nsec=each.nsec, mints=[each.mint], home_relay=HOME_RELAY, relays=RELAYS)
            # acorn_obj = Acorn(nsec=each.nsec, relays=RELAYS, mints=MINTS, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
            # profile_out = acorn_obj.get_profile()
            print(f"quote: {record}")
            #acorn_obj = Acorn(nsec=record.nsec, relays=RELAYS, mints=MINTS, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
            # print(acorn_obj.seed_phrase)
            
        except Exception as e:
            print(f"error: {e}")
        # del acorn_obj

    print("Poll for paymentx")
    
    return


