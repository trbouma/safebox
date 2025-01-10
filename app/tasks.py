from time import sleep, time
import asyncio

from safebox.acorn import Acorn
from sqlmodel import Field, Session, SQLModel, create_engine, select

from app.appmodels import RegisteredSafebox, PaymentQuote

HOME_RELAY = 'wss://relay.openbalance.app'
RELAYS = ['wss://relay.openbalance.app']

engine = create_engine("sqlite:///data/database.db")
SQLModel.metadata.create_all(engine)

async def periodic_task():
    while True:
        poll_for_payment()
        await asyncio.sleep(3)  # Simulate work every 10 seconds


def poll_for_payment():

    with Session(engine) as session:
        statement = select(PaymentQuote)
        payment_quotes = session.exec(statement)
        for each in payment_quotes:
            acorn_obj = Acorn(nsec=each.nsec, mints=[each.mint], home_relay=HOME_RELAY, relays=RELAYS)
            print(each)

    print("Poll for payment")
    
    return


