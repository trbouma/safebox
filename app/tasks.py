from time import sleep, time
import asyncio

from safebox.acorn import Acorn
from sqlmodel import Field, Session, SQLModel, create_engine, select

from app.appmodels import RegisteredSafebox, PaymentQuote
from safebox.acorn import Acorn
from app.config import Settings
settings = Settings()

# HOME_RELAY = 'wss://relay.openbalance.app'
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


async def service_poll_for_payment(handle:str, quote: str, mint: str, amount: int ):


    
    with Session(engine) as session:
        statement = select(RegisteredSafebox).where(RegisteredSafebox.handle ==handle)
        safeboxes = session.exec(statement)
        safebox_found = safeboxes.one()
        if safebox_found:
            out_name = safebox_found.handle
        else:
            raise ValueError("Could not find safebox!")
    
        print(f"safebox! {safebox_found.handle} {safebox_found.balance} amount: {amount}")

        safebox_found.balance = safebox_found.balance + amount
        session.add(safebox_found)
        session.commit()
    
   
    

    return

async def callback_done(task):
    print("callback function")
