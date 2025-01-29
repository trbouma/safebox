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

engine = create_engine(settings.DATABASE)
SQLModel.metadata.create_all(engine)

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
