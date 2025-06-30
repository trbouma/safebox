from pydantic import BaseModel
from datetime import datetime, timedelta
import jwt, re, requests, bech32
from time import sleep
import asyncio
import csv
from zoneinfo import ZoneInfo

from bech32 import bech32_decode, convertbits
import struct, json

from fastapi import FastAPI, HTTPException
from app.appmodels import RegisteredSafebox, CurrencyRate
from sqlmodel import Field, Session, SQLModel, create_engine, select
from app.config import Settings

settings = Settings()
engine = create_engine(settings.DATABASE)
# SQLModel.metadata.create_all(engine, checkfirst=True)

async def refresh_currency_rates():
    refresh_time = datetime.now()
    print("refresh currency rates:")
    currency_table = json.loads(requests.get('https://blockchain.info/ticker').text)
    
    with Session(engine) as session:
        statement = select(CurrencyRate).where(CurrencyRate.currency_code.in_(settings.SUPPORTED_CURRENCIES))
        results = session.exec(statement).all()
        for record in results:
            try:
                print(f"{record.currency_code} {currency_table[record.currency_code]['15m']}")
                record.currency_rate = currency_table[record.currency_code]['15m']
                record.refresh_time = datetime.now()
                session.commit()
            except:
                print(f"Cannot refresh: {record}")

async def get_currency_rates():
    with Session(engine) as session:
        statement = select(CurrencyRate).where(CurrencyRate.currency_code.in_(settings.SUPPORTED_CURRENCIES))
        results = session.exec(statement).all()

    return results

async def get_currency_rate(currency_code: str)  :
    with Session(engine) as session:
        statement = select(CurrencyRate).where(CurrencyRate.currency_code==currency_code)
        result = session.exec(statement).one()

    return result

async def get_online_currency_rates():
    return json.loads(requests.get('https://blockchain.info/ticker').text)
   



async def init_currency_rates():
   
    print("init currency rates")
    await load_currency_rates_from_csv()

# Routine to load CSV into the CurrencyRate table
async def load_currency_rates_from_csv():
    # Setup database engine and session

    try:
        with Session(engine) as session:
            csv_path = "setup/currency.csv"
            with open(csv_path, newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                
                for row in reader:
                    currency_code = row['currency_code']                    
                    # session.exec("BEGIN EXCLUSIVE;")
                    statement = select(CurrencyRate).where(CurrencyRate.currency_code==currency_code)
                    result = session.exec(statement).first()

                    if result:
                        print("already record!")
                        break

                    else:
                        print("let add record!")


                        # Convert and prepare data
                        data = {
                            "currency_code": currency_code,
                            "currency_rate": float(row['currency_rate']) if row['currency_rate'] else None,
                            "currency_symbol": row['currency_symbol'],
                            "currency_description": row['currency_description'],
                            "refresh_time": None,
                            "fractional_unit": row['fractional_unit'],
                            "number_to_base": int(row['number_to_base']) if row['number_to_base'] else None,
                        }
            
                        # print(data)
                        currency = CurrencyRate(**data)
                        session.add(currency)
                        session.commit()
    except Exception as e:
        # print(f"Exception as {e}")
        pass
        


                


if __name__ == "__main__":
    refresh_currency_rates()