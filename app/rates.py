from pydantic import BaseModel
from datetime import datetime, timedelta
import jwt, re, bech32
from time import sleep
import asyncio
import csv
from zoneinfo import ZoneInfo
import logging
import time
from typing import Any, Dict

from bech32 import bech32_decode, convertbits
import struct, json
import httpx
from sqlalchemy import text

from fastapi import FastAPI, HTTPException
from app.appmodels import RegisteredSafebox, CurrencyRate
from sqlmodel import Field, Session, SQLModel, select
from app.config import Settings
from app.db import engine

settings = Settings()
logger = logging.getLogger(__name__)

CURRENCY_TICKER_URL = "https://blockchain.info/ticker"
HTTP_TIMEOUT_SECONDS = 10.0
MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = 0.5
CIRCUIT_FAILURE_THRESHOLD = 3
CIRCUIT_COOLDOWN_SECONDS = 60
_circuit_failures = 0
_circuit_open_until = 0.0
_circuit_lock = asyncio.Lock()
# SQLModel.metadata.create_all(engine, checkfirst=True)

async def _record_success() -> None:
    global _circuit_failures, _circuit_open_until
    async with _circuit_lock:
        _circuit_failures = 0
        _circuit_open_until = 0.0

async def _record_failure() -> None:
    global _circuit_failures, _circuit_open_until
    async with _circuit_lock:
        _circuit_failures += 1
        if _circuit_failures >= CIRCUIT_FAILURE_THRESHOLD:
            _circuit_open_until = time.time() + CIRCUIT_COOLDOWN_SECONDS

async def _ensure_circuit_closed() -> None:
    async with _circuit_lock:
        if _circuit_open_until > time.time():
            remaining = int(_circuit_open_until - time.time())
            raise RuntimeError(f"currency rate circuit is open for {remaining}s")

async def _fetch_currency_table() -> Dict[str, Any]:
    await _ensure_circuit_closed()
    timeout = httpx.Timeout(HTTP_TIMEOUT_SECONDS)
    last_error: Exception | None = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(CURRENCY_TICKER_URL)
                response.raise_for_status()
                payload = response.json()
                if not isinstance(payload, dict):
                    raise ValueError("currency ticker response must be a JSON object")
                await _record_success()
                return payload
        except (httpx.RequestError, httpx.HTTPStatusError, ValueError, json.JSONDecodeError) as exc:
            last_error = exc
            logger.warning(
                "Currency ticker fetch attempt failed (attempt=%s/%s): %s",
                attempt,
                MAX_RETRIES,
                exc,
            )
            if attempt < MAX_RETRIES:
                await asyncio.sleep(RETRY_BACKOFF_SECONDS * attempt)

    await _record_failure()
    raise RuntimeError("failed to fetch currency ticker after retries") from last_error

async def refresh_currency_rates():
    logger.info("Refreshing currency rates")
    try:
        currency_table = await _fetch_currency_table()
    except RuntimeError as exc:
        logger.error("Currency rate refresh skipped: %s", exc)
        return
    
    with Session(engine) as session:
        statement = select(CurrencyRate).where(CurrencyRate.currency_code.in_(settings.SUPPORTED_CURRENCIES))
        results = session.exec(statement).all()
        for record in results:
            try:
                rate_obj = currency_table[record.currency_code]
                record.currency_rate = rate_obj['15m']
                record.refresh_time = datetime.now()
            except KeyError:
                logger.warning("No currency ticker rate for %s", record.currency_code)
            except TypeError as exc:
                logger.warning("Malformed currency ticker entry for %s: %s", record.currency_code, exc)
        session.commit()

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
    return await _fetch_currency_table()
   



async def init_currency_rates():
   
    print("init currency rates")
    await load_currency_rates_from_csv()

# Routine to load CSV into the CurrencyRate table
async def load_currency_rates_from_csv():
    try:
        with Session(engine) as session:
            csv_path = settings.CURRENCY_CSV
            logger.info("Initializing currency rates from CSV path=%s", csv_path)
            inserted = 0
            with open(csv_path, newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    currency_code = row['currency_code']                    
                    data = {
                        "currency_code": currency_code,
                        "currency_rate": float(row['currency_rate']) if row['currency_rate'] else None,
                        "currency_symbol": row['currency_symbol'],
                        "currency_description": row['currency_description'],
                        "refresh_time": None,
                        "fractional_unit": row['fractional_unit'],
                        "number_to_base": int(row['number_to_base']) if row['number_to_base'] else None,
                    }
                    # Safe for concurrent startup workers on SQLite/Postgres.
                    result = session.exec(
                        text(
                            """
                            INSERT INTO currencyrate (
                                currency_code,
                                currency_rate,
                                currency_symbol,
                                currency_description,
                                refresh_time,
                                fractional_unit,
                                number_to_base
                            ) VALUES (
                                :currency_code,
                                :currency_rate,
                                :currency_symbol,
                                :currency_description,
                                :refresh_time,
                                :fractional_unit,
                                :number_to_base
                            )
                            ON CONFLICT (currency_code) DO NOTHING
                            """
                        ),
                        params=data,
                    )
                    if result.rowcount and result.rowcount > 0:
                        inserted += result.rowcount
                session.commit()
            logger.info("Currency CSV initialization completed inserted=%s", inserted)
    except (OSError, ValueError, KeyError) as exc:
        logger.error("Failed to initialize currency rates from CSV: %s", exc)
        


                


if __name__ == "__main__":
    refresh_currency_rates()
