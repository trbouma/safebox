import pathlib

from pydantic import AnyHttpUrl
from pydantic_settings import BaseSettings

from typing import List, Optional, Union

# Project Directories
ROOT = pathlib.Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    HOME_RELAY: str = 'wss://relay.openbalance.app'
    SERVICE_NAME: str = 'Safebox'
    SERVICE_TAG_LINE: str = 'Your money. Your data'
    SERVICE_SECRET_KEY: str = "foobar"
    TZ: str = "America/New_York"
    ALGORITHM: str = "HS256"
    DATABASE: str = "sqlite:///data/database.db"  
    RELAYS: List = ['wss://relay.openbalance.app']
    MINTS: List = ['https://mint.nimo.cash']
    TOKEN_EXPIRES_WEEKS: int = 4
    TOKEN_EXPIRES_HOURS: int = 8
    SESSION_AGE_DAYS: int = 30
    SUPPORTED_CURRENCIES: List =['CAD','USD','AUD','EUR','GBP','CNY','JPY']
    BRANDING: str = "Get SafeBox"
    BRANDING_MESSAGE: str = "Control your personal funds and data."
    BRANDING_RETRY: str = "Whoops! Let's try that again!"
    INVITE_CODES: List = ["alpha","sec2025", "rektuser"]

    class Config:
        env_file = '.env'
        env_file_encoding ='utf-8'
        case_sensitive = True

settings = Settings()

if __name__ == "__main__":
    
    print("ROOT:", ROOT)
    print(settings)