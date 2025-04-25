import pathlib

from pydantic import AnyHttpUrl, BaseModel
from pydantic_settings import BaseSettings

from typing import List, Optional, Union

# Project Directories
ROOT = pathlib.Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    HOME_RELAY: str = 'ws://localhost:8735'
    HOME_MINT: str= 'https://mint.getsafebox.app'      
    SERVICE_NAME: str = 'Safebox'
    SERVICE_TAG_LINE: str = 'Your money. Your data'
    SERVICE_SECRET_KEY: str|None = 'nsec1s7kq8yqregp0pa0v4vmcan4s8m8dn6az6k6u8pe9gz4thzst595sl7grfd'
    SERVICE_RELAY_DB_FILE: str = "data/relay.db"
    TZ: str = "America/New_York"
    ALGORITHM: str = "HS256"
    DATABASE: str = "sqlite:///data/database.db"  
    RELAYS: List = ['wss://relay.getsafebox.app']
    MINTS: List = ['https://mint.getsafebox.app']
    IP_INFO_TOKEN: str = "notset"
    LOCAL_RELAY_PORT: int = 8735
    TOKEN_EXPIRES_WEEKS: int = 4
    TOKEN_EXPIRES_HOURS: int = 8
    SESSION_AGE_DAYS: int = 30
    SUPPORTED_CURRENCIES: List =['CAD','USD','EUR','GBP','JPY','INR','CHF','AUD']
    BRANDING: str = "Get SafeBox"
    BRANDING_MESSAGE: str = "Control your personal funds and data."
    BRANDING_RETRY: str = "Whoops! Let's try that again!"
    INVITE_CODES: List = ["alpha", "rektuser"]
    AUTH_RELAYS: List = ['wss://relay.getsafebox.app']
    TRANSMITTAL_RELAYS: List = ['wss://relay.getsafebox.app']
    REFRESH_CURRENCY_INTERVAL: int = 3600
    TRANSMITTAL_KIND: int = 21060
    AUTH_KIND: int = 21061

    class Config:
        env_file = '.env'
        env_file_encoding ='utf-8'
        case_sensitive = True

class modeEventKind(BaseModel):
    mode: str
    kind: int

class mapEventKind(BaseModel):
    mapping: List [modeEventKind]


settings = Settings()

if __name__ == "__main__":
    
    print("ROOT:", ROOT)
    print(settings)