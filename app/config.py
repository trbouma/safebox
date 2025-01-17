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
    SECRET_KEY: str = "foobar"
    ALGORITHM: str = "HS256"
    DATABASE: str = "sqlite:///data/database.db"  
    RELAYS: List = ['wss://relay.openbalance.app']
    TOKEN_EXPIRES_WEEKS: int = 1
    TOKEN_EXPIRES_HOURS: int = 8

    class Config:
        env_file = '.env'
        env_file_encoding ='utf-8'
        case_sensitive = True

settings = Settings()

if __name__ == "__main__":
    
    print("ROOT:", ROOT)
    print(settings)