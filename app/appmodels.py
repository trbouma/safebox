from typing import Optional

from sqlmodel import Field, SQLModel


class Hero(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    secret_name: str
    age: Optional[int] = None

class RegisteredSafebox(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    handle: str
    npub: str
    nsec: str
    home_relay: str = None
    onboard_code: str = None
    access_key: str 

class PaymentQuote(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    nsec: str
    handle: str
    quote: str
    amount: int
    mint: str
    paid: bool
