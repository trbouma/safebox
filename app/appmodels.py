from typing import Optional

from pydantic import BaseModel
from typing import List
from enum import Enum

from sqlmodel import Field, SQLModel


class Hero(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    secret_name: str
    age: Optional[int] = None

class RegisteredSafebox(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    handle: str
    custom_handle: Optional[str] = None
    npub: str
    nsec: str
    home_relay: str = None
    onboard_code: str = None
    access_key: str 
    balance: int = 0

class PaymentQuote(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    nsec: str
    handle: str
    quote: str
    amount: int
    mint: str
    paid: bool

class lnPayAddress(BaseModel):
    address: str 
    amount: int 
    comment: str

class lnPayInvoice(BaseModel):
    invoice: str 
    comment: str = None


class lnInvoice(BaseModel):
    amount: int 
    comment: str = "Please Pay!"

class ecashRequest(BaseModel):
    amount: int 
    