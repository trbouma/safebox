from typing import Optional

from pydantic import BaseModel
from typing import List
from enum import Enum
from datetime import datetime

from sqlmodel import Field, SQLModel




class RegisteredSafebox(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    handle: str
    custom_handle: Optional[str] = Field(default=None,unique=True, nullable=True)
    npub: str
    nsec: str
    home_relay: str 
    onboard_code: str 
    access_key: str 
    balance: int = 0
    owner: Optional[str] = None
    session_nonce: Optional[str] = None

class PaymentQuote(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    nsec: str
    handle: str
    quote: str
    amount: int
    mint: str
    paid: bool

class CurrencyRate(SQLModel, table=True):
    currency_code: str = Field(primary_key=True)  # Primary Key & Unique
    currency_rate: Optional[float] = None
    currency_symbol: Optional[str] = None
    currency_description: Optional[str] = None
    refresh_time: Optional[datetime] = None
    fractional_unit: Optional[str] = None
    number_to_base: Optional[int] = None
    

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
    
class ecashAccept(BaseModel):
    ecash_token: str 

class customHandle(BaseModel):
    custom_handle: str

class ownerData(BaseModel):
    npub: str|None = None
    local_currency: str|None=None

class addCard(BaseModel):
    title: str
    content: str

class updateCard(BaseModel):
    title: str
    content: str
    kind: int = 37375

class deleteCard(BaseModel):
    title: str
    kind: int = 37375
  
class transmitConsultation(BaseModel):
    nauth: str
    kind: int = 1060

class incomingRecord(BaseModel):
    id: str
    kind: int = 1060


