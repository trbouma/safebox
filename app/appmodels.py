from typing import Optional

from pydantic import BaseModel
from typing import List, Union
from enum import Enum
from datetime import datetime

from sqlmodel import Field, SQLModel




class RegisteredSafebox(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    handle: str
    custom_handle: Optional[str] = Field(default=None,unique=True, nullable=True)
    npub: str
    nsec: Optional[str] = Field(default=None, nullable=True)  # Made nullable
    home_relay: str 
    onboard_code: str 
    access_key: Optional[str] = Field(default=None, nullable=True)  # Made nullable 
    balance: int = 0
    owner: Optional[str] = None
    session_nonce: Optional[str] = None
    emergency_code: Optional[str] = Field(default=None,unique=True, nullable=True)
    currency_code: Optional[str] = Field(default="USD",unique=False, nullable=True)
    

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

class NWCEvent(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    event_id: str = Field(unique=True, nullable=False)
    # Add more fields below as needed for your use case    

class lnPayAddress(BaseModel):
    address: str 
    amount: float 
    currency: str = "SAT"
    comment: str

class lnPayInvoice(BaseModel):
    invoice: str 
    comment: str = None


class lnInvoice(BaseModel):
    amount: float
    currency: str = "SAT"
    comment: str = "Please Pay!"

class ecashRequest(BaseModel):
    amount: int 
    
class ecashAccept(BaseModel):
    ecash_token: str 

class customHandle(BaseModel):
    custom_handle: str

class nauthRequest(BaseModel):
    npub: str|None = None
    scope: str|None = None
    grant: str|None = None
    transmittal_kind: int|None = None

    

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
    originating_kind: int = 37375
    final_kind: int = 37375


class deleteCard(BaseModel):
    title: str
    kind: int = 37375
  
class transmitConsultation(BaseModel):
    nauth: str
    originating_kind: int = 32227
    final_kind: int = 32225

class incomingRecord(BaseModel):
    id: str
    kind: int = 34002
    nauth: str|None = None

class recoverIdentity(BaseModel):
    seed_phrase: str
    home_relay: Union[None,str]=None
    new_identity: bool = False

class sendCredentialParms(BaseModel):
    nauth: str
    grant: str = None

class sendRecordParms(BaseModel):
    nauth: str
    grant: str = None

class paymentByToken(BaseModel):
    payment_token: str
    amount: float = 0    
    currency: str = "SAT"
    comment: str = "Please Pay!"

class proofByToken(BaseModel):
    proof_token: str|None = None
    nauth: str
    label: str|None=None


class nfcCard(BaseModel):
    nembed: str

class nfcPayRequest(BaseModel):
    nembed: str
    amount: int
    comment: str = "nwc pay request"
    
      
class nfcPayOutRequest(BaseModel):
    nembed: str
    amount: float
    currency: str = "SAT"
    comment: str = "nwc pay request"
    
class nwcVault(BaseModel):
    ln_invoice: str
    token: str 
    tendered_amount: float|None = None
    tendered_currency: str = "SAT"
    comment: str|None=None
    pubkey:str|None= None
    sig: str|None = None  

class proofVault(BaseModel):    
    token: str 
    nauth: str
    label: str|None = None
    pubkey:str|None= None
    sig: str|None = None  

class nfcPayOutVault(BaseModel):
    token: str
    amount: int
    tendered_amount: float|None = None
    tendered_currency: str = "SAT"
    comment: str = "nwc pay request"
    pubkey: str|None = None
    sig: str|None=None
    
