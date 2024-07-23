from pydantic import BaseModel
import hashlib
from binascii import hexlify
from enum import Enum

class BIP329Enum(Enum):
    TYPE_TX     =   "tx"
    TYPE_ADDR   =   "addr"
    TYPE_PUBKEY =   "pubkey"
    TYPE_INPUT  =   "input"
    TYPE_OUTPUT =   "output"
    TYPE_XPUB   =   "xpub"
    TYPE_WALLET =   "wallet"
    TYPE_NOTE   =   "note"


class nostrProfile(BaseModel):
    name:           str|None=None
    display_name:   str|None=None
    about:          str|None=None
    picture:        str|None=None
    nip05:          str|None=None
    banner:         str|None=None
    website:        str|None=None



class SafeboxItem(BaseModel):
    name:           str|None=None
    type:           str|None=None
    description:    str|None=None
   

    
    def gethash(self):       
        
        return hexlify(hashlib.sha256((self.name+self.description).encode()).digest()).decode()