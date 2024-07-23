from pydantic import BaseModel
import hashlib
from binascii import hexlify

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
        
        return hexlify(hashlib.sha256(self.name.encode()).digest()).decode()