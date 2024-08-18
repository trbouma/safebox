from pydantic import BaseModel
from typing import Union, List, Optional
from typing import Any, Dict
import hashlib
from binascii import hexlify
from enum import Enum
from datetime import datetime
import json, base64

class BIP329Enum(Enum):
    TYPE_TX     =   "tx"
    TYPE_ADDR   =   "addr"
    TYPE_PUBKEY =   "pubkey"
    TYPE_INPUT  =   "input"
    TYPE_OUTPUT =   "output"
    TYPE_XPUB   =   "xpub"
    TYPE_WALLET =   "wallet"
    TYPE_NOTE   =   "note"
    TYPE_PROOF  =   "proof"

class DLEQ(BaseModel):
    """
    Discrete Log Equality (DLEQ) Proof
    """

    e: str
    s: str


class DLEQWallet(BaseModel):
    """
    Discrete Log Equality (DLEQ) Proof
    """

    e: str
    s: str
    r: str  # blinding_factor, unknown to mint but sent from wallet to wallet for DLEQ proof

class Proof(BaseModel):
    """
    Value token
    """

    # NOTE: None for backwards compatibility for old clients that do not include the keyset id < 0.3
    id: Union[None, str] = ""
    amount: int = 0
    secret: str = ""  # secret or message to be blinded and signed
    Y: str = ""  # hash_to_curve(secret)
    C: str = ""  # signature on secret, unblinded by wallet
    dleq: Union[DLEQWallet, None] = None  # DLEQ proof
    witness: Union[None, str] = ""  # witness for spending condition

    # whether this proof is reserved for sending, used for coin management in the wallet
    reserved: Union[None, bool] = False
    # unique ID of send attempt, used for grouping pending tokens in the wallet
    send_id: Union[None, str] = ""
    time_created: Union[None, datetime, str] = ""
    time_reserved: Union[None, datetime, str] = ""
    derivation_path: Union[None, str] = ""  # derivation path of the proof
    mint_id: Union[None, str] = (
        None  # holds the id of the mint operation that created this proof
    )
    melt_id: Union[None, str] = (
        None  # holds the id of the melt operation that destroyed this proof
    )
   

class Proofs(BaseModel):
    proofs: List[Proof] = []

class proofEvent(BaseModel):
    id:         str = "Not set"  
    proofs:     List[Proof] = []     

class walletQuote(BaseModel):
    quote:          str   
    amount:         int
    invoice:        str = ""

class proofEvents(BaseModel):
      
  proof_events:     List[proofEvent] = []    

class nostrProfile(BaseModel):
    name:           str = "Not set"
    display_name:   str = "Not set"
    about:          str = "Not set"
    picture:        str = "Not set"
    nip05:          str = "Not set"
    banner:         str = "Not set"
    website:        str = "Not set"
    lud16:          str = "npub@openbalance.app"

class mintRequest(BaseModel):
    unit:       str = "sat"
    amount:     int = 0    

class mintQuote(BaseModel):
    quote:      str
    request:    str
    paid:       bool = False
    state:      str = 'UNPAID'    
    expiry:     int|None = None

class cliQuote(BaseModel):
    invoice:    str
    quote:      str


class KeysetsResponseKeyset(BaseModel):
    id: str
    unit: str
    active: bool


class KeysetsResponse(BaseModel):
    keysets: list[KeysetsResponseKeyset]

class BlindedMessage(BaseModel):
    """
    Blinded message or blinded secret or "output" which is to be signed by the mint
    """

    amount: int
    id: str  # Keyset id
    B_: str  # Hex-encoded blinded message

class BlindedSignature(BaseModel):
    """
    Blinded signature or "promise" which is the signature on a `BlindedMessage`
    """

    id: str
    amount: int
    C_: str  # Hex-encoded signature
    dleq: Optional[DLEQ] = None  # DLEQ proof


    
class PostMeltQuoteResponse(BaseModel):
    quote: str  # quote id
    amount: int  # input amount
    fee_reserve: int  # input fee reserve
    paid: bool  # whether the request has been paid # DEPRECATED as per NUT PR #136
    state: str  = "" # state of the quote
    expiry: Optional[int]  # expiry of the quote
    payment_preimage: Optional[str] = None  # payment preimage
    change: Union[List[BlindedSignature], None] = None 

class SafeboxItem(BaseModel):
    name:           str|None=None
    type:           BIP329Enum|None=None
    description:    str|None=None
    value:          str|None=None
   

    
    def gethash(self):       
        
        return hexlify(hashlib.sha256((self.name+self.description).encode()).digest()).decode()
    
    def get_d_tag(self, pubkey: str):       
        
        return hexlify(hashlib.sha256((self.name+self.description+pubkey).encode()).digest()).decode()
    
class TokenV3Token(BaseModel):
    mint: Optional[str] = None
    proofs: List[Proof]

    def to_dict(self, include_dleq=False):
        return_dict = dict(proofs=[p.to_dict(include_dleq) for p in self.proofs])
        if self.mint:
            return_dict.update(dict(mint=self.mint))  # type: ignore
        return return_dict


class TokenV3(BaseModel):
    """
    A Cashu token that includes proofs and their respective mints. Can include proofs from multiple different mints and keysets.
    """

    token: List[TokenV3Token] = []
    memo: Optional[str] = None
    unit: Optional[str] = None

    def get_proofs(self):
        return [proof for token in self.token for proof in token.proofs]

    def get_amount(self):
        return sum([p.amount for p in self.get_proofs()])

    def get_keysets(self):
        return list(set([p.id for p in self.get_proofs()]))

    def get_mints(self):
        return list(set([t.mint for t in self.token if t.mint]))

    def serialize_to_dict(self, include_dleq=False):
        return_dict = dict(token=[t.to_dict(include_dleq) for t in self.token])
        if self.memo:
            return_dict.update(dict(memo=self.memo))  # type: ignore
        if self.unit:
            return_dict.update(dict(unit=self.unit))  # type: ignore
        return return_dict

    @classmethod
    def deserialize(cls, tokenv3_serialized: str) -> "TokenV3":
        """
        Ingesta a serialized "cashuA<json_urlsafe_base64>" token and returns a TokenV3.
        """
        prefix = "cashuA"
        assert tokenv3_serialized.startswith(prefix), Exception(
            f"Token prefix not valid. Expected {prefix}."
        )
        token_base64 = tokenv3_serialized[len(prefix) :]
        # if base64 string is not a multiple of 4, pad it with "="
        token_base64 += "=" * (4 - len(token_base64) % 4)

        token = json.loads(base64.urlsafe_b64decode(token_base64))
        return cls.parse_obj(token)

    def serialize(self, include_dleq=False) -> str:
        """
        Takes a TokenV3 and serializes it as "cashuA<json_urlsafe_base64>.
        """
        prefix = "cashuA"
        tokenv3_serialized = prefix
        # encode the token as a base64 string
        tokenv3_serialized += base64.urlsafe_b64encode(
            json.dumps(self.serialize_to_dict(include_dleq)).encode()
        ).decode()
        return tokenv3_serialized


class TokenV4DLEQ(BaseModel):
    """
    Discrete Log Equality (DLEQ) Proof
    """

    e: bytes
    s: bytes
    r: bytes


class TokenV4Proof(BaseModel):
    """
    Value token
    """

    a: int
    s: str  # secret
    c: bytes  # signature
    d: Optional[TokenV4DLEQ] = None  # DLEQ proof
    w: Optional[str] = None  # witness

    @classmethod
    def from_proof(cls, proof: Proof, include_dleq=False):
        return cls(
            a=proof.amount,
            s=proof.secret,
            c=bytes.fromhex(proof.C),
            d=(
                TokenV4DLEQ(
                    e=bytes.fromhex(proof.dleq.e),
                    s=bytes.fromhex(proof.dleq.s),
                    r=bytes.fromhex(proof.dleq.r),
                )
                if proof.dleq
                else None
            ),
            w=proof.witness,
        )


class TokenV4Token(BaseModel):
    # keyset ID
    i: bytes
    # proofs
    p: List[TokenV4Proof]


class TokenV4(BaseModel):
    # mint URL
    m: str
    # unit
    u: str
    # tokens
    t: List[TokenV4Token]
    # memo
    d: Optional[str] = None

    @property
    def mint(self) -> str:
        return self.m

    @property
    def memo(self) -> Optional[str]:
        return self.d

    @property
    def unit(self) -> str:
        return self.u

    @property
    def amounts(self) -> List[int]:
        return [p.a for token in self.t for p in token.p]

    @property
    def amount(self) -> int:
        return sum(self.amounts)

    @property
    def proofs(self) -> List[Proof]:
        return [
            Proof(
                id=token.i.hex(),
                amount=p.a,
                secret=p.s,
                C=p.c.hex(),
                dleq=(
                    DLEQWallet(
                        e=p.d.e.hex(),
                        s=p.d.s.hex(),
                        r=p.d.r.hex(),
                    )
                    if p.d
                    else None
                ),
                witness=p.w,
            )
            for token in self.t
            for p in token.p
        ]

    @classmethod
    def from_tokenv3(cls, tokenv3: TokenV3):
        if not len(tokenv3.get_mints()) == 1:
            raise Exception("TokenV3 must contain proofs from only one mint.")

        proofs = tokenv3.get_proofs()
        proofs_by_id: Dict[str, List[Proof]] = {}
        for proof in proofs:
            proofs_by_id.setdefault(proof.id, []).append(proof)

        cls.t = []
        for keyset_id, proofs in proofs_by_id.items():
            cls.t.append(
                TokenV4Token(
                    i=bytes.fromhex(keyset_id),
                    p=[
                        TokenV4Proof(
                            a=p.amount,
                            s=p.secret,
                            c=bytes.fromhex(p.C),
                            d=(
                                TokenV4DLEQ(
                                    e=bytes.fromhex(p.dleq.e),
                                    s=bytes.fromhex(p.dleq.s),
                                    r=bytes.fromhex(p.dleq.r),
                                )
                                if p.dleq
                                else None
                            ),
                            w=p.witness,
                        )
                        for p in proofs
                    ],
                )
            )

        # set memo
        cls.d = tokenv3.memo
        # set mint
        cls.m = tokenv3.get_mints()[0]
        # set unit
        cls.u = tokenv3.unit or "sat"
        return cls(t=cls.t, d=cls.d, m=cls.m, u=cls.u)

    def serialize_to_dict(self, include_dleq=False):
        return_dict: Dict[str, Any] = dict(t=[t.dict() for t in self.t])
        # strip dleq if needed
        if not include_dleq:
            for token in return_dict["t"]:
                for proof in token["p"]:
                    if "d" in proof:
                        del proof["d"]
        # strip witness if not present
        for token in return_dict["t"]:
            for proof in token["p"]:
                if not proof.get("w"):
                    del proof["w"]
        # optional memo
        if self.d:
            return_dict.update(dict(d=self.d))
        # mint