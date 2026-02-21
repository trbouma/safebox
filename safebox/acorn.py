from typing import Any, Dict, List, Optional, Union
import asyncio, json, requests
from time import sleep,time
import secrets
from datetime import datetime, timedelta
import urllib.parse
import random
from mnemonic import Mnemonic
import bolt11
import aioconsole
import logging
import httpx
import math
from zoneinfo import ZoneInfo
from datetime import timezone
import filetype

from hotel_names import hotel_names
# from coolname import generate, generate_slug
from binascii import unhexlify
import hashlib
import signal, sys, string, cbor2, base64,os
from bip_utils import Bip39SeedGenerator, Bip32Slip10Ed25519, Bip32Slip10Secp256k1
import contextlib



from monstr.encrypt import Keys
from monstr.encrypt import NIP44Encrypt, NIP4Encrypt
from monstr.client.client import Client, ClientPool
from monstr.event.event import Event


from monstr.signing.signing import BasicKeySigner
from monstr.giftwrap import GiftWrap
from monstr.util import util_funcs
from monstr.entities import Entities
from monstr.client.event_handlers import DeduplicateAcceptor

from safebox.monstrmore import KindOtherGiftWrap, ExtendedNIP44Encrypt
from safebox.func_utils import npub_to_hex, encrypt_bytes, decrypt_bytes


tail = util_funcs.str_tails

from safebox.b_dhke import step1_alice, step3_alice, hash_to_curve
from safebox.secp import PrivateKey, PublicKey
from safebox.lightning import lightning_address_pay, lnaddress_to_lnurl, zap_address_pay
from safebox.nostr import bech32_to_hex, hex_to_bech32, nip05_to_npub, create_nembed_compressed,parse_nembed_compressed

from safebox.models import nostrProfile, SafeboxItem, mintRequest, mintQuote, BlindedMessage, Proof, Proofs, proofEvent, proofEvents, KeysetsResponse, PostMeltQuoteResponse, walletQuote, NIP60Proofs
from safebox.models import TokenV3, TokenV3Token, cliQuote, proofsByKeyset, Zevent
from safebox.models import TokenV4, TokenV4Token
from safebox.models import WalletConfig, WalletRecord,WalletReservedRecords
from safebox.models import TxHistory, SafeboxRecord, ParseRecord, EncryptionParms, EncryptionResult, OriginalRecordTransfer

from safebox.func_utils import generate_name_from_hex, name_to_hex, generate_access_key_from_hex,split_proofs_instance

from python_blossom import BlossomClient, Blob as BlossomBlob
from tempfile import NamedTemporaryFile
import mimetypes

RECORD_LIMIT: int = 1024
PROOF_LIMIT: int = 32

def powers_of_2_sum(amount):
    powers = []
    while amount > 0:
        power = 1
        while power * 2 <= amount:
            power *= 2
        powers.append(power)
        amount -= power
    return sorted(powers)




    return "hello"
class Acorn:
    k: Keys
    nsec: str
    name: str
    handle: str
    unit: str   = "sat" 
    acorn_tags: List = None
    owner: str = None
    proof_event_ids = []
    pubkey_bech32: str
    pubkey_hex: str
    privkey_hex: str
    privkey_bech32: str 
    seed_phrase: str = ""  
    access_key: str =""
    pqc_self_secret: str = None
    home_relay: str
    home_mint: str
    known_mints: dict = {}
    local_currency: str = "SAT"
    latest_ecash: int = 0
    emergency_contacts: List[str] = None
    authorities: List[str] = None
    providers: List[str] = None
    trusted_entities: List[str] = None
    user_records = []
    relays: List[str]
    mints: List[str]
    max_proof_event_size: int
    safe_box_items: List[SafeboxItem]
    proofs: List[Proof]
    profile_found_on_home_relay = False
    events: int
    balance: int
    proof_events: proofEvents 
    replicate: bool
    RESERVED_RECORDS: List[str] = ["balance","privkey"]
    wallet_reserved_records: object
    logger: logging.Logger
    TZ: str = "America/New_York"

    



    def __init__(   self, 
                    nsec: str, 
                    relays: List[str]|None=None, 
                    mints: List[str]|None=None,
                    home_relay:str|None=None, 
                    max_proof_event_size: int = 16384,
                    replicate = False, 
                    logging_level=logging.INFO) -> None:
        
        self.max_proof_event_size = max_proof_event_size
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging_level)  
        # Configure the logger's handler and format
        if not self.logger.hasHandlers():
            handler = logging.StreamHandler()  # Output to console
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

        
        access_key_digest = hashlib.sha256()    
        
        self.logger.info(f"Wallet initialized: {self.__class__.__name__}")

        if nsec.startswith('nsec'):
            self.k = Keys(priv_k=nsec)
            self.pubkey_bech32  =   self.k.public_key_bech32()
            self.pubkey_hex     =   self.k.public_key_hex()
            self.privkey_bech32 =   self.k.private_key_bech32()
            self.privkey_hex    =   self.k.private_key_hex()
            self.relays         =   relays
            self.mints          =   mints
            # self.home_mint      = mints[0]
            self.safe_box_items = []
            self.proofs: List[Proof] = []
            self.balance: int = 0
            self.proof_events = proofEvents()
            self.trusted_mints = {}
            self.trusted_entities = []
            self.home_relay = home_relay
            self.replicate = replicate
            self.wallet_config = None
            self.handle = generate_name_from_hex(self.pubkey_hex)
            access_key_digest.update(self.privkey_hex.encode())
            access_key_hash = access_key_digest.hexdigest()
            self.access_key = generate_access_key_from_hex(access_key_hash)

            self.wallet_reserved_records = {}
        else:
            return "Need nsec" 

        
 
        
        # asyncio.run(self._load_proofs())
        

        
        return None
   
    async def load_data(self, force_profile_creation: bool=False):
        self.logger.debug(f"load data. Force profile creation {force_profile_creation}")

        try:

          
            # wallet_config= await self.get_wallet_config()
            wallet_config=None
            if wallet_config:
                self.acorn_tags = wallet_config
            else:
                #FIXME get rid of this eventually
                wallet_info = await self.get_wallet_info(label="wallet")
                self.acorn_tags = json.loads(wallet_info)


            

            for each in self.acorn_tags:
                if each[0]== "balance":
                    self.balance = int(each[1])
                    self.unit = each[2]
                if each[0] == "mint":
                    self.home_mint = each[1]
                    # print(f"home mint: {self.home_mint}")
                if each[0] == "name":
                    self.name = each[1]
                if each[0] == "local_currency":
                    self.local_currency = each[1]
                    # print(f"name: {self.name}")
                if each[0] == "owner":
                    self.owner = each[1]
                    # print(f"owner: {self.owner}")
                if each[0] == "privkey":                    
                    # print(f"privkey: {each[1]}")
                    # print(f"pubkey: {Keys(priv_k=each[1]).public_key_hex()}")
                    pass
                if each[0] == "seedphrase":
                    self.seed_phrase = each[1]
                if each[0] == "local_currency":
                    self.local_currency = each[1]
                if each[0] == "user_record":
                    self.user_records.append(each[1])  
                if each[0] == "latest_ecash":
                    self.latest_ecash = each[1] 

        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as e:
            # await self.set_wallet_info(label="wallet",label_info=json.dumps(self.acorn_tags))
            if force_profile_creation:
                self.logger.info("op=load_data status=create_profile_on_missing_data relay=%s", self.home_relay)
                await self.create_instance(keepkey=True)
                
            else:
                self.logger.error("op=load_data status=failed relay=%s error=%s", self.home_relay, e)
                raise RuntimeError(f"No wallet data on {self.home_relay}!!!")


        await self._load_proofs()
        
        
        if len(self.proofs) > PROOF_LIMIT:
            self.logger.info("op=load_data status=reduce_proofs proofs=%s", len(self.proofs))
            await self.swap_multi_each()
            await self.swap_multi_consolidate()
        return
    
    async def set_owner_data(self, npub:str = None, local_currency=None):

        update_tags = []
        if npub ==None and local_currency== None:
            return
        if npub:            
            try:
                npub_obj = Keys(pub_k=npub)
                update_tags.append(["owner",npub])                
            except (ValueError, TypeError) as exc:
                raise ValueError("npub is not a valid format")
        if local_currency:
            update_tags.append(["local_currency",local_currency])
        
        await self.update_tags(update_tags)
        return "OK"

    def __repr__(self):
        out_str = json.dumps(self.wallet_reserved_records)

        return out_str
    
    def powers_of_2_sum(self, amount: int):
        powers = []
        while amount > 0:
            power = 1
            while power * 2 <= amount:
                power *= 2
            powers.append(power)
            amount -= power
        return sorted(powers)
    
    def create_profile(self, nostr_profile_create: bool=False, keepkey:bool=False, longseed:bool=False):
        init_index = {}
        wallet_info = {}
        n_profile = {}
        mnemo = Mnemonic("english")

        if keepkey==False:
            if longseed:
                #TODO need to decide if to keep 24 seed phrase option.
                seed_phrase = mnemo.generate(strength=128)
                seed = Bip39SeedGenerator(seed_phrase).Generate()
                bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed)
                seed_private_key_hex = bip32_ctx.PrivateKey().Raw().ToBytes().hex()
                self.logger.debug(f"seed private key: {seed_private_key_hex}")                

                self.k= Keys(priv_k=seed_private_key_hex)
                self.pubkey_bech32  =   self.k.public_key_bech32()
                self.pubkey_hex     =   self.k.public_key_hex()
                self.privkey_hex    =   self.k.private_key_hex()
                seed_phrase = mnemo.to_mnemonic(bytes.fromhex(self.privkey_hex))

            else:
                # This to generate a 32 byte private key from a 12 word seed phrase
                # Need to store because it cannot be derives from the resulting private key
                
                seed_phrase = mnemo.generate(strength=128)
                seed = Bip39SeedGenerator(seed_phrase).Generate()
                bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed)
                seed_private_key_hex = bip32_ctx.PrivateKey().Raw().ToBytes().hex()
                self.logger.debug(f"seed private key: {seed_private_key_hex}")
                
                self.k= Keys(priv_k=seed_private_key_hex)
                self.pubkey_bech32  =   self.k.public_key_bech32()
                self.pubkey_hex     =   self.k.public_key_hex()
                self.privkey_hex    =   self.k.private_key_hex()
            

        
        local_name = generate_name_from_hex(self.pubkey_hex)
        hotel_name = hotel_names.get_hotel_name()
       
        # Create nprofile
        n_profile['pubkey'] = self.k.public_key_hex()
        n_profile['relay'] = [self.home_relay]
        n_profile_str = Entities.encode('nprofile', n_profile)
        self.logger.debug("op=create_profile status=nprofile_created nprofile=%s", n_profile_str)

        nostr_profile = nostrProfile(   name=local_name,
                                        display_name=local_name,
                                        about = f"Resident of {hotel_name}",
                                        picture=f"https://robohash.org/{local_name}/?set=set4",
                                        lud16= f"{local_name}@openbalance.app",
                                        website=f"https://njump.me/{self.pubkey_bech32}",
                                        nprofile=n_profile_str

                                         )
        if nostr_profile_create:
            out = asyncio.run(self._async_create_profile(nostr_profile))
            hello_msg = f"Hello World from {local_name}! #introductions"
            self.logger.info("op=create_profile status=hello_post msg=%s", hello_msg)
            asyncio.run(self._async_send_post(hello_msg))
            self.logger.debug("op=create_profile status=post_result result=%s", out)

        # init_index = "[{\"root\":\"init\"}]"
        init_index["root"] = local_name
        # self.set_index_info(json.dumps(init_index))
        self.set_wallet_info(label="default", label_info=local_name)
        self.set_wallet_info(label="profile", label_info=json.dumps(nostr_profile.model_dump()))
        
        self.wallet_config = WalletConfig(  kind_cashu = 7375,
                                            seed_phrase=seed_phrase)                
        self.set_wallet_info(label="wallet_config", label_info=json.dumps(self.wallet_config.model_dump()))
        self.set_wallet_info(label="mints", label_info=json.dumps(self.mints))
        self.set_wallet_info(label="relays", label_info=json.dumps(self.relays))
        self.set_wallet_info(label="quote", label_info='[]')
        self.set_wallet_info(label="index", label_info='{}')
        self.set_wallet_info(label="last_dm", label_info='0')
        self.set_wallet_info(label="user_records", label_info='[]')
        self.set_wallet_info(label="payment_request", label_info='[]')

        self._load_record_events()
        
 
        return self.k.private_key_bech32()

    async def _async_create_profile(self, nostr_profile: nostrProfile, replicate_relays: List[str]=None):
        if replicate_relays:
            write_relays = replicate_relays
        else:
            write_relays = [self.home_relay]
        async with ClientPool(write_relays) as c:
            out_msg = "ok"
            try:
                profile = nostr_profile.model_dump_json()
            
                profile_str = json.dumps(profile)
                self.logger.debug("op=create_profile status=profile_json_ready")
                # this seems to work
                profile_2 = json.dumps(nostr_profile.model_dump(mode='json'))
                n_msg = Event(kind=0,
                        content=profile_2,
                        pub_key=self.pubkey_hex)
                n_msg.sign(self.privkey_hex)
                c.publish(n_msg)
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                self.logger.warning("op=create_profile status=publish_failed error=%s", exc)
                out_msg = "error"
        return out_msg

    async def create_instance(self, keepkey:bool=False, longseed:bool=False, name="wallet"):
        out_msg = "This is another instance"
        mnemo = Mnemonic("english")
        access_key_digest = hashlib.sha256()
        if keepkey==False:
            if longseed:
                #TODO need to decide if to keep 24 seed phrase option.
                seed_phrase = mnemo.generate(strength=128)
                seed = Bip39SeedGenerator(seed_phrase).Generate()
                bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed)
                seed_private_key_hex = bip32_ctx.PrivateKey().Raw().ToBytes().hex()
                self.logger.debug(f"seed private key: {seed_private_key_hex}")                

                self.k= Keys(priv_k=seed_private_key_hex)
                self.pubkey_bech32  =   self.k.public_key_bech32()
                self.privkey_bech32 =   self.k.private_key_bech32()
                self.pubkey_hex     =   self.k.public_key_hex()
                self.privkey_hex    =   self.k.private_key_hex()
                seed_phrase = mnemo.to_mnemonic(bytes.fromhex(self.privkey_hex))

            else:
                # This to generate a 32 byte private key from a 12 word seed phrase
                # Need to store because it cannot be derives from the resulting private key
                
                seed_phrase = mnemo.generate(strength=128)
                seed = Bip39SeedGenerator(seed_phrase).Generate()
                bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed)
                seed_private_key_hex = bip32_ctx.PrivateKey().Raw().ToBytes().hex()
                self.logger.debug(f"seed private key: {seed_private_key_hex}")
                
                self.k= Keys(priv_k=seed_private_key_hex)
                self.pubkey_bech32  =   self.k.public_key_bech32()
                self.privkey_bech32 =   self.k.private_key_bech32()
                self.pubkey_hex     =   self.k.public_key_hex()
                self.privkey_hex    =   self.k.private_key_hex()
            
            nut_key = Keys()
            self.seed_phrase = seed_phrase
            self.acorn_tags = [ [ "balance", "0", "sat" ],
                                [ "privkey", nut_key.private_key_hex() ], 
                                [ "mint", self.mints[0]],
                                [ "name", name ],
                                ["seedphrase",seed_phrase],
                                ["owner",self.pubkey_bech32],
                                ["local_currency", self.local_currency]
                            ]
            
            self.handle = generate_name_from_hex(self.pubkey_hex)
            access_key_digest.update(self.privkey_hex.encode())
            access_key_hash = access_key_digest.hexdigest()
            self.access_key = generate_access_key_from_hex(access_key_hash)
            self.logger.debug(f"acorn tags: {self.acorn_tags} npub: {self.pubkey_bech32}")
            await self.set_wallet_info(label=name,label_info=json.dumps(self.acorn_tags))
            # await self.set_wallet_config()
        else:
            #keepkey = true # we already have a private key
            # need to check if a profile exists, if not create one
            try:
            
                wallet_config= await self.get_wallet_config()
                if  wallet_config:
                    return self.privkey_bech32
                else:
                    seed_phrase = mnemo.to_mnemonic(bytes.fromhex(self.privkey_hex))
                    nut_key = Keys()
                    self.acorn_tags = [ [ "balance", "0", "sat" ],
                                [ "privkey", nut_key.private_key_hex() ], 
                                [ "mint", self.mints[0]],
                                [ "name", name ],
                                ["seedphrase",seed_phrase],
                                ["owner",self.pubkey_bech32],
                                ["local_currency", self.local_currency]
                            ]
                    self.handle = generate_name_from_hex(self.pubkey_hex)
                    access_key_digest.update(self.privkey_hex.encode())
                    access_key_hash = access_key_digest.hexdigest()
                    self.access_key = generate_access_key_from_hex(access_key_hash)
                    self.logger.debug(f"acorn tags: {self.acorn_tags} npub: {self.pubkey_bech32}")
                    pass
                    await self.set_wallet_config()
                    


            except (ValueError, TypeError, KeyError, json.JSONDecodeError) as e:
                self.logger.warning("op=create_instance status=no_profile error=%s", e)

            pass
        return self.privkey_bech32

    def get_profile(self, name="wallet"):
        mints = []
        mnemo = Mnemonic("english")
        try:
            for each in self.acorn_tags:
                if each[0] == "balance":
                    balance_amount = int(each[1])
                    balance_unit = each[2]
                elif each[0] == "privkey":
                    lock_privkey = each[1]
                    lock_pubkey = Keys(each[1]).public_key_hex()
                elif each[0] == "mint":
                    mints.append(each[1])
                elif each[0] == "name":
                    name = each[1]

            known_mints_cat=""

            for index, (key, value) in enumerate(self.known_mints.items()):
                known_mints_cat +=f"\n{index+1}. {value} {key}"

            out_string = f"""   \nnpub: {self.pubkey_bech32}
                                \nnsec: {self.privkey_bech32} 
                                \nnsechex: {self.privkey_hex} 
                                \npubhex: {self.pubkey_hex}  
                                \nhandle: {self.handle}   
                                \naccess key: {self.access_key}  
                                \nowner: {self.owner}                     
                                \nlock privkey: {lock_privkey}
                                \nseed phrase: {self.seed_phrase}
                                \nlock pubkey: {lock_pubkey}
                                \nlocal currency: {self.local_currency}
                                \nhome mints: {mints}
                                \nknown mints: {self.known_mints}
                                \nbalance: {self.balance} {self.unit}
                                \nhome relay: {self.home_relay}
                                \nuser records: {self.user_records}
                                \nname: {name}
                                \n{"*"*75}

            """
        except (ValueError, TypeError, KeyError) as exc:
            self.logger.warning("op=get_profile status=missing_profile error=%s", exc)
            raise RuntimeError("No profile on relay")
            out_string = f"No profile - seed phrase: {mnemo.to_mnemonic(bytes.fromhex(self.privkey_hex))}"
        return out_string






        return out_string
    
    def get_instance(self):
        pass
        return "this is the instance"
    
    def get_balance(self):
        
        balance_tally = 0
        for each in self.proofs:                
            balance_tally += each.amount
            self.balance = balance_tally
        return self.balance
    

    async def listen_for_record(self, record_kind:int=37375, since:int = None, reverse: bool=False, relays:List=None):
        # Listen for a record and return it
        self.logger.info("op=listen_for_record status=start kind=%s", record_kind)

        def incoming_handler(the_client: Client, sub_id: str, evt: Event):
            self.logger.debug("op=listen_for_record status=event sub_id=%s event_id=%s", sub_id, evt.id)
            return

        url = relays[0]
        c = ClientPool(url)
        asyncio.create_task(c.run())
   
        await c.wait_connect()

        c.subscribe(
        handlers=incoming_handler,
        filters={
            'limit': 1024,
            'kinds': [record_kind],
            '#p': [self.pubkey_hex]
            
        }
        )
        while True:
            self.logger.debug("op=listen_for_record status=waiting kind=%s relay=%s", record_kind, url)
            await asyncio.sleep(3)
        return

    async def listen_for_record_sub(
    self,
    record_kind: int = 37375,
    since: int | None = None,
    reverse: bool = False,
    relays: List[str] | None = None,
    timeout: int = 60
    ):
        my_gift = GiftWrap(BasicKeySigner(self.k))
        self.logger.info("op=listen_for_record_sub status=start kind=%s", record_kind)

        loop = asyncio.get_running_loop()
        record_future = loop.create_future()

        def incoming_handler(the_client: ClientPool, sub_id: str, evt: Event):
            if not record_future.done():
                self.logger.debug("op=listen_for_record_sub status=received event_id=%s", evt.id)
                record_future.set_result(evt)

        # url = relays[0]
        client = ClientPool(relays)

        # Run client in background
        client_task = asyncio.create_task(client.run())
        sub_id = secrets.token_hex(4)
        await client.wait_connect()

        client.subscribe(
            sub_id=sub_id,
            handlers=incoming_handler,
            filters={
                "limit": 1,
                "kinds": [record_kind],
                "#p": [self.pubkey_hex],
            },
        )

        try:
            # Wait until first record arrives
            evt = await asyncio.wait_for(record_future, timeout=timeout)
            unwrapped_event = await my_gift.unwrap(evt)
            nauth_split = unwrapped_event.content.split(':')
            nauth = nauth_split[0]
            if len(nauth_split)>1:
                nembed = nauth_split[1]
            else:
                nembed = None  
               
            return nauth, nembed
        except (asyncio.TimeoutError, ValueError, TypeError) as exc:
            self.logger.debug("op=listen_for_record_sub status=timeout_or_invalid kind=%s error=%s", record_kind, exc)
            return None, None

        finally:
            # Clean shutdown no matter what
            self.logger.debug("op=listen_for_record_sub status=shutdown")
            # await client.unsubscribe(sub_id=sub_id)
            client_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await client_task
    
    async def get_user_records(self, record_kind:int=37375, since:int = None, reverse: bool=False, relays:List=None)->List[Any]:

        events_out = []
        my_enc = NIP44Encrypt(self.k)
        my_gift = GiftWrap(BasicKeySigner(self.k))
        m = hashlib.sha256()
        m.update(self.privkey_hex.encode())
        # m.update(label.encode())
        # label_hash = m.digest().hex()
        decrypt_content = None

        if relays:
            relays_to_use = relays
        else:
            relays_to_use = [self.home_relay]

        # handle records that are coming in via giftwraps
        # 1059 are regular DMs
        # 1060 are health records
        # 1061 are health authentication messages
        # 1062 are shared notes
        # 1063 are official docs and credentials
        # 1400-1499: regular events
        # 21400-21400: emphemeral events

        if record_kind in [1059,1060,1061,1062,1063,21059,21060,21061,21062,21063] or \
            (1400 <= record_kind <= 1499) or (21400 <= record_kind <= 21499):
            
           if since:        
                FILTER = [{
                'limit': RECORD_LIMIT, 
                '#p'  :  [self.pubkey_hex],              
                'kinds': [record_kind],
                'since': since
                
                }]
           else:
                FILTER = [{
                'limit': RECORD_LIMIT, 
                '#p'  :  [self.pubkey_hex],              
                'kinds': [record_kind]
                
                }]
               
        else:
                FILTER = [{
                'limit': RECORD_LIMIT,
                'authors': [self.pubkey_hex],
                'kinds': [record_kind]   
                
            }]

        # print(f"kind: {record_kind} relays to use: {relays_to_use}")
        self.logger.debug(f"kind: {record_kind} relays to use: {relays_to_use} filter: {FILTER}")
        async with ClientPool(relays_to_use) as c:  
            events = await c.query(FILTER)           
        
        events.sort(reverse=reverse)

        each: Event
        for each in events:
            
            # check to see if record originates from elsewhere
            if record_kind in [1059,1060,1061,1062,1063,21059,21060,21061,21062,21063] or \
                (1400 <= record_kind <= 1499) or (21400 <= record_kind <= 21499):
                # print(f"need to  unwrap {type(each.content)} {each.content} ")
                try:
                    pass
                    # print(f"content to decrypt: {each.content}")
                    # decrypt_content = my_enc.decrypt(each.content,self.pubkey_hex)
                    # print(f"decrypt content {decrypt_content}")

                    unwrapped_event = await my_gift.unwrap(each)
                    # print(f"unwrapped event content: {unwrapped_event.content}")
                    try:
                        parsed_record = json.loads(unwrapped_event.content)
                        parsed_record['created_at'] = unwrapped_event.created_at.strftime("%Y-%m-%d %H:%M:%S")
                        parsed_record['id']=unwrapped_event.id
                        parsed_record['sender']=unwrapped_event.pub_key
                        
                        

                    except (json.JSONDecodeError, TypeError) as exc:
                        parsed_record = {   "tag": ["message"],
                                            "type": "dm",
                                            "created_at": unwrapped_event.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                                            "payload":unwrapped_event.content,
                                            "id": unwrapped_event.id,
                                            "timestamp": int(unwrapped_event.created_at.timestamp())
                                            }

                    
                    parsed_record['presenter'] = unwrapped_event.pub_key
                    parsed_record['sender'] = unwrapped_event.pub_key
                    parsed_record['social_name'] = None

                except (ValueError, TypeError, RuntimeError) as e:
                    self.logger.warning("op=get_user_records status=unwrap_failed kind=%s event=%s error=%s", record_kind, each.id, e)
                    continue
            
                #Add in sender detais
                if record_kind in [1059]:
                    social_profile = await self.get_social_profile(npub=unwrapped_event.pub_key,relays=relays_to_use)
                    parsed_record['social_name'] = social_profile.get('display_name', None)
                else:
                    parsed_record['social_name'] = None


            else: # otherwise record is self-originating
                try:
                    decrypt_content = my_enc.decrypt(each.content, self.pubkey_hex)
                except (ValueError, TypeError) as exc:
                    # Try Gift Unwrapping
                    decrypt_event = my_enc.decrypt_event(each)
                    decrypt_content = decrypt_event.content
            
                try:
                    parsed_record = json.loads(decrypt_content)
                except (json.JSONDecodeError, TypeError) as exc:
                    #It's just a raw string stored - map into the fields    
                    parsed_record = {}           
                    parsed_record['payload'] = decrypt_content
                    #add the extra fields
                    parsed_record['created_at'] = each.created_at.strftime("%Y-%m-%d %H:%M:%S")
                    parsed_record['id'] = each.id
                    parsed_record['presenter'] = self.pubkey_hex
                    parsed_record['sender'] = each.pub_key

                # check for special wallet record which is a list
                if isinstance(parsed_record,list):
                    #FIXME not sure if in a list
                    pass
                else:
                    #FIXME - I think this logic is in the wrong place
                    parsed_record['created_at'] = each.created_at.strftime("%Y-%m-%d %H:%M:%S")
                    parsed_record['id'] = each.id
                    parsed_record['presenter'] = self.pubkey_hex
                    parsed_record['sender'] = each.pub_key

            # Convert payload to json
            # See if payload is in stringifed json and convert
                    
            if isinstance(parsed_record, dict) and "payload" in parsed_record:
                try:
                    payload_obj = json.loads(parsed_record["payload"])
                    parsed_record["payload"] = payload_obj
                except (json.JSONDecodeError, TypeError) as exc:
                    self.logger.debug(
                        "Payload is not JSON for event_id=%s",
                        parsed_record.get("id", "unknown"),
                    )
            else:
                self.logger.debug(
                    "Skipping payload JSON parse for record_type=%s",
                    type(parsed_record).__name__,
                )

            #check to see if wallet record and skip
            if isinstance(parsed_record,list):
                pass
            else:
                
                #Inspect Payload and decide what to show
                # print(f"get parsed record payload: {type(parsed_record['payload'])} {parsed_record['payload']}")
                if isinstance(parsed_record["payload"], dict):
                    # private event so just show context
                    parsed_record["content"] = parsed_record["payload"]["content"]
                    
                else:
                    # string so just show string
                    parsed_record["content"] = parsed_record["payload"]
                    

                
                events_out.append(parsed_record)
              
        
        return events_out


    async def _async_query_client_profile(self, filter: List[dict]): 
    # does a one off query to relay prints the events and exits
        json_obj = {}
        # print("are we here today", self.relays)
        async with ClientPool([self.home_relay]+self.relays) as c:        
            events = await c.query(filter)
        try:    
            json_str = events[0].content
            # print("json_str", json_str)
            # json_obj = json.loads(json_str)
            json_obj = json.loads(json_str)
        except (IndexError, json.JSONDecodeError, TypeError) as exc:
            self.logger.debug("op=query_client_profile status=missing_or_invalid error=%s", exc)
            {"staus": "could not access profile"}
            pass
       
        # print("json_obj", json_obj)
        
        return json_str
        
    def replicate_safebox(self, replicate_relays = List[str]):
        
        self.logger.info("op=replicate_safebox status=start relays=%s", replicate_relays)

        FILTER = [{
            'limit': 1,
            'authors': [self.pubkey_hex],
            'kinds': [0]
        }]
        
        try:
            profile =asyncio.run(self.async_query_client_profile([self.home_relay],FILTER))
            profile_obj = nostrProfile(**json.loads(profile))
            self.logger.debug("op=replicate_safebox status=profile_loaded")
            asyncio.run(self._async_create_profile(profile_obj, replicate_relays=replicate_relays))
        except (ValueError, TypeError, IndexError, json.JSONDecodeError) as exc:
            self.logger.warning("op=replicate_safebox status=no_profile error=%s", exc)
            out_string = "No profile found!"
            return out_string
        


        self.set_wallet_info(label="test", label_info="test record booga", replicate_relays=replicate_relays)
        # self.set_wallet_info(label="profile", label_info=json.dumps(nostr_profile.model_dump()))
       
        # replicate the reserved records

        profile = self.get_wallet_info(label="profile")
        self.logger.debug("op=replicate_safebox status=replicate_profile")
        self.set_wallet_info(label="profile", label_info=profile, replicate_relays=replicate_relays)

        self.set_wallet_info(label="home_relay", label_info=json.dumps(self.home_relay), replicate_relays=replicate_relays)

        default = self.get_wallet_info(label="default")
        self.set_wallet_info(label="default", label_info=default, replicate_relays=replicate_relays)

        wallet_config = self.get_wallet_info(label="wallet_config")
        self.set_wallet_info(label="wallet_config", label_info=wallet_config, replicate_relays=replicate_relays)
        
        mints = self.get_wallet_info(label="mints")
        self.set_wallet_info(label="mints", label_info=mints,replicate_relays=replicate_relays)
        
        read_relays = self.get_wallet_info(label="relays")
        self.set_wallet_info(label="relays", label_info=read_relays, replicate_relays=replicate_relays)
        
        trusted_mints = self.get_wallet_info(label="trusted_mints")
        self.logger.debug("op=replicate_safebox status=trusted_mints")
        self.set_wallet_info(label="trusted_mints", label_info=json.dumps(self.trusted_mints), replicate_relays=replicate_relays)
        
        quote = self.get_wallet_info(label="quote")
        self.logger.debug("op=replicate_safebox status=quote")
        self.set_wallet_info(label="quote", label_info=quote,replicate_relays=replicate_relays)
        
        index = self.get_wallet_info(label="index")
        self.logger.debug("op=replicate_safebox status=index")
        self.set_wallet_info(label="index", label_info=index, replicate_relays=replicate_relays)
        
        last_dm = self.get_wallet_info(label="last_dm")
        self.logger.debug("op=replicate_safebox status=last_dm")
        self.set_wallet_info(label="last_dm", label_info=last_dm, replicate_relays=replicate_relays)
        
        replicate_proofs = []
        for each in self.proofs:
            each_dump = each.model_dump()
            replicate_proofs.append(each_dump)
        self.logger.debug("op=replicate_safebox status=proofs count=%s", len(replicate_proofs))
        # self.add_proofs(json.dumps(replicate_proofs), replicate_relays=replicate_relays)
        self.add_proofs_obj(self.proofs, replicate_relays=replicate_proofs)
        return profile 
    
    async def _async_store_event(self, event_content_str:str, event_kind: int, relays: List[str]):

        async with ClientPool(relays) as c:
      
            self.logger.debug("op=store_event status=publish kind=%s", event_kind)
      
            n_msg = Event(kind=event_kind,
                        content=event_content_str,
                        pub_key=self.pubkey_hex)
            n_msg.sign(self.privkey_hex)
            c.publish(n_msg)
        return "ok"

    def get_post(self):
        if not self.profile_found_on_home_relay:
            return f"No profile found on {self.home_relay}"
        
        
        FILTER = [{
            'authors': "78733951a0435da2644aa5dbe6230cc0624844132a6fe213e59170bcc7dd3870",
            'limit': RECORD_LIMIT,
            'authors': [self.pubkey_hex],
            'kinds': [1]
        }]
        content =asyncio.run(self.query_client_post(FILTER))
        
        return content
    
    async def query_client_post(self, filter: List[dict]):
    # does a one off query to relay prints the events and exits
        posts = ""
        async with ClientPool([self.home_relay]+self.relays) as c:
        # async with Client(relay) as c:
            events = await c.query(filter)
            
            for each in events:
                posts += str(each.content) +"\n"
                
           
            return posts

    async def send_ecash_dm(self,amount: int, nrecipient: str, ecash_relays:List[str], comment: str ="Sent!"):
        #FIXME Deprecate this function
        relays = []
        try:
            if '@' in nrecipient:
                npub_hex, relays = nip05_to_npub(nrecipient)
                npub = hex_to_bech32(npub_hex)
                self.logger.debug("op=send_ecash_dm status=resolved_npub npub=%s", npub)
            else:
                npub = nrecipient
        except (ValueError, TypeError) as exc:
            self.logger.warning("op=send_ecash_dm status=invalid_recipient recipient=%s error=%s", nrecipient, exc)
            return "error"
        try:
            token_amount = await self.issue_token(amount=amount)
            token_msg = comment +"\n\n" + token_amount
        except (RuntimeError, ValueError, TypeError) as exc:
            self.logger.warning("op=send_ecash_dm status=issue_failed amount=%s error=%s", amount, exc)
            return "insufficient funds"
        
        self.logger.debug("op=send_ecash_dm status=sending relays=%s", ecash_relays)
        out_msg = await self.secure_dm(nrecipient=npub,message=token_msg,dm_relays=ecash_relays)
        # out_msg= asyncio.run(self._async_send_ecash_dm(token_msg,npub, ecash_relays+relays ))
        return out_msg

    async def send_ecash(self,amount: int, nrecipient: str, ecash_relays:List[str], comment: str ="Sent!"):
        #FIXME Deprecate this function
        relays = []
        try:
            if '@' in nrecipient:
                npub_hex, relays = nip05_to_npub(nrecipient)
                npub = hex_to_bech32(npub_hex)
                self.logger.debug("op=send_ecash status=resolved_npub npub=%s", npub)
            else:
                npub = nrecipient
        except (ValueError, TypeError) as exc:
            self.logger.warning("op=send_ecash status=invalid_recipient recipient=%s error=%s", nrecipient, exc)
            return "error"
        try:
            token_msg = await self.issue_token(amount=amount)
            # token_msg = comment +"\n\n" + token_amount
        except (RuntimeError, ValueError, TypeError) as exc:
            self.logger.warning("op=send_ecash status=issue_failed amount=%s error=%s", amount, exc)
            return "insufficient funds"
        
        self.logger.debug("op=send_ecash status=sending relays=%s", ecash_relays)
        out_msg = await self.secure_transmittal(nrecipient=npub,message=token_msg,dm_relays=ecash_relays,kind=21401)
        
        return f" {amount} {out_msg}"    

    async def _async_send_ecash_dm(self,token_message: str, npub: str, ecash_relays:List[str]):
        self.logger.debug("op=send_ecash_dm status=npub npub=%s", npub)
        
        my_enc = NIP4Encrypt(self.k)
        k_to_send = Keys(pub_k=npub)
        k_to_send_pubkey_hex = k_to_send.public_key_hex()
        self.logger.debug("op=send_ecash_dm status=to_pubkey pubkey=%s", k_to_send_pubkey_hex)
        ecash_msg = token_message
        # ecash_info_encrypt = my_enc.encrypt(ecash_msg,to_pub_k=k_to_send_pubkey_hex)

        self.logger.debug("op=send_ecash_dm status=relays relays=%s", ecash_relays)
        async with ClientPool(ecash_relays) as c:
            n_msg = Event(kind=Event.KIND_ENCRYPT,
                      content=ecash_msg,
                      pub_key=k_to_send_pubkey_hex)

            # print("are we here_async?", ecash_relays)
            # returns event we to_p_tag and content encrypted
            n_msg = my_enc.encrypt_event(evt=n_msg,
                                    to_pub_k=k_to_send_pubkey_hex)

            n_msg.sign(self.privkey_hex)
            c.publish(n_msg)
        
        return f"{token_message} {ecash_msg} to {npub} {ecash_relays}"    
    
    
    async def get_ecash_dm(self):
        
        
        tags = ["#p", self.pubkey_hex]
        # last_dm = float(self.get_wallet_info("last_dm"))
        try:
            last_dm = float(self.wallet_reserved_records['last_dm'])
        except (KeyError, TypeError, ValueError) as exc:
            last_dm = 0

        # last_dm = 0
        self.logger.debug("op=get_ecash_dm status=last_dm last_dm=%s", last_dm)
        #TODO need to figure out why the kind is not 1059
        dm_filter = [{
            
            'limit': RECORD_LIMIT, 
            '#p'  :  [self.pubkey_hex],
            'since': int(last_dm +1)
            
        }]
        final_dm, tokens =await self._async_query_ecash_dm(dm_filter)
        # final_dm, tokens =asyncio.run(self._async_query_secure_ecash_dm(dm_filter))
        self.logger.debug("op=get_ecash_dm status=tokens_found count=%s", len(tokens))
        for each in  tokens:
            self.accept_token(each)
        
        self.logger.debug("op=get_ecash_dm status=final_dm final_dm=%s", final_dm)
        self.set_wallet_info("last_dm", str(final_dm))
        # self.swap_multi_each()
        
        return final_dm
    
    async def _async_query_ecash_dm(self, filter: List[dict]):
    # does a one off query to relay prints the events and exits
        my_enc = NIP4Encrypt(self.k)
        posts = ""
        tags = []
        tokens =[]
        try:
            last_dm = self.wallet_reserved_records['last_dm']
        except (KeyError, TypeError, ValueError) as exc:
            last_dm = 0
        
        final_dm = int(last_dm)
        self.logger.debug("op=query_ecash_dm status=filter filter=%s", filter)
        relay_pool = [self.home_relay] + self.relays
        self.logger.debug("op=query_ecash_dm status=relays relays=%s", relay_pool)
        async with ClientPool(relay_pool) as c:
        # async with Client(relay) as c:
            events: List[Event] = await c.query(filter)
            self.logger.debug("op=query_ecash_dm status=events count=%s", len(events))
            if events:
                self.logger.debug("op=query_ecash_dm status=events_present")
                for each in events:
                    try:
                        decrypt_content = my_enc.decrypt_event(each)
                    except (ValueError, TypeError) as exc:
                        self.logger.debug("op=query_ecash_dm status=decrypt_skip")
                        self.logger.debug("op=query_ecash_dm status=decrypt_failed event=%s error=%s", each.id, exc)
                        continue
                    
                    self.logger.debug("op=query_ecash_dm status=message event_id=%s kind=%s", each.id, each.kind)
                    # last_dm = each.created_at.timestamp() if each.created_at.timestamp() > last_dm else last_dm
                    # print("last event update", datetime.fromtimestamp(last_dm),)

                    dm_timestamp = int(each.created_at.timestamp())
                    print ("final_dm, dm_timestamp:",final_dm, dm_timestamp)
                    final_dm = dm_timestamp if dm_timestamp > final_dm else final_dm
                    print ("final_dm, dm_timestamp:",final_dm, dm_timestamp)
                    array_token = decrypt_content.content.splitlines()
                    self.logger.debug("op=query_ecash_dm status=token_lines count=%s", len(array_token))
                    
                    for each in array_token:
                        if each.startswith("cashuA"):
                            self.logger.debug("op=query_ecash_dm status=token_found")
                            token = each
                            tokens.append(token)
                            break
            else:
                self.logger.debug("op=query_ecash_dm status=no_events")
                
                
        self.logger.debug("op=query_ecash_dm status=complete last_dm=%s", last_dm)
        return final_dm, tokens          

    async def _async_query_secure_ecash_dm(self, filter: List[dict]):
    # does a one off query to relay prints the events and exits
        my_enc = NIP4Encrypt(self.k)
        posts = ""
        tags = []
        tokens =[]
        
        last_dm = self.wallet_reserved_records['last_dm']
        final_dm = int(last_dm)
        self.logger.debug("op=query_secure_ecash_dm status=filter filter=%s", filter)
        relay_pool = [self.home_relay]+self.relays
        self.logger.debug("op=query_secure_ecash_dm status=relays relays=%s", relay_pool)
        async with ClientPool(relay_pool) as c:
        # async with Client(relay) as c:
            events: List[Event] = await c.query(filter)
            self.logger.debug("op=query_secure_ecash_dm status=events count=%s", len(events))
            if events:
                self.logger.debug("op=query_secure_ecash_dm status=events_present")
                for each in events:
                   
                    
                    self.logger.debug("op=query_secure_ecash_dm status=message event_id=%s kind=%s", each.id, each.kind)
                   
            else:
                self.logger.debug("op=query_secure_ecash_dm status=no_events")
                
                
        self.logger.debug("op=query_secure_ecash_dm status=complete last_dm=%s", last_dm)
        return final_dm, tokens               
       
    async def delete_dms(self, tags):
         async with ClientPool([self.home_relay]+self.relays) as c:
            self.logger.debug("op=delete_dms status=start")
            n_msg = Event(kind=Event.KIND_DELETE,
                        content=None,
                        pub_key=self.pubkey_hex,
                        tags=tags)
            self.logger.debug("op=delete_dms status=tags tags=%s", tags)
            n_msg.sign(self.privkey_hex)
            c.publish(n_msg)
            self.logger.debug("op=delete_dms status=published")

            
    async def secure_dm(self,nrecipient:str, message: str, dm_relays: List[str]):
        try:
            if '@' in nrecipient:
                npub_hex, relays = nip05_to_npub(nrecipient)
                
               
                dm_relays = dm_relays
            else:
                npub_hex = bech32_to_hex(nrecipient)
        except (ValueError, TypeError) as exc:
            raise RuntimeError(f"Could not resolve {nrecipient}") from exc
        
        npub = hex_to_bech32(npub_hex)
        self.logger.debug("op=secure_dm status=resolved recipient=%s npub=%s relays=%s", nrecipient, npub, dm_relays)

        await self._async_secure_dm(npub_hex=npub_hex, message=message,dm_relays=dm_relays) 
        return "message sent" 
    
    async def _async_secure_dm(self, npub_hex, message:str, dm_relays: List[str]):
       
        # my_gift = GiftWrap(BasicKeySigner(self.k))
        
        my_gift = KindOtherGiftWrap(BasicKeySigner(self.k), kind_gift_wrap=1059)
        # relays = [self.home_relay]
        relays = dm_relays

        async with ClientPool(relays) as c:


            send_evt = Event(content=message,
                         tags=[
                             ['p', npub_hex]
                         ])
           
            self.logger.debug(f"sending dm to {npub_hex} via {dm_relays}")
            wrapped_evt, trans_k = await my_gift.wrap(send_evt,
                                                  to_pub_k=npub_hex)
            # wrapped_evt.sign(self.privkey_hex)
            c.publish(wrapped_evt)
            await asyncio.sleep(0.2)
                
    async def secure_transmittal(   self,
                                    nrecipient:str, 
                                    message: str,  
                                    dm_relays: List[str],
                                    kind: int=1060, ):
        try:
            if '@' in nrecipient:
                npub_hex, relays = nip05_to_npub(nrecipient)
                npub = hex_to_bech32(npub_hex)
                self.logger.debug("op=share_record status=resolved_npub npub=%s", npub)
                dm_relays = dm_relays
            else:
                npub_hex = bech32_to_hex(nrecipient)
        except (ValueError, TypeError) as exc:
            self.logger.warning("Invalid transmittal recipient=%s error=%s", nrecipient, exc)
            raise ValueError("invalid transmittal recipient") from exc
        self.logger.debug(f"send to: {nrecipient} {npub_hex}, {message} using {dm_relays}")

        await self._async_secure_transmittal(npub_hex=npub_hex, message=message, dm_relays=dm_relays, kind=kind) 
        return "message sent" 
    
    async def _async_secure_transmittal(self, npub_hex, message:str,  dm_relays: List[str],kind):
       
        my_gift = KindOtherGiftWrap(BasicKeySigner(self.k),kind_gift_wrap=kind)
        
        # relays = [self.home_relay]
        relays = dm_relays

        async with ClientPool(relays) as c:


            send_evt = Event(content=message,
                         tags=[
                             ['p', npub_hex]
                         ],
                         created_at=int(datetime.now(timezone.utc).timestamp()))
           
            self.logger.debug(f"sending dm to {npub_hex} via {dm_relays}")
            wrapped_evt, trans_k = await my_gift.wrap(send_evt,
                                                  to_pub_k=npub_hex)
            # wrapped_evt.sign(self.privkey_hex)
            c.publish(wrapped_evt)
            await asyncio.sleep(0.2)                


    def send_post(self,text):
        asyncio.run(self._async_send_post(text))  
    
    async def _async_send_post(self, text:str):
        """
            Example showing how to post a text note (Kind 1) to relay
        """

        # rnd generate some keys
        
        async with ClientPool([self.home_relay]+self.relays) as c:
        # async with Client(relay) as c:
            n_msg = Event(kind=Event.KIND_TEXT_NOTE,
                        content=text,
                        pub_key=self.pubkey_hex)
            n_msg.sign(self.privkey_hex)
            c.publish(n_msg)
            # await asyncio.sleep(1)

    async def add_tx_history(   self, 
                                tx_type:str, 
                                amount:int, 
                                comment:str = "", 
                                tendered_amount: float=None,
                                tendered_currency: str = "SAT",
                                fees: int =0,
                                invoice:str=None,
                                payment_preimage: str = None,
                                payment_hash: str = None,
                                description_hash: str = None
                                ):
        self.logger.debug("Add tx history")
        my_enc = NIP44Encrypt(self.k)
        if comment == None: #sometimes none get passed in
            comment = ""

        if tendered_amount == None:
            tendered_amount = amount
        created_at = int(datetime.now().timestamp())

        # Calculate current balance - need to refresh data

        # await self.load_data()
        

       
        tx_history = TxHistory( create_time=created_at,
                                tx_type=tx_type,
                                amount= amount,
                                comment= comment,
                                tendered_amount=tendered_amount,
                                tendered_currency=tendered_currency,
                                fees=fees,
                                current_balance=self.balance,
                                invoice=invoice,
                                payment_hash=payment_hash,
                                preimage=payment_preimage,
                                description_hash=description_hash
                               
                                 
                                )
        tx_history_str = json.dumps(tx_history.model_dump())
        tx_history_encrypt = my_enc.encrypt(tx_history_str,to_pub_k=self.pubkey_hex)
        async with ClientPool([self.home_relay]) as c:
       
            n_msg = Event(                        
                        kind=7377,
                        content=tx_history_encrypt,
                        pub_key=self.pubkey_hex)
            n_msg.sign(self.privkey_hex)
            c.publish(n_msg)
            await asyncio.sleep(0.2)
            


    async def get_tx_history(self):
        self.logger.debug("Get tx history")
        tx_history = []
        my_enc = NIP44Encrypt(self.k)
        decrypt_content = None

        filter = [{
            'limit': RECORD_LIMIT,
            'authors': [self.pubkey_hex],
            'kinds': [7377] 
            
        }]

        async with ClientPool([self.home_relay]) as c:  
            events = await c.query(filter) 
            for each in events:
                decrypt_content = my_enc.decrypt(each.content, self.pubkey_hex)
                
                json_obj = json.loads(decrypt_content) 
                # Convert create_time to datetime
                json_obj['create_time'] = datetime.fromtimestamp(json_obj['create_time']).strftime('%Y-%m-%d %H:%M:%S')
               
                tx_history.append(json_obj)         
           
        return tx_history


    async def set_wallet_config(self):
        # this function will eventually get rid of set_wallet_info_wallet("wallet")     
        m = hashlib.sha256()
        m.update(self.privkey_hex.encode())
        wallet_config_data = json.dumps(self.acorn_tags)
        m.update(wallet_config_data.encode())
                 
        label_name_hash = m.digest().hex()
        
        # print(label, label_info)
        my_enc = NIP44Encrypt(self.k)
        wallet_config_data_encrypt = my_enc.encrypt(wallet_config_data,to_pub_k=self.pubkey_hex) 
        write_relays = [self.home_relay]
        async with ClientPool(write_relays) as c:
        # async with Client(relay) as c:
            n_msg = Event(kind=17375,
                        content=wallet_config_data_encrypt,
                        pub_key=self.pubkey_hex
                        )
            
            # n_msg = my_enc.encrypt_event(evt=n_msg,
            #                         to_pub_k=self.pubkey_hex)
            
            n_msg.sign(self.privkey_hex)
            # print("label, event id:", label, n_msg.id)
            c.publish(n_msg)
            await asyncio.sleep(0.2)
            self.logger.debug(f"wrote event {wallet_config_data} to {write_relays}")

    async def get_wallet_config(self):  
        wallet_config_info = None
        events = None  
        my_enc = NIP44Encrypt(self.k)
        decrypt_content = None
        FILTER = [{
            'limit': 1,
            'authors': [self.pubkey_hex],
            'kinds': [17375] 
        }]
        async with ClientPool([self.home_relay]) as c:       
            
            events = await c.query(FILTER)
            
            self.logger.debug(f"get wallet info no of events: {len(events)}")

        if events:
            wallet_config_info = json.loads(my_enc.decrypt(events[0].content, self.pubkey_hex))
       
        
        return wallet_config_info

       

    async def set_wallet_info(self,label: str,label_info: str, replicate_relays: List[str]=None, record_kind: int=37375):
        await self._async_set_wallet_info(label,label_info,replicate_relays=replicate_relays, record_kind=record_kind)  
    
    async def _async_set_wallet_info(self, label:str, label_info: str, replicate_relays:List[str]=None, record_kind: int = 37375):

        m = hashlib.sha256()
        m.update(self.privkey_hex.encode())
        m.update(label.encode())
                 
        label_name_hash = m.digest().hex()
        
        # print(f"set wallet info {label}, {label_info}")
        my_enc = NIP44Encrypt(self.k)
        wallet_info_encrypt = my_enc.encrypt(label_info,to_pub_k=self.pubkey_hex)
        # wallet_name_encrypt = my_enc.encrypt(wallet_name,to_pub_k=self.pubkey_hex)
       
        # print(wallet_info_encrypt)

        tags = [['d',label_name_hash]]
        
        if replicate_relays:
            write_relays = replicate_relays
        else:
            write_relays = [self.home_relay]

        async with ClientPool(write_relays) as c:
        # async with Client(relay) as c:
            n_msg = Event(kind=record_kind,
                        content=wallet_info_encrypt,
                        pub_key=self.pubkey_hex,
                        tags=tags)
            
            # n_msg = my_enc.encrypt_event(evt=n_msg,
            #                         to_pub_k=self.pubkey_hex)
            
            n_msg.sign(self.privkey_hex)
            # print("label, event id:", label, n_msg.id)
            c.publish(n_msg)
            await asyncio.sleep(0.2)
            self.logger.debug(f"wrote event {label} to {write_relays}")

    async def get_label_hash(self, label:str=None):
        """get label hash used for d tag"""

        m = hashlib.sha256()
        m.update(self.privkey_hex.encode())
        m.update(label.encode())
        label_hash = m.digest().hex()

        return label_hash

    async def get_wallet_info(self, label:str=None, record_kind:int=37375, record_by_hash: str = None, record_origin: str = None):
        my_enc = NIP44Encrypt(self.k)

        if record_origin:
            label = ':'.join([record_origin,label])

        if record_by_hash:
            label_hash = record_by_hash
        else:
            m = hashlib.sha256()
            m.update(self.privkey_hex.encode())
            m.update(label.encode())
            label_hash = m.digest().hex()
        
        decrypt_content = None
        
        # d_tag_encrypt = my_enc.encrypt(d_tag,to_pub_k=self.pubkey_hex)
        # a_tag = ["a", label_hash]
        # print("a_tag:",a_tag)
       
        self.logger.debug(f"getting record for: {label}")
        
        # DEFAULT_RELAY = self.relays[0]
        FILTER = [{
            'limit': RECORD_LIMIT,
            'authors': [self.pubkey_hex],
            'kinds': [record_kind],
            '#d': [label_hash]   
            
            
        }]

        # print("are we here?", label_hash)
        event = await self._async_get_wallet_info(FILTER, label_hash)
        if not event:
            self.logger.debug(
                "op=get_wallet_info status=missing label=%s kind=%s hash=%s",
                label,
                record_kind,
                label_hash,
            )
            return None
        
        # print(event.data())
        try:
            decrypt_content = my_enc.decrypt(event.content, self.pubkey_hex)
        except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
            self.logger.warning(
                "op=get_wallet_info status=decrypt_failed label=%s kind=%s hash=%s error=%s",
                label,
                record_kind,
                label_hash,
                exc,
            )
            return None
        
        

        return decrypt_content
    
    async def delete_record(self, label:str=None, record_kind:int=37375):
        my_enc = NIP44Encrypt(self.k)

        m = hashlib.sha256()
        m.update(self.privkey_hex.encode())
        m.update(label.encode())
        label_hash = m.digest().hex()
        decrypt_content = None
        
        # d_tag_encrypt = my_enc.encrypt(d_tag,to_pub_k=self.pubkey_hex)
        # a_tag = ["a", label_hash]
        # print("a_tag:",a_tag)
       
        self.logger.debug(f"getting record for: {label}")
        
        # DEFAULT_RELAY = self.relays[0]
        FILTER = [{
            'limit': RECORD_LIMIT,
            'authors': [self.pubkey_hex],
            'kinds': [record_kind],
            '#d': [label_hash]   
            
            
        }]

        # print("are we here?", label_hash)
        event = await self._async_get_wallet_info(FILTER, label_hash)
        if not event:
            return f"{label} not found."
        
        # Do the delete here
        tags = [["e", event.id]]
        self.logger.debug("op=delete_record status=tags tags=%s", tags)
        async with ClientPool([self.home_relay]) as c:
        
            n_msg = Event(kind=Event.KIND_DELETE,
                        content=None,
                        pub_key=self.pubkey_hex,
                        tags=tags)
            n_msg.sign(self.privkey_hex)
            c.publish(n_msg)
            # added a delay here so the delete event get published
            await asyncio.sleep(1)
        
        return f"{label} deleted."    
    
    async def _async_get_wallet_info(self, filter: List[dict],label_hash):
    # does a one off query to relay prints the events and exits
        self.logger.debug(f"filter {filter}")
        # my_enc = NIP44Encrypt(self.k)
        # target_tag = filter[0]['d']
        target_tag = label_hash
        
        self.logger.debug(f"target tag: {target_tag}")
        async with ClientPool([self.home_relay]) as c:
        
            
            events = await c.query(filter)
            
            self.logger.debug(f"no of events: {len(events)}")
            
            # print(f"_async event xoxoxo: type: {type(events[0])} data: {events[0].data()}")

        if not events:
            self.logger.debug("No wallet info events found for tag=%s", target_tag)
            return None

        return events[0]


    async def set_lock(self, lock: bool):
        pass

    async def check_lock(self):
        lock_value = "FALSE"
        try:
            lock_value = await self.get_wallet_info("lock")
            # print(lock_value)
        except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as e:
            self.logger.debug("Check lock fallback; lock record unavailable: %s", e)
        if lock_value is None:
            self.logger.debug("op=check_lock status=missing_lock_record")
            lock_value = "FALSE"
        
        return str(lock_value).upper().strip() == "TRUE"

    async def acquire_lock(self, attempts=10):
        loop_count = 0
        try:
            lock_value = await self.get_wallet_info(label="lock")
        except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as e:
            self.logger.debug("Lock record missing/unreadable; defaulting to unlocked: %s", e)
            lock_value = "FALSE"
        if lock_value is None:
            self.logger.debug("op=acquire_lock status=missing_lock_record")
            lock_value = "FALSE"

        
        if str(lock_value).upper().strip() == "TRUE":
            
            self.logger.debug("op=acquire_lock status=already_locked handle=%s", self.handle)
            
            
            
            while True:                
                await asyncio.sleep(1)
                loop_count +=1
                if loop_count > attempts:
                    self.logger.warning("op=acquire_lock status=seizing_lock handle=%s attempts=%s", self.handle, attempts)
                    await self.set_wallet_info(label="lock",label_info="FALSE")
                    break
                    # raise RuntimeError(f"Could not acquire lock after {timeout} attempts")
                try:
                    lock_value = await self.get_wallet_info(label="lock")
                except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as e:
                    self.logger.debug("Lock poll failed; assuming unlocked for recovery: %s", e)
                    lock_value = "FALSE"
                if lock_value is None:
                    self.logger.debug("op=acquire_lock status=missing_lock_record_during_poll")
                    lock_value = "FALSE"
                self.logger.debug(
                    "op=acquire_lock status=poll lock_value=%s attempt=%s max_attempts=%s handle=%s",
                    lock_value,
                    loop_count,
                    attempts,
                    self.handle,
                )
                if str(lock_value).upper().strip() != 'TRUE':
                    await self.set_wallet_info(label="lock",label_info="TRUE")
                    self.logger.debug("op=acquire_lock status=acquired_after_wait handle=%s", self.handle)
                    break
        else:
            self.logger.debug("op=acquire_lock status=acquired_immediately handle=%s", self.handle)
            await self.set_wallet_info(label="lock",label_info="TRUE")
       

    async def release_lock(self):
        self.logger.debug("op=release_lock status=releasing handle=%s", self.handle)
        await self.set_wallet_info(label="lock",label_info="FALSE")
        
        pass  

        
    async def get_record(self,record_name:str=None, record_kind: int =37375, record_by_hash=None, record_origin:str = None):
        #FIXME - not sure if this function is used - get_wallet_info is doing is
        
        record_out = await self.get_wallet_info(label=record_name,record_kind=record_kind, record_by_hash=record_by_hash)
        if record_out is None:
            return None
        try:
            record_obj = json.loads(record_out)
            
        except (json.JSONDecodeError, TypeError):
            record_obj = record_out

        return record_obj

    async def get_record_safebox(self, record_name:str=None, record_kind:int=37375, record_by_hash: str = None, record_origin: str = None)->SafeboxRecord:
        my_enc = NIP44Encrypt(self.k)

        if record_origin:
            record_name = ':'.join([record_origin,record_name])

        if record_by_hash:
            label_hash = record_by_hash
        else:
            m = hashlib.sha256()
            m.update(self.privkey_hex.encode())
            m.update(record_name.encode())
            label_hash = m.digest().hex()
        
        decrypt_content = None
        
        # d_tag_encrypt = my_enc.encrypt(d_tag,to_pub_k=self.pubkey_hex)
        # a_tag = ["a", label_hash]
        # print("a_tag:",a_tag)
       
        self.logger.debug(f"getting record for: {record_name}")
        
        # DEFAULT_RELAY = self.relays[0]
        FILTER = [{
            'limit': RECORD_LIMIT,
            'authors': [self.pubkey_hex],            
            '#d': [label_hash]   
            
            
        }]

        # print("are we here?", label_hash)
        event =await self._async_get_wallet_info(FILTER, label_hash)
        if not event:
            self.logger.warning(
                "op=get_record_safebox status=missing record=%s kind=%s hash=%s",
                record_name,
                record_kind,
                label_hash,
            )
            raise ValueError(f"No event found for {record_kind} {record_name}")

        try:
            decrypt_content = my_enc.decrypt(event.content, self.pubkey_hex)
        except (ValueError, TypeError) as exc:
            self.logger.warning("op=get_record_safebox status=decrypt_failed record=%s kind=%s error=%s", record_name, record_kind, exc)
            raise ValueError(f"Could not decrypt info for: {record_name}. Does a record exist?") from exc
        
        try:
            safebox_record: SafeboxRecord = SafeboxRecord(**json.loads(decrypt_content))
            self.logger.debug(
                "op=get_record_safebox status=ok record=%s kind=%s blobref=%s",
                record_name,
                record_kind,
                safebox_record.blobref,
            )
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            self.logger.warning("op=get_record_safebox status=parse_failed record=%s kind=%s error=%s", record_name, record_kind, exc)
            raise ValueError(f"Could create safebox record: {record_name}. Does a record exist?") from exc

        return safebox_record
    
    async def get_original_blob(self, orginal_record: OriginalRecordTransfer, delete:bool = True):

        blob_data: bytes = None
        blob_type:  str = None
        self.logger.debug("op=get_original_blob status=start")
        blossom_servers = ['https://blossom.getsafebox.app']
        client = BlossomClient(nsec=orginal_record.blobnsec, default_servers=blossom_servers)
        blob_retrieve: BlossomBlob = client.get_blob(server=orginal_record.blobserver,sha256=orginal_record.blobsha256,)
        self.logger.debug("op=get_original_blob status=mime mime=%s", blob_retrieve.mime_type)
        if blob_retrieve.mime_type == "application/octet-stream":
            self.logger.debug("op=get_original_blob status=decrypting")
            try:
                blob_data = decrypt_bytes(    cipherbytes=blob_retrieve.get_bytes(),
                                                        
                                                        key=bytes.fromhex(orginal_record.encryptparms.key),
                                                        iv = bytes.fromhex(orginal_record.encryptparms.iv)
                                                    )
                blob_type = filetype.guess_mime(blob_data)
                if delete:
                    delete_result = client.delete_blob(server=orginal_record.blobserver,sha256=orginal_record.blobsha256)
                    self.logger.debug("op=get_original_blob status=deleted delete=%s", delete)
            except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as e:
                self.logger.warning("op=get_original_blob status=decrypt_failed error=%s", e)
        else:
            self.logger.debug("op=get_original_blob status=no_decrypt_needed")
            blob_data = blob_retrieve.get_bytes()


        return blob_data, blob_type
    
    async def get_record_blobdata(self, record_name:str=None, record_kind:int=37375, record_by_hash: str = None, record_origin: str = None)->bytes:
        blob_data: bytes = None
        blob_type:  str = None
        guessed_blob_type: str = None
        my_enc = NIP44Encrypt(self.k)

        blossom_servers = ['https://blossom.getsafebox.app']
        client = BlossomClient(nsec=None, default_servers=blossom_servers)

        
        if record_origin:
            record_name = ':'.join([record_origin,record_name])

        self.logger.debug("op=get_record_blobdata record=%s kind=%s", record_name, record_kind)

        if record_by_hash:
            label_hash = record_by_hash
        else:
            m = hashlib.sha256()
            m.update(self.privkey_hex.encode())
            m.update(record_name.encode())
            label_hash = m.digest().hex()
        
        decrypt_content = None
        
        # d_tag_encrypt = my_enc.encrypt(d_tag,to_pub_k=self.pubkey_hex)
        # a_tag = ["a", label_hash]
        # print("a_tag:",a_tag)
       
        self.logger.debug(f"getting record for: {record_name}")
        
        # DEFAULT_RELAY = self.relays[0]
        FILTER = [{
            'limit': RECORD_LIMIT,
            'authors': [self.pubkey_hex],
            'kinds': [record_kind],
            '#d': [label_hash]   
            
            
        }]

        event =await self._async_get_wallet_info(FILTER, label_hash)
        if not event:
            self.logger.warning(
                "op=get_record_blobdata status=missing record=%s kind=%s hash=%s",
                record_name,
                record_kind,
                label_hash,
            )
            return None, None
        
        # print(event.data())
        try:
            decrypt_content = my_enc.decrypt(event.content, self.pubkey_hex)
        except (ValueError, TypeError) as exc:
            self.logger.warning("op=get_record_blobdata status=decrypt_failed record=%s kind=%s error=%s", record_name, record_kind, exc)
            return None, None

        try:
            safebox_record: SafeboxRecord = SafeboxRecord(**json.loads(decrypt_content))
            blob_sha256 = safebox_record.blobsha256
            blob_type = safebox_record.blobtype
            if blob_type:                
                server = blossom_servers[0]
                # meta = client.head_blob(server, blobsha256)
                blob_retrieve: BlossomBlob = client.get_blob(server=server,sha256=blob_sha256,)
                
                if blob_retrieve.mime_type == "application/octet-stream":
                    try:
                        blob_data = decrypt_bytes(
                            cipherbytes=blob_retrieve.get_bytes(),
                            key=bytes.fromhex(safebox_record.encryptparms.key),
                            iv=bytes.fromhex(safebox_record.encryptparms.iv),
                        )
                    except (ValueError, TypeError) as e:
                        self.logger.warning("op=get_record_blobdata status=blob_decrypt_failed record=%s kind=%s error=%s", record_name, record_kind, e)
                else:
                    blob_data = blob_retrieve.get_bytes()
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            self.logger.warning("op=get_record_blobdata status=parse_failed record=%s kind=%s error=%s", record_name, record_kind, exc)
            return None, None

        if blob_data:
            guessed_blob_type = filetype.guess_mime(blob_data)
            guessed_extension = '.'+filetype.guess_extension(blob_data)
            extension = mimetypes.guess_extension(blob_data) or ""
            # with NamedTemporaryFile(
            #   mode="wb",
            #    suffix=guessed_extension,
            #    dir = './tmp',
            #    delete=False
            #) as tmp:
            #    tmp.write(blob_data)
            #    tmp_path = tmp.name
            self.logger.debug(
                "op=get_record_blobdata status=ok record=%s kind=%s mime=%s",
                record_name,
                record_kind,
                guessed_blob_type,
            )

        return guessed_blob_type, blob_data

   
    def get_proofs(self):
        #TODO add in a group by keyset

        
        return self.proofs
    
    async def get_ecash_latest(self,since: int|None = None, relays: List[str]|None=None, nonce:str = None):
        ecash_out = []
        ecash_record = {}
        latest_dm = 0
        since_now = int(datetime.now(timezone.utc).timestamp())
      
        if not relays:
                relays = self.relays
        try:
            ecash_latest_raw = await self.get_wallet_info("ecash_latest", record_kind=37376)
            ecash_latest = int(ecash_latest_raw) if ecash_latest_raw is not None else 0
            
            self.logger.debug("op=get_ecash_latest status=start ecash_latest=%s relays=%s", ecash_latest, relays)
           
            
            user_records = await self.get_user_records(record_kind=21401, relays=relays, since=ecash_latest+1, reverse=True)
            
           

            for each in user_records:
                ecash_record["ecash"] = each["payload"]
                ecash_record["timestamp"] = each["timestamp"]
               
                # ecash_out.append(ecash_record)
                latest_dm = each["timestamp"] 
                self.logger.debug(
                    "op=get_ecash_latest status=processing age_seconds=%s timestamp=%s",
                    since_now - latest_dm,
                    latest_dm,
                )
                try:
                    ecash_nembed = parse_nembed_compressed(each["payload"])                    
                    token_to_redeem = ecash_nembed["token"]
                    receive_nonce = ecash_nembed.get("nonce", None)
                    tendered_amount = ecash_nembed.get("tendered_amount", None)
                    tendered_currency = ecash_nembed.get("tendered_currency", "SAT")
                    self.logger.debug(
                        "op=get_ecash_latest status=parsed_token nonce_match=%s",
                        bool(nonce and receive_nonce == nonce),
                    )
                    if nonce and receive_nonce == nonce:
                        self.logger.debug("op=get_ecash_latest status=matching_nonce")
                    else:
                        self.logger.debug("op=get_ecash_latest status=different_nonce")

                    msg_out, token_amount = await self.accept_token(
                        cashu_token=token_to_redeem,
                        comment=ecash_nembed["comment"],
                        tendered_amount=tendered_amount,
                        tendered_currency=tendered_currency,
                    )

                    if token_to_redeem == "nsf":
                        pass
                        self.logger.info("op=get_ecash_latest status=nsf_token")
                        # tendered_amount = ecash_nembed.get("tendered_amount", None)
                        # tendered_currency = ecash_nembed.get("tendered_currency", "SAT")
                        # ecash_out.append(("ERROR", 0,"SAT"))
                        # await self.add_tx_history(tx_type='X',amount=0, comment="PAYMENT UNSUCCESSFUL", tendered_amount=0, tendered_currency="NSF" )
                        ecash_out.append(("ADVISORY", 0, "SAT", "NSF", nonce, 0))
                    else:
                        self.logger.info("op=get_ecash_latest status=redeemed_ok")
                        self.logger.debug("op=get_ecash_latest status=record_payment tendered_currency=%s", tendered_currency)
                        # await self.add_tx_history(tx_type='C',amount=token_amount, comment=ecash_nembed["comment"], tendered_amount=tendered_amount, tendered_currency=tendered_currency )
                        ecash_out.append(("OK", tendered_amount, tendered_currency, "Payment OK", nonce, token_amount))
                    
                    
                except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
                    ecash_out.append(("ERROR", 0,"SAT", "Redemption"))
                    pass
                
                   
        except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
            self.logger.debug("op=get_ecash_latest status=init_latest_record error=%s", exc)
            await self.set_wallet_info("ecash_latest", "0", record_kind=37376)
            
        self.logger.debug("op=get_ecash_latest status=complete latest_dm=%s", latest_dm)
        if latest_dm > 0:
            await self.set_wallet_info("ecash_latest", str(latest_dm), record_kind=37376)
        # print(f"since now: {since_now} {latest_dm} {since_now-latest_dm}")
        # print(f"total messages: {len(ecash_out)} received for {self.handle}")
        

        return ecash_out

        
        
    def set_index_info(self,index_info: str):
        asyncio.run(self._async_set_index_info(index_info))  
    
    async def _async_set_index_info(self, index_info: str):
        
        self.logger.debug("op=set_index_info status=update")
        my_enc = NIP44Encrypt(self.k)
        index_info_encrypt = my_enc.encrypt(index_info,to_pub_k=self.pubkey_hex)
    

        async with ClientPool([self.home_relay]) as c:
        # async with Client(relay) as c:
            n_msg = Event(kind=17375,
                        content=index_info_encrypt,
                        pub_key=self.pubkey_hex
                        )
            
            # n_msg = my_enc.encrypt_event(evt=n_msg,
            #                         to_pub_k=self.pubkey_hex)
            
            n_msg.sign(self.privkey_hex)
            self.logger.debug("op=set_index_info status=published event_id=%s", n_msg.id)
            c.publish(n_msg)
            # await asyncio.sleep(1)

    def get_index_info(self):
        my_enc = NIP44Encrypt(self.k)
        
        DEFAULT_RELAY = self.relays[0]
        FILTER = [{
            'limit': RECORD_LIMIT,
            'authors': [self.pubkey_hex],
            'kinds': [17375]
            
        }]
        try:
            event =asyncio.run(self._async_get_index_info(FILTER))
        
            # print(event.data())
            decrypt_content = my_enc.decrypt(event.content, self.pubkey_hex)

            index_obj = json.loads(decrypt_content)

            return index_obj
        except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
            return None
    
    async def _async_get_index_info(self, filter: List[dict]):
    # does a one off query to relay prints the events and exits
        # print("filter", filter[0]['d'])
        my_enc = NIP44Encrypt(self.k)
        
        event_select = None
        async with ClientPool([self.home_relay]) as c:
        # async with Client(relay) as c:
            
            events = await c.query(filter)
            
            # print(f"{filter} events: {len(events)}")
  
            
            return events[0]
        
    async def transfer_blob(
        self,
        record_name,
        record_kind: int = 37375,
        record_origin: str = None,
        blobxfer: str = None,
    ) -> Dict[str, Any]:
        """Transfer source blob to wallet blob store and attach metadata to record."""
        self.logger.debug("op=transfer_blob status=start record=%s kind=%s", record_name, record_kind)
        blossom_servers = ['https://blossom.getsafebox.app']
        blossom_server = 'https://blossom.getsafebox.app'

        if record_origin:
            record_name = ':'.join([record_origin, record_name])

        if not blobxfer:
            return {"status": "SKIPPED", "reason": "no_blobxfer"}

        try:
            blobxfer_obj: OriginalRecordTransfer = OriginalRecordTransfer.model_validate_json(blobxfer)
        except (ValueError, TypeError) as exc:
            self.logger.warning(
                "op=transfer_blob status=invalid_blobxfer record=%s kind=%s error=%s",
                record_name,
                record_kind,
                exc,
            )
            return {"status": "INVALID_BLOBXFER", "reason": str(exc)}

        self.logger.debug("op=transfer_blob status=validated record=%s kind=%s", record_name, record_kind)
        try:
            client_xfer = BlossomClient(nsec=blobxfer_obj.blobnsec, default_servers=blossom_servers)
            try:
                blob_retrieve: BlossomBlob = client_xfer.get_blob(
                    server=blobxfer_obj.blobserver,
                    sha256=blobxfer_obj.blobsha256,
                )
            except Exception as exc:
                if exc.__class__.__name__ == "BlobNotFound":
                    self.logger.info(
                        "op=transfer_blob status=source_missing record=%s kind=%s sha256=%s",
                        record_name,
                        record_kind,
                        blobxfer_obj.blobsha256,
                    )
                    return {"status": "NOT_FOUND", "reason": "source_blob_missing"}
                self.logger.warning(
                    "op=transfer_blob status=fetch_failed record=%s kind=%s error=%s",
                    record_name,
                    record_kind,
                    exc,
                )
                return {"status": "FETCH_FAILED", "reason": str(exc)}

            try:
                delete_result = client_xfer.delete_blob(
                    server=blobxfer_obj.blobserver,
                    sha256=blobxfer_obj.blobsha256,
                )
                self.logger.debug("op=transfer_blob status=source_deleted record=%s result=%s", record_name, delete_result)
            except Exception as exc:
                self.logger.warning(
                    "op=transfer_blob status=source_delete_failed record=%s kind=%s error=%s",
                    record_name,
                    record_kind,
                    exc,
                )

            if blob_retrieve.mime_type != "application/octet-stream":
                return {"status": "INVALID_SOURCE_MIME", "reason": blob_retrieve.mime_type}

            try:
                blob_data = decrypt_bytes(
                    cipherbytes=blob_retrieve.get_bytes(),
                    key=bytes.fromhex(blobxfer_obj.encryptparms.key),
                    iv=bytes.fromhex(blobxfer_obj.encryptparms.iv),
                )
            except (ValueError, TypeError) as exc:
                self.logger.warning("op=transfer_blob status=decrypt_failed record=%s error=%s", record_name, exc)
                return {"status": "DECRYPT_FAILED", "reason": str(exc)}

            resultsha256 = hashlib.sha256(blob_data).hexdigest()
            if resultsha256 != blobxfer_obj.origsha256:
                self.logger.warning(
                    "op=transfer_blob status=hash_mismatch record=%s expected=%s got=%s",
                    record_name,
                    blobxfer_obj.origsha256,
                    resultsha256,
                )
                return {"status": "HASH_MISMATCH", "reason": "transferred_hash_mismatch"}

            guessed_blob_type = filetype.guess_mime(blob_data) or "application/octet-stream"
            self.logger.debug("op=transfer_blob status=decrypted record=%s mime=%s", record_name, guessed_blob_type)

            safebox_record = await self.get_record_safebox(record_name=record_name, record_kind=record_kind)
            self.logger.debug("op=transfer_blob status=loaded_record record=%s", record_name)

            blob_key = os.urandom(32)
            encrypt_result: EncryptionResult = encrypt_bytes(blob_data, blob_key)
            encrypt_parms = EncryptionParms(
                alg=encrypt_result.alg,
                key=blob_key.hex(),
                iv=encrypt_result.iv.hex(),
            )

            final_blob_data = encrypt_result.cipherbytes
            client = BlossomClient(nsec=self.privkey_bech32, default_servers=[blossom_server])
            upload_result = client.upload_blob(
                blossom_server,
                data=final_blob_data,
                description='Blob to server',
            )
            sha256 = upload_result['sha256']
            blob_ref = upload_result.get('url', f"{blossom_server}/{sha256}")

            self.logger.debug("op=transfer_blob status=uploaded record=%s sha256=%s", record_name, sha256)
            updated_safebox_record = SafeboxRecord(
                tag=safebox_record.tag,
                type=safebox_record.type,
                payload=safebox_record.payload,
                blobref=blob_ref,
                blobtype=guessed_blob_type,
                blobsha256=sha256,
                origsha256=blobxfer_obj.origsha256,
                encryptparms=encrypt_parms,
            )
            record_json_str = updated_safebox_record.model_dump_json()

            await self.update_tags([["user_record", record_name, "generic"]])
            await self.set_wallet_info(record_name, record_json_str, record_kind=record_kind)
            await self.set_wallet_config()
            return {"status": "OK", "blobref": blob_ref, "blobsha256": sha256}

        except (ValueError, TypeError, RuntimeError, KeyError) as exc:
            self.logger.warning(
                "op=transfer_blob status=processing_failed record=%s kind=%s error=%s",
                record_name,
                record_kind,
                exc,
            )
            return {"status": "PROCESSING_FAILED", "reason": str(exc)}

    async def put_record(self,record_name, record_value, record_type="generic", record_kind: int = 37375, record_origin: str = None, blob_data: bytes = None):

        blossom_server = "https://blossom.getsafebox.app"
        mime_type_guess = None
        origsha256 = None
        encrypt_parms = None


        if record_origin:
            record_name = ':'.join([record_origin,record_name])



        self.logger.debug("op=put_record status=start record=%s kind=%s", record_name, record_kind)
        if record_name in self.RESERVED_RECORDS:
            self.logger.debug("op=put_record status=reserved_record record=%s", record_name)
            await self.set_wallet_info(record_name,record_value,record_kind=record_kind)
            return record_name
        else:
            blob_ref = None
            blob_type = None
            sha256 = None
            if blob_data:
                self.logger.debug("op=put_record status=blob_upload_start")
                origsha256 = hashlib.sha256(blob_data).hexdigest()
                self.logger.debug("op=put_record status=origsha256")
                mime_type_guess = filetype.guess(blob_data).mime
                self.logger.debug("op=put_record status=mime mime=%s", mime_type_guess)
                blob_key = os.urandom(32)  # 256-bit key
                
                encrypt_result:EncryptionResult = encrypt_bytes(blob_data, blob_key)
                encrypt_parms = EncryptionParms(alg=encrypt_result.alg,key=blob_key.hex(),iv=encrypt_result.iv.hex())
        
                # final_blob_data = blob_data
                final_blob_data = encrypt_result.cipherbytes

                client = BlossomClient(nsec=self.privkey_bech32, default_servers=[blossom_server])
                upload_result = client.upload_blob(blossom_server, data=final_blob_data,
                             description='Blob to server')
                sha256 = upload_result['sha256']
                blob_ref = upload_result.get('url', f"{blossom_server}/{sha256}")
                # blob_ref = upload_result['sha256']
                blob_type = upload_result['type']
                self.logger.debug("op=put_record status=blob_uploaded sha256=%s", sha256)
                
            record_obj = SafeboxRecord(tag=[record_name], type=record_type,payload=record_value, blobref=blob_ref, blobtype=mime_type_guess, blobsha256=sha256, origsha256=origsha256, encryptparms=encrypt_parms)
            self.logger.debug("op=put_record status=record_serialized")
            record_json_str = record_obj.model_dump_json()

            await self.update_tags([["user_record",record_name,record_type]])

            await self.set_wallet_info(record_name,record_json_str,record_kind=record_kind)
            # print(user_records)
            await   self.set_wallet_config()
            return record_name
    
    async def update_tags(self,tag_values):
        
        for tag_value in tag_values:
            if tag_value[0]=="user_record":
                if tag_value in self.acorn_tags:
                    self.logger.debug("op=update_tags status=user_record_exists")
                else:
                    self.acorn_tags.append(tag_value)
            elif tag_value[0]=="balance":
                for index, each in enumerate(self.acorn_tags):
                    if each[0]=="balance":
                        self.acorn_tags[index]=tag_value
            elif tag_value[0] == "owner":
                for index, each in enumerate(self.acorn_tags):
                    if each[0]=="owner":
                        self.acorn_tags[index]=tag_value
            elif tag_value[0] == "local_currency":
                for index, each in enumerate(self.acorn_tags):
                    if each[0]=="local_currency":
                        self.acorn_tags[index]=tag_value
            elif tag_value[0] == "ecash_latest":
                for index, each in enumerate(self.acorn_tags):
                    if each[0]=="ecash_latest":
                        self.acorn_tags[index]=tag_value
            
        
        # print(f"update tags: {self.acorn_tags}")
        await self.set_wallet_info(label=self.name,label_info=json.dumps(self.acorn_tags))

    async def _mint_proofs(self, quote:str, amount:int, mint:str=None):
        # print("mint proofs")
        lock_acquired = False
        try:
            await self.acquire_lock()
            lock_acquired = True
            headers = { "Content-Type": "application/json"}
            timeout = httpx.Timeout(20.0, connect=5.0)
            if mint:
                keyset_url = f"https://{mint}/v1/keysets"
            else:
                keyset_url = f"{self.home_mint}/v1/keysets"

            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(keyset_url, headers=headers)
                response.raise_for_status()
                keysets_json = response.json()

                keyset = keysets_json['keysets'][0]['id']
                keysets_obj = KeysetsResponse(**keysets_json)

            if mint:
                self.known_mints[keysets_obj.keysets[0].id]= f"https://{mint}"
            else:
                self.known_mints[keysets_obj.keysets[0].id]= self.home_mint

            # print("id:", keysets_obj.keysets[0].id)

            blinded_messages=[]
            blinded_values =[]
            powers_of_2 = powers_of_2_sum(int(amount))
            
            
            for each in powers_of_2:
                secret = secrets.token_hex(32)
                B_, r, Y = step1_alice(secret)
                blinded_values.append((B_,r, secret, Y))
                
                blinded_messages.append(    BlindedMessage( amount=each,
                                                            id=keyset,
                                                            B_=B_.serialize().hex(),
                                                            Y = Y.serialize().hex(),
                                                            ).model_dump()
                                                            
                                        )
            # print("blinded values, blinded messages:", blinded_values, blinded_messages)
            if mint:
                mint_url = f"https://{mint}/v1/mint/bolt11"
            else:
                mint_url = f"{self.home_mint}/v1/mint/bolt11"


            # blinded_message = BlindedMessage(amount=amount,id=keyset,B_=B_.serialize().hex())
            # print(blinded_message)
            request_body = {
                                "quote"     : quote,
                                "outputs"   : blinded_messages
                            }
            # print(request_body)
            
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(mint_url, json=request_body, headers=headers)
                response.raise_for_status()
                promises = response.json()['signatures']
                # print("promises:", promises)
           

            
            if mint:
                mint_key_url = f"https://{mint}/v1/keys/{keyset}"
            else:
                mint_key_url = f"{self.home_mint}/v1/keys/{keyset}"

            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(mint_key_url, headers=headers)
                response.raise_for_status()
                keys = response.json()["keysets"][0]["keys"]

            proof_objs = []
            i = 0
            
            for each in promises:
                pub_key_c = PublicKey()
                # print("each:", each['C_'])
                pub_key_c.deserialize(unhexlify(each['C_']))
                promise_amount = each['amount']
                A = keys[str(int(promise_amount))]
                # A = keys[str(j)]
                pub_key_a = PublicKey()
                pub_key_a.deserialize(unhexlify(A))
                r = blinded_values[i][1]
                # print(pub_key_c, promise_amount,A, r)
                C = step3_alice(pub_key_c,r,pub_key_a)
                
                proof = Proof ( amount= promise_amount,
                            id = keyset,
                            secret=blinded_values[i][2],
                            C=C.serialize().hex(),
                            Y=blinded_values[i][3].serialize().hex()
                )

                proof_objs.append(proof)
                
                i+=1
            
            self.logger.debug(f"Adding proofs from mint: {proof_objs}")

            #TODO change this to write_proofs
            await self.add_proofs_obj(proof_objs)
        except (httpx.HTTPError, KeyError, ValueError, TypeError) as e:
            self.logger.error(
                "op=mint_proofs quote=%s amount=%s mint=%s error=%s",
                quote,
                amount,
                mint,
                e,
            )
            raise RuntimeError(f"Error in mint_proofs {e}") from e
        
        finally:
            if lock_acquired:
                await self.release_lock()
        
        return True

    async def check_quote(self, quote:str, amount:int, mint:str = None):
        self.logger.debug("op=check_quote quote=%s amount=%s mint=%s", quote, amount, mint)
        
        

        success_mint = True  
        lninvoice = None  
          
        if mint:
            url = f"https://{mint}/v1/mint/quote/bolt11/{quote}"
        else:
             url = f"{self.home_mint}/v1/mint/quote/bolt11/{quote}" 

        self.logger.debug(f"mint quote: {url}")

        headers = { "Content-Type": "application/json"}
        timeout = httpx.Timeout(10.0, connect=5.0)

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                mint_quote = mintQuote(**response.json())
        except (httpx.HTTPError, ValueError, TypeError, KeyError) as exc:
            self.logger.warning(
                "op=check_quote status=failed quote=%s amount=%s mint=%s error=%s",
                quote,
                amount,
                mint,
                exc,
            )
            return False, None

        if mint_quote.paid == True:
            self.logger.debug("op=check_quote status=paid quote=%s", quote)
            success_mint = await self._mint_proofs(mint_quote.quote, amount, mint)
            lninvoice = mint_quote.request
        else:
            success_mint = False
      

        return success_mint, lninvoice
        
       
        # return await self._check_quote(quote, amount,mint)
    
    async def async_deposit(self, amount:int, mint:str = None)->cliQuote:
        
        #FIXME parameter passing with scheme
        if mint:
            mint = mint.replace("https://","")
            url = f"https://{mint}/v1/mint/quote/bolt11"
        else:
            url = f"{self.home_mint}/v1/mint/quote/bolt11"
       
        headers = { "Content-Type": "application/json"}
        mint_request = mintRequest(amount=amount)
        payload_json = mint_request.model_dump_json()
        timeout = httpx.Timeout(10.0, connect=5.0)

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(url, data=payload_json, headers=headers)
                response.raise_for_status()
                response_json = response.json()
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            self.logger.error(
                "op=async_deposit amount=%s mint=%s url=%s error=%s",
                amount,
                mint,
                url,
                exc,
            )
            raise RuntimeError(f"Deposit quote request failed: {exc}") from exc

        mint_quote = mintQuote(**response_json)
        invoice = response_json['request']
        quote = response_json['quote']
        self.logger.debug("op=async_deposit quote_received amount=%s mint_url=%s", amount, url)
        # print(self.powers_of_2_sum(int(amount)))
        # add quote as a replaceable event

        wallet_quote_list =[]
        
        success, lninvoice = await self.poll_for_payment(quote=quote, amount=amount, mint=url)

        return success, lninvoice 
        
       
    
    def deposit(self, amount:int, mint:str = None)->cliQuote:
        
        #FIXME parameter passing with scheme
        try:
            if mint:
                mint = mint.replace("https://","")
                url = f"https://{mint}/v1/mint/quote/bolt11"
            else:
                url = f"{self.home_mint}/v1/mint/quote/bolt11"
            
            headers = { "Content-Type": "application/json"}
            mint_request = mintRequest(amount=amount)
            mint_request_dump = mint_request.model_dump()
            payload_json = mint_request.model_dump_json()
            response = requests.post(url, data=payload_json, headers=headers)
            # print(response.json())
            mint_quote = mintQuote(**response.json())
            # print(mint_quote)
            invoice = response.json()['request']
            quote = response.json()['quote']
            self.logger.debug("op=deposit status=invoice_received")
            # print(self.powers_of_2_sum(int(amount)))
            # add quote as a replaceable event

            wallet_quote_list =[]
            

        except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as e:
            raise RuntimeError(f"The is a error with the deposit {e}")
         
        return cliQuote(invoice=invoice, quote=quote, mint_url=url)
        # return f"Please pay invoice \n{invoice} \nfor quote: \n{quote}."
    
    async def poll_for_payment(self, quote:str, amount: int, mint:str=None):
        start_time = time()  # Record the start time
        end_time = start_time + 120  # Set the loop to run for 120 seconds
        success = False
        lninvoice = None
        #FIXME figure out the prefit
        if mint:
            mint = mint.replace("https://","")

        while time() < end_time:
            self.logger.debug("op=poll_for_payment quote=%s amount=%s mint=%s", quote, amount, mint)
            success, lninvoice = await self.check_quote(quote=quote, amount=amount, mint=mint)
            if success:
                self.logger.info("op=poll_for_payment status=paid quote=%s amount=%s", quote, amount)
                break
            elapsed = time() - start_time
            # Faster polling in the early window for better UX, then taper.
            if elapsed < 20:
                await asyncio.sleep(1)
            elif elapsed < 60:
                await asyncio.sleep(2)
            else:
                await asyncio.sleep(3)

        self.logger.debug("op=poll_for_payment status=done quote=%s", quote)
        if not success:
            self.logger.warning("op=poll_for_payment status=timeout quote=%s amount=%s", quote, amount)
            raise TimeoutError("Polling has timed out.")
        return success, lninvoice
        
    
    def withdraw(self, lninvoice:str):

        msg_out = self.pay_multi_invoice(lninvoice=lninvoice)
        
        return msg_out

    async def add_proofs_obj(self,proofs_arg: List[Proof], replicate_relays: List[str]=None):
        
        records_to_write = []
        # my_enc = NIP44Encrypt(self.k)
        my_enc = ExtendedNIP44Encrypt(self.k)

        if replicate_relays:
            write_relays = replicate_relays
            
        else:
            write_relays = [self.home_relay]

        # Create the format for NIP 60 proofs
        #FIXME This is where the swap error handling needs to be fixed
        # proofs_arg[0].id - is null sometimes
        try:
            nip60_proofs = NIP60Proofs(mint=self.known_mints[proofs_arg[0].id])
            for each in proofs_arg:
                nip60_proofs.proofs.append(each)
    
            #TODO Do some error checking on size of record

            record = nip60_proofs.model_dump_json()
            self.logger.debug("op=add_proofs_obj status=record_length length=%s proofs=%s", len(record), len(nip60_proofs.proofs))

            if len(record) > self.max_proof_event_size:
                self.logger.warning("Record length %s is greater than max, splitting proofs", len(record))
                self.logger.warning(f"Record length {len(record)} is greater than max, splitting proofs")
                split_proofs = split_proofs_instance(original=nip60_proofs, num_splits=math.ceil(len(record)/self.max_proof_event_size))
                
                for each in split_proofs:
                    records_to_write.append(each.model_dump_json())
            else:
                records_to_write =[record]
            

            for each in records_to_write:
                payload_encrypt = my_enc.encrypt(each,to_pub_k=self.pubkey_hex)
            
                async with ClientPool(write_relays) as c:
                    
                    #FIXME kind
                    n_msg = Event(kind=7375,
                                content=payload_encrypt,
                                pub_key=self.pubkey_hex)
                    n_msg.sign(self.privkey_hex)
                    self.logger.debug(f"proof event content {n_msg.kind} {record}")
                    c.publish(n_msg)
                    await asyncio.sleep(0.2)
        except (ValueError, TypeError, json.JSONDecodeError) as e:
            self.logger.error("op=add_proofs_obj status=failed proofs=%s error=%s", len(proofs_arg), e)
            raise RuntimeError(f"Error writing proofs: {e}") from e
        
        return



    async def write_proofs(self, replicate_relays: List[str]=None):
        # make sure have latest kind
        #TODO Need to add some error checking


        self.logger.debug(f"writing proofs ")
        try:
            old_filter = [{
                'limit': RECORD_LIMIT,
                'authors': [self.pubkey_hex],
                'kinds': [7375]
            }]
            old_proof_event_ids: List[str] = []
            async with ClientPool([self.home_relay]) as c:
                existing_events = await c.query(old_filter)
                old_proof_event_ids = [event.id for event in existing_events]

            # get proofs by keyset
            all_proofs, _amount = self._proofs_by_keyset()
            
            for key, value in all_proofs.items():

                await self.add_proofs_obj(value) 

            if old_proof_event_ids:
                await self._async_delete_events_by_ids(old_proof_event_ids, record_kind=7375)

            await self._load_proofs()
        except (ValueError, TypeError, RuntimeError, httpx.HTTPError) as e:
            self.logger.error("op=write_proofs status=failed error=%s", e)
            raise RuntimeError(f"error writing proofs: {e}") from e

        
        return

    async def _async_add_proofs_obj(self,proofs_arg: List[Proofs], replicate_relays: List[str]=None):
        # make sure have latest kind
        #TODO this is a workaround



        proofs_to_store = json.dump
        for each in proofs_arg:
            pass
            proof_to_store = [each.model_dump()]
            text = json.dumps(proof_to_store)
            await self._async_add_proofs(text, replicate_relays)
        
        return

    
    async def _async_add_proofs(self, text:str, replicate_relays: List[str]=None):
        """
            Example showing how to post a text note (Kind 1) to relay
        """
        self.logger.debug("op=add_proofs status=text_length length=%s", len(text))
        my_enc = NIP44Encrypt(self.k)
        payload_encrypt = my_enc.encrypt(text,to_pub_k=self.pubkey_hex)
        
        if replicate_relays:
            write_relays = replicate_relays
            
        else:
            write_relays = [self.home_relay]


        async with ClientPool(write_relays) as c:
            
            #FIXME kind
            n_msg = Event(kind=7375,
                        content=payload_encrypt,
                        pub_key=self.pubkey_hex)
            n_msg.sign(self.privkey_hex)
            self.logger.debug(f"proof event content {n_msg.kind} {text}")
            c.publish(n_msg)
            await asyncio.sleep(0.2)



    async def add_proof_event(self, proofs:List[Proof]):
        await self._async_add_proof_event(proofs)  
    
    async def _async_add_proof_event(self, proofs: List[Proof]):
        """
            Example showing how to post a text note (Kind 1) to relay
        """
        proofs_for_event = []
        
        for proof in proofs:
            proofs_for_event.append(proof.model_dump())
        
        text = json.dumps(proofs_for_event)

        my_enc = NIP44Encrypt(self.k)
        payload_encrypt = my_enc.encrypt(text,to_pub_k=self.pubkey_hex)
        
        async with ClientPool([self.home_relay]) as c:
        # async with Client(relay) as c:
        #FIXME KIND
            n_msg = Event(kind=7375,
                        content=payload_encrypt,
                        pub_key=self.pubkey_hex)
            n_msg.sign(self.privkey_hex)
            c.publish(n_msg)
            # await asyncio.sleep(1) 
    
    def _load_record_events(self):
        exists = False
        FILTER = [{
            'limit': RECORD_LIMIT,
            'authors': [self.pubkey_hex],
            'kinds': [37375]
        }]
        exists =asyncio.run(self._async_load_record_events(FILTER))
        self.profile_found_on_home_relay = exists
        return exists
    
    async def _async_load_record_events(self, filter: List[dict]):
    # does a query for record events, does not decrypt
        exists = False
       
        async with ClientPool([self.home_relay]) as c:
            record_events =[]
            my_enc = NIP44Encrypt(self.k)
            # get reserved records  
            reverse_hash = {}        
            record_events = await c.query(filter)
            if len(record_events) == 0:
                # raise ValueError(f"There is no profile on home relay: {self.home_relay}")
                return False
            
            self.logger.debug(f"Load record events: {len(record_events)}")
            for each in self.RESERVED_RECORDS:
                m = hashlib.sha256()
                m.update(self.privkey_hex.encode())
                m.update(each.encode())
                label_hash = m.digest().hex()
                # print(each, label_hash)
                reverse_hash[label_hash]=each

                for each_record in record_events:                
                    for each_tag in each_record.tags:            
                        if each_tag[0] == 'd':
                            
                            try:
                                decrypt_content = my_enc.decrypt(each_record.content, self.pubkey_hex)
                            except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
                                decrypt_content = "could not decrpyt"
                                                        
                            reserved_record_label = reverse_hash.get(each_tag[1])
                            
                            if reverse_hash.get(each_tag[1]):
                                self.wallet_reserved_records[reserved_record_label]=decrypt_content
                                
                
                    
        self.logger.debug(f"Finished loading reserved records of {len(record_events)} events")   
        return True
    
    async def _load_proofs(self):
        
        
        FILTER = [{
            'limit': RECORD_LIMIT,
            'authors': [self.pubkey_hex],
            'kinds': [7375]
        }]
       
        content = await self._async_load_proofs(FILTER)

        
        
        return content
    


    async def _async_load_proofs(self, filter: List[dict]):
    # does a one off query to relay prints the events and exits
        my_enc = NIP44Encrypt(self.k)
        proofs = ""
        self.proofs = []
        async with ClientPool([self.home_relay]) as c:
        # async with Client(relay) as c:
            events = await c.query(filter)
            self.events = len(events)
            
            for each_event in events:
                # print(type(each_event.id), each_event.id)
                self.proof_event_ids.append(each_event.id)
                proof_event = proofEvent(id=each_event.id)
                try:
                    content = my_enc.decrypt(each_event.content, self.pubkey_hex)
                    content_json = json.loads(content)
                    # print("event_id:", each_event.id)
                    
                    
                        
                    # proof = Proof(**each_content)
                    nip60_proofs = NIP60Proofs(**content_json)
                    # self.logger.debug(f"load nip60 proofs")
                    self.known_mints[nip60_proofs.proofs[0]['id']]= nip60_proofs.mint
                    for each in nip60_proofs.proofs:
                        self.proofs.append(each)
                        proof_event.proofs.append(each)
                        # print(proof.amount, proof.secret)
                    # self.proof_events.proof_events.append(proof_event)          
                except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
                    content = each.content

                
                proofs += str(content) +"\n\n"

            
            balance = 0
            for each in self.proofs:
                # print(each.amount, each.secret)
                balance += each.amount
            self.balance = balance
            # self.logger.debug(f"balance from loaded proofs: {balance}")
            # print("proofs:", len(self.proofs))

                
            # print("let's dedup proofs just in case")
            #TODO this is to mitigate some dup errors reading from multiple relays
            self.proofs = list(set(self.proofs))     
           
            
            return proofs
    


    async def delete_proof_events(self):
        await self._async_delete_proof_events()

    def _proofs_by_keyset(self):
        all_proofs = {}
        keyset_amounts = {}
        for each in self.proofs:
            # print(each.id)
            if each.id not in all_proofs:                
                all_proofs[each.id] = [each]
            else:
                all_proofs[each.id].append(each)  
        
        # calculate amounts for each keyset
        for key in all_proofs: 
            amount=0
            for each in all_proofs[key]:
                amount +=each.amount        
            keyset_amounts[key]=amount
        # print(keyset_amounts)
        return all_proofs, keyset_amounts



    async def pay_multi(  self, 
                    amount:int, 
                    lnaddress: str, 
                    comment: str = "Paid!",
                    tendered_amount: float = None,
                    tendered_currency: str = "SAT"
                    ): 
                    
        
        # print("pay from multiple mints")
        available_amount = 0
        chosen_keyset = None
        chosen_keysets = [] # This is for multipath payments
        multi_path = False
        keyset_proofs,keyset_amounts = self._proofs_by_keyset()
        headers = { "Content-Type": "application/json"}
        msg_out = "Paid"
        final_fees = 0

        try:
            timeout = httpx.Timeout(30.0, connect=5.0)
            # await self.acquire_lock()
            callback, safebox, nonce = lightning_address_pay(amount, lnaddress,comment=comment)         
            pr = callback['pr'] 
            self.logger.debug("op=pay_multi status=lookup lnaddress=%s safebox=%s", lnaddress, safebox)

            if safebox:
                self.logger.info("op=pay_multi status=direct_safebox nonce=%s", nonce)
                ln_parts = lnaddress.split('@')
                local_part = ln_parts[0]
                safebox_to_call = f"https://{ln_parts[1]}/.well-known/safebox.json/{ln_parts[0].lower()}"
                self.logger.debug("op=pay_multi status=resolve_safebox url=%s", safebox_to_call)
                async with httpx.AsyncClient(timeout=timeout) as client:
                    response = await client.get(safebox_to_call)
                    response.raise_for_status()
                    response = response.json()
                pubkey = response.get("pubkey",None)
                nrecipient = hex_to_bech32(pubkey)
                relays = response.get("relays", None)
                ecash_relays = response.get("ecash_relays", relays)
                self.logger.debug("op=pay_multi status=transmit_ecash relays=%s", ecash_relays)
                cashu_token = await self.issue_token(amount=amount, comment=comment)
                pay_obj =   {"token": cashu_token,
                             "amount": amount, 
                             "comment": comment,
                             "tendered_amount": tendered_amount,
                             "tendered_currency": tendered_currency,
                             "nonce": nonce}
                nembed_to_send = create_nembed_compressed(pay_obj)
                self.logger.debug("op=pay_multi status=nembed_created")
                
                

                await self.secure_transmittal(nrecipient=nrecipient,message=nembed_to_send,dm_relays=ecash_relays,kind=21401)
                await self.release_lock()
                # await self.add_tx_history(tx_type='D', amount=amount, comment=comment,
                # tendered_amount=tendered_amount, tendered_currency=tendered_currency, fees=final_fees)
            else: #     return f"Payment in ecash of {amount} sats", 0


                for each in keyset_amounts:
                    available_amount += keyset_amounts[each]
                
                
                # print("available amount:", available_amount)
                if available_amount < amount:
                    msg_out = f"Insufficient balance to pay {amount} sats. You need more funds!"
                    raise RuntimeError(msg_out)
                
                
                for key in sorted(keyset_amounts, key=lambda k: keyset_amounts[k]):
                    # print(key, keyset_amounts[key])
                    if keyset_amounts[key] >= amount:
                        chosen_keyset = key
                        break
                if not chosen_keyset:
                    # print("insufficient balance in any one keyset, you need to swap or do mpp!") 
                    multi_path = True
                    
                
                if multi_path:
                    raise RuntimeError("Multipath payments are not implemented yet!")
                    #TODO the remaining code is for multipath
                    amount_multi =0
                    keysets_to_use_for_multi = []
                    for key in sorted(keyset_amounts, key=lambda k: keyset_amounts[k],reverse=True):
                        
                        # print(key, keyset_amounts[key])
                        amount_multi += keyset_amounts[key]
                        chosen_keysets.append(key)
                        # just do all the keysets for now
                        # if amount_multi >= amount:
                        #     print(f"got enough!")
                        #     break
                    
                    self.logger.debug("op=pay_multi status=mpp_choose amount=%s keysets=%s", amount, chosen_keysets)
                    amount_remaining = amount
                    total_fees = 0
                    total_melt_amount = 0
                    for each_keyset in chosen_keysets:
                        self.logger.debug("op=pay_multi status=mpp_remaining amount_remaining=%s", amount_remaining)
                        # There are three possible use cases
                        if amount_remaining <= 0:
                            self.logger.debug("op=pay_multi status=mpp_done")
                            break
                        elif amount_remaining > keyset_amounts[each_keyset]:
                            self.logger.debug("op=pay_multi status=mpp_use_full_keyset keyset=%s", each_keyset)
                            amount_to_use = keyset_amounts[each_keyset]
                        else:
                            amount_to_use = amount_remaining
                        
                        
                        melt_quote_url = f"{self.known_mints[each_keyset]}/v1/melt/quote/bolt11"
                        melt_url = f"{self.known_mints[each_keyset]}/v1/melt/bolt11"
                        
                        data_to_send = {    "request": pr,
                                            "unit": "sat",
                                            "options": {"mpp": {"amount": amount_to_use}}
                                    }
                        # print(f"{melt_quote_url, melt_url} {data_to_send}")
                        async with httpx.AsyncClient(timeout=timeout) as client:
                            response = await client.post(url=melt_quote_url, json=data_to_send, headers=headers)
                            response.raise_for_status()
                            post_melt_response = PostMeltQuoteResponse(**response.json())
                        self.logger.debug("op=pay_multi status=mpp_melt_quote keyset=%s", each_keyset)

                        # Now need to figure out how much can be paid based on case
                        if amount_remaining > keyset_amounts[each_keyset]:
                            pass
                            amount_to_pay = amount_to_use - post_melt_response.fee_reserve
                            melt_amount = amount_to_use
                        else:
                            pass
                            amount_to_pay = amount_to_use
                            melt_amount = amount_to_use + post_melt_response.fee_reserve
                            if melt_amount >= keyset_amounts[each_keyset]:
                                self.logger.warning("op=pay_multi status=mpp_melt_warning keyset=%s", each_keyset)
                            else:
                                self.logger.debug("op=pay_multi status=mpp_melt_amount_ok keyset=%s", each_keyset)

                        total_melt_amount += melt_amount
                        total_fees += post_melt_response.fee_reserve
                        # amount_paid_by_keyset = amount_to_use - post_melt_response.fee_reserve
                        self.logger.debug(
                            "op=pay_multi status=mpp_amount_calc keyset=%s amount_to_pay=%s keyset_total=%s fee_reserve=%s melt_amount=%s",
                            each_keyset,
                            amount_to_pay,
                            keyset_amounts[each_keyset],
                            post_melt_response.fee_reserve,
                            melt_amount,
                        )
                        # Redo the melt request
                        data_to_send = {    "request": pr,
                                        "unit": "sat",
                                        "options": {"mpp": {"amount": amount_to_pay}}
                                }
                        async with httpx.AsyncClient(timeout=timeout) as client:
                            response = await client.post(url=melt_quote_url, json=data_to_send, headers=headers)
                            response.raise_for_status()
                            post_melt_response = PostMeltQuoteResponse(**response.json())
                        self.logger.debug("op=pay_multi status=mpp_adjusted_quote keyset=%s", each_keyset)
                        amount_remaining = amount_remaining - amount_to_pay   
                        self.logger.debug("op=pay_multi status=mpp_adjusted_remaining amount_remaining=%s", amount_remaining)
                        keysets_to_use_for_multi.append((each_keyset,melt_amount,amount_to_pay,post_melt_response))

                    if amount_remaining > 0:
                        raise ValueError(f"There are not sufficient mints to support multipath payments. Try smaller amounts?")

                    # Now we have the meltquotes
                    self.logger.debug("op=pay_multi status=mpp_requests keysets=%s", keysets_to_use_for_multi)
                    self.logger.info("op=pay_multi status=mpp_summary amount=%s fees=%s melt_amount=%s", amount, total_fees, total_melt_amount)
                    
                    self._multi_melt(keysets_to_use_for_multi) 
                    
                    # self.write_proofs()

                    msg_out = f"pay amount with mpp {amount} total fees: {total_fees}, total melt amount {total_melt_amount}"
                    return msg_out, total_fees
                    # raise ValueError(f"Need to implement multipath payment for {amount} with {available_amount} available")

                else: # Can pay with a single keyset
                    
                    self.logger.debug(f"chosen keyset for payment {chosen_keyset}")
                
                    # Now do the pay routine
                    melt_quote_url = f"{self.known_mints[chosen_keyset]}/v1/melt/quote/bolt11"
                    melt_url = f"{self.known_mints[chosen_keyset]}/v1/melt/bolt11"

                    self.logger.debug("op=pay_multi status=single_keyset amount=%s lnaddress=%s", amount, lnaddress)
                    data_to_send = {    "request": pr,
                                        "unit": "sat"

                                    }
                    async with httpx.AsyncClient(timeout=timeout) as client:
                        response = await client.post(url=melt_quote_url, json=data_to_send, headers=headers)
                        response.raise_for_status()
                    

                    # print("post melt response:", response.json())
                    post_melt_response = PostMeltQuoteResponse(**response.json())
                    # print("mint response:", post_melt_response)
                    proofs_to_use = []
                    proof_amount = 0
                    amount_needed = amount + post_melt_response.fee_reserve
                    self.logger.debug(f"amount needed: {amount_needed}")
                    if amount_needed > keyset_amounts[chosen_keyset]:
                        self.logger.warning("op=pay_multi status=single_keyset_insufficient_switching")
                        chosen_keyset = None
                        for key in sorted(keyset_amounts, key=lambda k: keyset_amounts[k]):
                            # print(key, keyset_amounts[key])
                            if keyset_amounts[key] >= amount_needed:
                                chosen_keyset = key
                                self.logger.debug(f"new chosen keyset: {key}")
                                break
                        if not chosen_keyset:
                            msg_out = "you don't have a sufficient balance in a keyset, you need to swap"
                            raise ValueError(msg_out)

                        # Adding in some additional error handling to head off a random fatal error    
                        
                        # Set to new mints and redo the calls
                        melt_quote_url = f"{self.known_mints[chosen_keyset]}/v1/melt/quote/bolt11"
                        melt_url = f"{self.known_mints[chosen_keyset]}/v1/melt/bolt11"
                        # print(melt_quote_url,melt_url)
                        # callback = lightning_address_pay(amount, lnaddress,comment=comment)
                        # pr = callback['pr']        
                        # print(pr)
                        self.logger.debug(f"{amount}, {lnaddress}")
                        data_to_send = {    "request": pr,
                                        "unit": "sat"

                                    }
                        async with httpx.AsyncClient(timeout=timeout) as client:
                            response = await client.post(url=melt_quote_url, json=data_to_send, headers=headers)
                            response.raise_for_status()
                        # print("post melt response:", response.json())
                        post_melt_response = PostMeltQuoteResponse(**response.json())
                        # print("mint response:", post_melt_response)
                        
                        
                        
                        if not chosen_keyset:
                            msg_out ="insufficient balance in any one keyset, you need to swap!"
                            raise ValueError(msg_out) 
                        
                    # Print now we should be all set to go
                    
                    self.logger.debug("---we have a sufficient mint balance---")
                    
                    # This is the part that needs to be added in multi
                    proofs_to_use = []
                    proof_amount = 0
                    proofs_from_keyset = keyset_proofs[chosen_keyset]
                    while proof_amount < amount_needed:
                        pay_proof = proofs_from_keyset.pop()
                        proofs_to_use.append(pay_proof)
                        proof_amount += pay_proof.amount
                        # print("pop", pay_proof.amount)
                        

                    
                    #FIXME this is the critical error!!!
                    try: 
                        proofs_remaining = await self.swap_for_payment_multi(chosen_keyset,proofs_to_use, amount_needed)
                    except (ValueError, RuntimeError) as e:
                        raise RuntimeError(f"ERROR Swap for Payment: {e}. You may need to try the payment again.") from e
                        

                    # print("proofs remaining:", proofs_remaining)
                    # print(f"amount needed: {amount_needed}")
                    # Implement from line 824
                    sum_proofs =0
                    spend_proofs = []
                    keep_proofs = []
                    
                    for each in proofs_remaining:
                        
                        sum_proofs += each.amount
                        if sum_proofs <= amount_needed:
                            spend_proofs.append(each)
                            self.logger.debug(f"pay with {each.amount}, {each.secret}")
                        else:
                            keep_proofs.append(each)
                            self.logger.debug(f"keep {each.amount}, {each.secret}")
                    
                    self.logger.debug(f"spend proofs: {spend_proofs}")
                    self.logger.debug(f"keep proofs: {keep_proofs}")
                    melt_proofs = []
                    for each_proof in spend_proofs:
                            melt_proofs.append(each_proof.model_dump())

                    data_to_send = {"quote": post_melt_response.quote,
                                "inputs": melt_proofs }
                    
                
                    
                    self.logger.debug(f"lightning payment we are here!: {data_to_send}")
                    try:
                        async with httpx.AsyncClient(timeout=timeout) as client:
                            response = await client.post(url=melt_url, json=data_to_send, headers=headers)
                            response.raise_for_status()
                    except httpx.HTTPError as e:
                        raise RuntimeError(f"payment melt request failed: {e}") from e
                    
                    self.logger.debug(f"response json: {response.json()}")
                    payment_json = response.json()
                    #TODO Need to do some error checking
                
                    self.logger.debug(f"need to do some error checking")
                    # {'detail': 'Lightning payment unsuccessful. no_route', 'code': 20000}
                    # add keep proofs back into selected keyset proofs
                    if payment_json.get("paid",False):        
                        self.logger.info(f"Lightning payment ok")
                    else:
                        self.logger.info(f"lighting payment did no go through")
                        raise RuntimeError(f"Lightning payment to {lnaddress} of amount {amount} sats did not go through! Please try again.")
                        # The following code is not necessary
                        # Add back in spend proofs
                        # for each in spend_proofs:   
                        #    proofs_from_keyset.append(each)
                    

                    for each in keep_proofs:
                        proofs_from_keyset.append(each)
                    # print("self proofs", self.proofs)
                    # need to reassign back into 
                    keyset_proofs[chosen_keyset]= proofs_from_keyset
                    # OK - now need to put proofs back into a flat lish
                    post_payment_proofs = []
                    for key in keyset_proofs:
                        each_proofs = keyset_proofs[key]
                        for each_proof in each_proofs:
                            post_payment_proofs.append(each_proof)
                    
                    
                    # asyncio.run(self._async_delete_proof_events())
                    # self.delete_proof_events()
                    
                    self.proofs = post_payment_proofs
                
                
                
                final_fees = amount_needed - amount
                msg_out = f"Payment of {amount} sats with fee {final_fees} sats to {lnaddress} successful!"
                self.logger.info(msg_out)
                await self.write_proofs()
                await self.release_lock()
                self.logger.debug("op=pay_multi status=complete amount=%s", amount)
                self.logger.debug(
                    "op=pay_multi status=tx_history amount=%s comment=%s tendered_amount=%s tendered_currency=%s",
                    amount,
                    comment,
                    tendered_amount,
                    tendered_currency,
                )
                await self.add_tx_history(tx_type='D', amount=amount, comment=comment, tendered_amount=tendered_amount, tendered_currency=tendered_currency, fees=final_fees)
        except (ValueError, RuntimeError, httpx.HTTPError) as e:
            await self.release_lock()
            final_fees = 0
            msg_out = f"There is an error sending the payment. Did it go through?"
            self.logger.error("%s original_error=%s", msg_out, e)
            raise RuntimeError(msg_out) from e
        finally:
            await self.release_lock()
    
        
        return msg_out, final_fees

    async def _multi_melt(self, keysets_to_use):

        
        headers = { "Content-Type": "application/json"}
        
        mpp_mint_melt_request = []
        
        for each in keysets_to_use:
            keyset_proofs,keyset_amounts = self._proofs_by_keyset()
            chosen_keyset = each[0]
            proofs_to_use = []
            proof_amount = 0
            proofs_from_keyset = keyset_proofs[each[0]]
            amount_needed = each[1]
            amount_to_pay = each[2]
            post_melt_response = each[3]
            melt_url = f"{self.known_mints[chosen_keyset]}/v1/melt/bolt11"
            self.logger.debug("op=multi_melt status=request amount_needed=%s keyset=%s", amount_needed, chosen_keyset)
            while proof_amount < amount_needed:
                pay_proof = proofs_from_keyset.pop()
                proofs_to_use.append(pay_proof)
                proof_amount += pay_proof.amount
            
            proofs_remaining = await self.swap_for_payment_multi(chosen_keyset,proofs_to_use, amount_needed)
            # proofs_remaining = proofs_to_use
            sum_proofs =0
            spend_proofs = []
            keep_proofs = []
            for each_proof in proofs_remaining:
                
                sum_proofs += each_proof.amount
                if sum_proofs <= amount_needed:
                    spend_proofs.append(each_proof)
                    self.logger.debug(f"pay with {each_proof.amount}, {each_proof.secret}")
                else:
                    keep_proofs.append(each_proof)
                    self.logger.debug(f"keep {each_proof.amount}, {each_proof.secret}")
            
            self.logger.debug(f"spend proofs: {spend_proofs}")
            self.logger.debug(f"keep proofs: {keep_proofs}")
            melt_proofs = []
            for each_spend_proof in spend_proofs:
                    melt_proofs.append(each_spend_proof.model_dump())

            data_to_send = {"quote": post_melt_response.quote,
                        "inputs": melt_proofs }
            
        
            
            self.logger.debug(f"lightning payment mpp we are here!: {data_to_send}")
            mpp_mint_melt_request.append((melt_url,data_to_send))
            
        # print(mpp_mint_melt_request)
        await self._do_mpp_requests(mpp_mint_melt_request)
        self.logger.debug("op=multi_melt status=requests_complete")




            
        return 
           
    async def _do_mpp_requests(self, mpp_requests):
        tasks = []
        for each_request in mpp_requests:
            self.logger.debug("op=multi_melt status=queue_request request=%s", each_request[0])
            tasks.append(asyncio.create_task(self._post_request(each_request)))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        self.logger.debug("op=multi_melt status=tasks_completed")
    
    async def _post_request(self,request_item):
        timeout = httpx.Timeout(30.0, connect=5.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            self.logger.debug("op=multi_melt status=post_request url=%s", request_item[0])
            response = await client.post(url=request_item[0], json=request_item[1])
            response.raise_for_status()
        return

            

    async def pay_multi_invoice(  self, 
                     
                    lninvoice: str, 
                    comment: str = "Paid!",
                    tendered_amount: float=None,
                    tendered_currency: str = "SAT",
                    fees: int =0,                             
                    payment_preimage: str = None,
                    payment_hash: str = None,
                    description_hash: str = None): 
                    

        # decode amount from invoice
        try:
            await self.acquire_lock()
            timeout = httpx.Timeout(30.0, connect=5.0)
            ln_amount = int(bolt11.decode(lninvoice).amount_msat//1e3)
            payment_hash = bolt11.decode(lninvoice).payment_hash
            description_hash = bolt11.decode(lninvoice).description_hash

            self.logger.debug("pay from multiple mints")
            available_amount = 0
            chosen_keyset = None
            keyset_proofs,keyset_amounts = self._proofs_by_keyset()
            for each in keyset_amounts:
                available_amount += keyset_amounts[each]
            
            
            self.logger.debug(f"available amount: {available_amount}")
            if available_amount < ln_amount:
                msg_out ="insufficient balance. you need more funds!"
                raise ValueError(msg_out)
                
            
            for key in sorted(keyset_amounts, key=lambda k: keyset_amounts[k]):
                self.logger.debug(f"{key}, {keyset_amounts[key]}")
                if keyset_amounts[key] >= ln_amount:
                    chosen_keyset = key
                    break
            if not chosen_keyset:
                self.logger.error("insufficient balance in any one keyset, you need to swap!") 
                raise ValueError("insufficient balance in any one keyset")
               
        
            self.logger.debug(f"chosen keyset: {chosen_keyset}")
            # Now do the pay routine
            melt_quote_url = f"{self.known_mints[chosen_keyset]}/v1/melt/quote/bolt11"
            melt_url = f"{self.known_mints[chosen_keyset]}/v1/melt/bolt11"
            self.logger.debug(f"{melt_quote_url}, {melt_url}")
            headers = { "Content-Type": "application/json"}
            # callback = lightning_address_pay(amount, lnaddress,comment=comment)
            pr = lninvoice        
            self.logger.debug(f"pr {pr}")
            self.logger.debug(f"{ln_amount}, {lninvoice}")
            data_to_send = {    "request": pr,
                                "unit": "sat"

                            }
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(url=melt_quote_url, json=data_to_send, headers=headers)
                response.raise_for_status()
            self.logger.debug(f"post melt response: {response.json()}")
            # check reponse for error
            # print(f"mint response: {response.json()}")
            response_json = response.json()
            if response_json.get('code', None) == 11000:
                raise RuntimeError("mint quote already paid!")
            post_melt_response = PostMeltQuoteResponse(**response.json())
            self.logger.debug(f"mint response: {post_melt_response}")
            proofs_to_use = []
            proof_amount = 0
            amount_needed = ln_amount + post_melt_response.fee_reserve
            self.logger.debug(f"amount needed: {amount_needed}")
            #FIXME There is something wrong with the logic here for chosen keysets
            # This is paying via invoice not lnadress so need to fix 1775
            if amount_needed > keyset_amounts[chosen_keyset]:
                self.logger.debug("insufficient balance in keyset. you need to swap, or use another keyset")
                chosen_keyset = None
                for key in sorted(keyset_amounts, key=lambda k: keyset_amounts[k]):
                    self.logger.debug(f"{key}, {keyset_amounts[key]}")
                    if keyset_amounts[key] >= amount_needed:
                        chosen_keyset = key
                        self.logger.debug(f"new chosen keyset: {key}")
                        break
                if not chosen_keyset:
                    msg_out="you don't have a sufficient balance in a keyset, you need to swap"
                    raise ValueError(msg_out)
                
                # Set to new mints and redo the calls
                melt_quote_url = f"{self.known_mints[chosen_keyset]}/v1/melt/quote/bolt11"
                melt_url = f"{self.known_mints[chosen_keyset]}/v1/melt/bolt11"
                self.logger.debug(f"{melt_quote_url},{melt_url}")
                # We already have the invoice in this function
                # callback = lightning_address_pay(ln_amount, lninvoice,comment=comment)
                # pr = callback['pr']   
                pr = lninvoice     
                self.logger.debug(f"pr {pr}")
                self.logger.debug(f"{ln_amount}, {lninvoice}")
                data_to_send = {    "request": pr,
                                "unit": "sat"

                            }
                async with httpx.AsyncClient(timeout=timeout) as client:
                    response = await client.post(url=melt_quote_url, json=data_to_send, headers=headers)
                    response.raise_for_status()
                self.logger.debug(f"post melt response: {response.json()}")
                post_melt_response = PostMeltQuoteResponse(**response.json())
                self.logger.debug(f"mint response: {post_melt_response}")

                if not chosen_keyset:
                    msg_out ="insufficient balance in any one keyset, you need to swap!"
                    raise ValueError(msg_out) 
                
            # Print now we should be all set to go
        
            self.logger.debug("---we have a sufficient mint---")
            self.logger.debug(f"{melt_quote_url}, {melt_url}, {post_melt_response}")
            proofs_to_use = []
            proof_amount = 0
            proofs_from_keyset = keyset_proofs[chosen_keyset]
            while proof_amount < amount_needed:
                pay_proof = proofs_from_keyset.pop()
                proofs_to_use.append(pay_proof)
                proof_amount += pay_proof.amount
                self.logger.debug(f"pop {pay_proof.amount}")
                
            self.logger.debug(f"proofs to use:  {proofs_to_use}")
            self.logger.debug(f"remaining: {proofs_from_keyset}")
            # Continue implementing from line 818 swap_for_payment may need a parameter
            # Now need to do the melt
            proofs_remaining = await self.swap_for_payment_multi(chosen_keyset,proofs_to_use, amount_needed)
            

            self.logger.debug(f"proofs remaining: {proofs_remaining}")
            self.logger.debug(f"amount needed: {amount_needed}")
            # Implement from line 824
            sum_proofs =0
            spend_proofs = []
            keep_proofs = []
            for each in proofs_remaining:
                
                sum_proofs += each.amount
                if sum_proofs <= amount_needed:
                    spend_proofs.append(each)
                    self.logger.debug(f"pay with {each.amount}, {each.secret}")
                else:
                    keep_proofs.append(each)
                    self.logger.debug(f"keep {each.amount}, {each.secret}")
            self.logger.debug(f"spend proofs: {spend_proofs}") 
            self.logger.debug(f"keep proofs:  {keep_proofs}")
            melt_proofs = []
            for each_proof in spend_proofs:
                    melt_proofs.append(each_proof.model_dump())

            data_to_send = {"quote": post_melt_response.quote,
                        "inputs": melt_proofs }
            
            self.logger.debug(data_to_send)
            self.logger.debug("we are here!!!")
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(url=melt_url, json=data_to_send, headers=headers)
                response.raise_for_status()
            self.logger.debug(response.json())  
            payment_json = response.json() 
            payment_preimage = payment_json.get('payment_preimage', None)            
            if payment_json.get("paid",False):        
                    self.logger.info(f"Lightning payment ok: {payment_hash} {payment_preimage}")
            else:
                self.logger.info(f"lighting payment did no go through")
                for each in keep_proofs:
                    proofs_from_keyset.append(each)
                keyset_proofs[chosen_keyset] = proofs_from_keyset
                post_payment_proofs = []
                for key in keyset_proofs:
                    post_payment_proofs.extend(keyset_proofs[key])
                self.proofs = post_payment_proofs

                raise RuntimeError(f"Lightning payment not go through! Please try again.")
            # add keep proofs back into selected keyset proofs
            for each in keep_proofs:
                proofs_from_keyset.append(each)
            # print("self proofs", self.proofs)
            # need to reassign back into 
            keyset_proofs[chosen_keyset]= proofs_from_keyset
            # OK - now need to put proofs back into a flat lish
            post_payment_proofs = []
            for key in keyset_proofs:
                each_proofs = keyset_proofs[key]
                for each_proof in each_proofs:
                    post_payment_proofs.append(each_proof)
            
            # Replace with new function
            self.proofs = post_payment_proofs
            # asyncio.run(self._async_delete_proof_events())
            # self.add_proofs_obj(post_payment_proofs)
            # self._load_proofs()
            
            
            final_fees = amount_needed-ln_amount
            msg_out = f"Paid {ln_amount} sats with fees {final_fees} sats successful!"
            self.logger.info(msg_out)
            await self.write_proofs()
            await self.release_lock()
        except (ValueError, RuntimeError, httpx.HTTPError) as e:
            # await self.release_lock()
            self.logger.error("Error in pay_multi_invoice: %s", e)
            # raise RuntimeError(f"Error There is problem with the invoice payment {e}")
            final_fees = 0
            msg_out = f"There is a problem paying the invoice. {e}"
            raise RuntimeError(msg_out) from e
        finally:
            await self.release_lock()
            self.logger.debug("op=pay_multi_invoice status=complete")
        
        await self.add_tx_history( tx_type='D',
                                        amount=ln_amount,
                                        comment=comment,
                                        tendered_amount=tendered_amount,
                                        tendered_currency=tendered_currency,
                                        fees=final_fees)
        
        return msg_out, final_fees, payment_hash,payment_preimage, description_hash

    async def delete_kind_events(self, record_kind:int):
        """
            Delete kind events
        """
        # first, get all of the events for the kind

        FILTER = [{
                'limit': RECORD_LIMIT, 
                '#p'  :  [self.pubkey_hex],              
                'kinds': [record_kind]
                
                }]
  

        async with ClientPool([self.home_relay]) as c:  
            events = await c.query(FILTER) 
        
        self.logger.debug("op=delete_kind_events status=events_found count=%s kind=%s", len(events), record_kind)
        for each in events:
            self.logger.debug("op=delete_kind_events status=event_id event_id=%s", each.id)
        
        tags = []
        for each_event in events:
            tags.append(["e",each_event.id])
            
        tags.append(["k",str(record_kind)])
        self.logger.debug("op=delete_kind_events status=tags count=%s", len(tags))
        
        
        try:

            async with ClientPool([self.home_relay]) as c:
            
                n_msg = Event(kind=Event.KIND_DELETE,
                            content=None,
                            pub_key=self.pubkey_hex,
                            tags=tags)
                n_msg.sign(self.privkey_hex)
                c.publish(n_msg)
                # added a delay here so the delete event get published
                await asyncio.sleep(1)
                self.logger.debug("op=delete_kind_events status=published")
        except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
            raise RuntimeError("error deleting proof events")  
        
        return f"events of kind {record_kind} deleted on {self.home_relay}" 


    async def _async_delete_proof_events(self):
        """
            Delete proof events
        """
        #FIXME I don't this code does anything
        backup_proof_events = self.proof_events
        try:
            tags = []
            for each_event in self.proof_events.proof_events:
                tags.append(["e",each_event.id])
                self.logger.debug(f"proof to delete: {each_event.id}")
                # print(each_event.id)
                for each_proof in each_event.proofs:
                    # self.logger.debug(f"{each_proof.id}, {each_proof.amount}")
                    pass
            #FIXME end of fix me
            for each in self.proof_event_ids:
                tags.append(["e",each])
            tags.append(["k","7375"])
            self.logger.debug(f"tags for proof events to delete {tags}")
            # print(f"tags for proof events to delete {tags}")
            
            async with ClientPool([self.home_relay]) as c:
            
                n_msg = Event(kind=Event.KIND_DELETE,
                            content=None,
                            pub_key=self.pubkey_hex,
                            tags=tags)
                n_msg.sign(self.privkey_hex)
                c.publish(n_msg)
                # added a delay here so the delete event get published
                await asyncio.sleep(1)
        except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
            raise RuntimeError("error deleting proof events")    

    async def _async_delete_events_by_ids(self, event_ids: List[str], record_kind: int):
        if not event_ids:
            return

        tags = []
        for event_id in event_ids:
            tags.append(["e", event_id])
        tags.append(["k", str(record_kind)])
        self.logger.debug(f"deleting {len(event_ids)} events for kind {record_kind}")

        async with ClientPool([self.home_relay]) as c:
            n_msg = Event(
                kind=Event.KIND_DELETE,
                content=None,
                pub_key=self.pubkey_hex,
                tags=tags,
            )
            n_msg.sign(self.privkey_hex)
            c.publish(n_msg)
            await asyncio.sleep(1)

    async def swap_proofs(self, incoming_swap_proofs: List[Proof]):
        '''This function swaps proofs'''
        self.logger.debug("Swap proofs")
        swap_amount =0
        count = 0
        
        headers = { "Content-Type": "application/json"}
        timeout = httpx.Timeout(30.0, connect=5.0)
        
        #keyset_url = f"{self.mints[0]}/v1/keysets"
        keyset_url = f"{self.known_mints[incoming_swap_proofs[0].id]}/v1/keysets"
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(keyset_url, headers=headers)
            response.raise_for_status()
            keyset = response.json()['keysets'][0]['id']

        swap_url = f"{self.known_mints[incoming_swap_proofs[0].id]}/v1/swap"
        swap_proofs = []
        blinded_swap_proofs = []
        blinded_values =[]
        blinded_messages = []
        new_proofs = []
        for each_proof in incoming_swap_proofs:
            swap_amount+=each_proof.amount        
            swap_proofs.append(each_proof.model_dump())                    
            count +=1
        
        r = PrivateKey()
        powers_of_2 = self.powers_of_2_sum(swap_amount)
        self.logger.debug("op=swap_proofs status=decompose total=%s proofs=%s", swap_amount, count)
        for each in powers_of_2:
                secret = secrets.token_hex(32)
                B_, r, Y = step1_alice(secret)
                blinded_values.append((B_,r, secret,Y))
                
                blinded_messages.append(    BlindedMessage( amount=each,
                                                            id=keyset,
                                                            B_=B_.serialize().hex(),
                                                            Y = Y.serialize().hex(),
                                                            ).model_dump()
                                        )
            
        data_to_send = {
                            "inputs":   swap_proofs,
                            "outputs": blinded_messages
                            
            } 
        
        try:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    response = await client.post(url=swap_url, json=data_to_send, headers=headers)
                    response.raise_for_status()
                    promises = response.json()['signatures']

                    mint_key_url = f"{self.known_mints[incoming_swap_proofs[0].id]}/v1/keys/{keyset}"
                    response = await client.get(mint_key_url, headers=headers)
                    response.raise_for_status()
                    keys = response.json()["keysets"][0]["keys"]
                # print(keys)
                new_proofs = []
                i = 0
            
                for each in promises:
                    pub_key_c = PublicKey()
                    # print("each:", each['C_'])
                    pub_key_c.deserialize(unhexlify(each['C_']))
                    promise_amount = each['amount']
                    A = keys[str(int(promise_amount))]
                    # A = keys[str(j)]
                    pub_key_a = PublicKey()
                    pub_key_a.deserialize(unhexlify(A))
                    r = blinded_values[i][1]
                    Y = blinded_values[i][3]
                    # print(pub_key_c, promise_amount,A, r)
                    C = step3_alice(pub_key_c,r,pub_key_a)
                    proof = {   "amount": promise_amount,
                            "id": keyset,
                            "secret": blinded_values[i][2],
                            "C":    C.serialize().hex(),
                            "Y":    Y.serialize().hex()
                            }
                    new_proofs.append(proof)
                    # print(proofs)
                    i+=1
        except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as e:
                raise RuntimeError(f"Problem with swap {e}")

        # need to convert new_proofs into objects
        new_proof_obj_list = []
        for each in new_proofs:
            new_proof_obj_list.append(Proof(**each))

        return new_proof_obj_list
    
    async def swap_multi_consolidate(self):
        #TODO run swap_multi_each first to get rid of any potential doublespends
        #TODO figure out how to catch doublespends in this routine
        headers = { "Content-Type": "application/json"}
        timeout = httpx.Timeout(30.0, connect=5.0)
        keyset_proofs,keyset_amounts = self._proofs_by_keyset()
        combined_proofs = []
        combined_proof_objs =[]
        proof_objs = []
        
        # Let's check all the proofs before we do anything
        try:
            await self.acquire_lock()

            for each_keyset in keyset_proofs:
                check = []
                mint_verify_url = f"{self.known_mints[each_keyset]}/v1/checkstate"
                for each_proof in keyset_proofs[each_keyset]:
                    check.append(each_proof.Y)

                # print(mint_verify_url, check)
                Ys = {"Ys": check}
                async with httpx.AsyncClient(timeout=timeout) as client:
                    response = await client.post(url=mint_verify_url, headers=headers, json=Ys)
                    response.raise_for_status()
                    check_response = response.json()
                proofs_to_check = check_response['states']
                for each_proof in proofs_to_check:
                    assert each_proof['state'] == "UNSPENT"
                    # print(each_proof['state'])
                
                    
            # return
            # All the proofs are verified, we are good to go for the swap    

 
            for each_keyset in keyset_proofs:
                
                each_keyset_url = self.known_mints[each_keyset]
                # print(each_keyset,each_keyset_url)
                swap_url = f"{self.known_mints[each_keyset]}/v1/swap"
                # print(swap_url)
                swap_proofs = []
                blinded_swap_proofs = []
                blinded_values =[]
                blinded_messages = []
                swap_amount =0
                count = 0
                for each_proof in keyset_proofs[each_keyset]:
                    # print(each_proof.amount)
                    swap_amount+=each_proof.amount
                    swap_proofs.append(each_proof.model_dump())                    
                    count +=1
                    # print("swap proofs:", swap_proofs)
                r = PrivateKey()

                # print("create blinded swap proofs")
                powers_of_2 = self.powers_of_2_sum(swap_amount)
                # print("total:", swap_amount,count, powers_of_2)
                for each in powers_of_2:
                    secret = secrets.token_hex(32)
                    B_, r, Y = step1_alice(secret)
                    blinded_values.append((B_,r, secret,Y))
                    
                    blinded_messages.append(    BlindedMessage( amount=each,
                                                                id=each_keyset,
                                                                B_=B_.serialize().hex(),
                                                                Y = Y.serialize().hex(),
                                                                ).model_dump()
                                            )
                data_to_send = {
                                "inputs":   swap_proofs,
                                "outputs": blinded_messages
                                
                }
            
                # print(data_to_send)
            try:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    response = await client.post(url=swap_url, json=data_to_send, headers=headers)
                    response.raise_for_status()
                    promises = response.json()['signatures']

                    mint_key_url = f"{self.known_mints[each_keyset]}/v1/keys/{each_keyset}"
                    response = await client.get(mint_key_url, headers=headers)
                    response.raise_for_status()
                    keys = response.json()["keysets"][0]["keys"]
                # print(keys)
                proofs = []
                proof_objs = []
                i = 0
            
                for each in promises:
                    pub_key_c = PublicKey()
                    # print("each:", each['C_'])
                    pub_key_c.deserialize(unhexlify(each['C_']))
                    promise_amount = each['amount']
                    A = keys[str(int(promise_amount))]
                    # A = keys[str(j)]
                    pub_key_a = PublicKey()
                    pub_key_a.deserialize(unhexlify(A))
                    r = blinded_values[i][1]
                    Y = blinded_values[i][3]
                    # print(pub_key_c, promise_amount,A, r)
                    C = step3_alice(pub_key_c,r,pub_key_a)
                    proof = {   "amount": promise_amount,
                            "id": each_keyset,
                            "secret": blinded_values[i][2],
                            "C":    C.serialize().hex(),
                            "Y":    Y.serialize().hex()
                            }
                    proofs.append(proof)
                    proof_obj = Proof(amount=promise_amount,
                                        id=each_keyset,
                                        secret=blinded_values[i][2],
                                        C=C.serialize().hex(),
                                        Y = Y.serialize().hex()
                                        )
                    proof_objs.append(proof_obj)

                    # print(proofs)
                    i+=1
            except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
                    # don't error the whole swap routine here
                    # duplicate proofs just ignore
                    proofs = []   

            
            combined_proofs = combined_proofs + proofs
            combined_proof_objs = combined_proof_objs + proof_objs
            # print(request_body) 
            # refresh balance
            
            swap_balance = 0
            for each in self.proofs:
                swap_balance += each.amount
            # print(len(self.proofs))
            self.proofs = combined_proof_objs
            await self.write_proofs()
            await self.release_lock()

            # self.add_proofs_obj(combined_proof_objs)
            # self._load_proofs()
        except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as e:
            raise RuntimeError(f"Error in swap multi {e}")
        
        finally:
            await self.release_lock()
    
        
        return f"multi swap ok  {len(self.proofs)} proofs in {self.events} proof events"

    async def swap_multi_each(self):
        #FIXME this is used before consolidate to throw out any dups or doublespend. Fix events
        headers = { "Content-Type": "application/json"}
        timeout = httpx.Timeout(30.0, connect=5.0)
        keyset_proofs,keyset_amounts = self._proofs_by_keyset()
        combined_proofs = []
        combined_proof_objs =[]
        
        # Let's check all the proofs before we do anything
        try:
            await self.acquire_lock()
            for each_keyset in keyset_proofs:
                check = []
                mint_verify_url = f"{self.known_mints[each_keyset]}/v1/checkstate"
                for each_proof in keyset_proofs[each_keyset]:
                    check.append(each_proof.Y)

                # print(mint_verify_url, check)
                Ys = {"Ys": check}
                async with httpx.AsyncClient(timeout=timeout) as client:
                    response = await client.post(url=mint_verify_url, headers=headers, json=Ys)
                    response.raise_for_status()
                    check_response = response.json()
                proofs_to_check = check_response['states']
                for each_proof in proofs_to_check:
                    assert each_proof['state'] == "UNSPENT"
                    # print(each_proof['state'])
                
            # return
            # All the proofs are verified, we are good to go for the swap   
            # In multi_each we are going to swap for each proof 
            

            for each_keyset in keyset_proofs:
                
                each_keyset_url = self.known_mints[each_keyset]

                mint_key_url = f"{self.known_mints[each_keyset]}/v1/keys/{each_keyset}"
                async with httpx.AsyncClient(timeout=timeout) as client:
                    response = await client.get(mint_key_url, headers=headers)
                    response.raise_for_status()
                    keys = response.json()["keysets"][0]["keys"]
                # print(each_keyset,each_keyset_url)
                swap_url = f"{self.known_mints[each_keyset]}/v1/swap"
                
                for each_proof in keyset_proofs[each_keyset]:
                    # print(each_proof.amount)
                    blinded_values =[]
                    blinded_messages = []
                    secret = secrets.token_hex(32)
                    B_, r, Y = step1_alice(secret)
                    blinded_values.append((B_,r, secret,Y))
                    
                    blinded_messages.append(    BlindedMessage( amount=each_proof.amount,
                                                                id=each_keyset,
                                                                B_=B_.serialize().hex(),
                                                                Y = Y.serialize().hex(),
                                                                ).model_dump()
                                            )
                    data_to_send = {
                                "inputs":   [each_proof.model_dump()],
                                "outputs": blinded_messages
                                
                    }
                    proofs = []
                    proof_objs = []
                    
                    try:
                        async with httpx.AsyncClient(timeout=timeout) as client:
                            response = await client.post(url=swap_url, json=data_to_send, headers=headers)
                            response.raise_for_status()
                            promises = response.json()['signatures']
                        # print("promises:", promises)
                        
                        i = 0
                
                        for each in promises:
                            pub_key_c = PublicKey()
                            # print("each:", each['C_'])
                            pub_key_c.deserialize(unhexlify(each['C_']))
                            promise_amount = each['amount']
                            A = keys[str(int(promise_amount))]
                            # A = keys[str(j)]
                            pub_key_a = PublicKey()
                            pub_key_a.deserialize(unhexlify(A))
                            r = blinded_values[i][1]
                            Y = blinded_values[i][3]
                            # print(pub_key_c, promise_amount,A, r)
                            C = step3_alice(pub_key_c,r,pub_key_a)
                            proof = {   "amount": promise_amount,
                                "id": each_keyset,
                                "secret": blinded_values[i][2],
                                "C":    C.serialize().hex(),
                                "Y":    Y.serialize().hex()
                                }
                            proofs.append(proof)
                            # print(proofs)
                            proof_obj = Proof(amount=promise_amount,
                                            id=each_keyset,
                                            secret=blinded_values[i][2],
                                            C=C.serialize().hex(),
                                            Y = Y.serialize().hex()
                                            )
                            proof_objs.append(proof_obj)
                            i+=1
                    except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
                        # Don't error the whole swap routine
                        # Just igore the duplicate proofs
                        proofs = []    
                        
                        

                    

                    combined_proofs = combined_proofs + proofs
                    combined_proof_objs = combined_proof_objs + proof_objs

            await self.delete_proof_events()
            self.logger.debug("XXXXX swap multi each")
            await self.add_proofs_obj(combined_proof_objs)
            
            await self._load_proofs()
            await self.release_lock()

        except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as e:
            await self.release_lock()
            raise RuntimeError(f"Error in swap {e}")
        
        finally:
            await self.release_lock()
                   
        
        return "multi swap ok"
    async def _async_swap(self):
        # This is the async version of swap
        headers = { "Content-Type": "application/json"}
        timeout = httpx.Timeout(30.0, connect=5.0)
        keyset_proofs,keyset_amounts = self._proofs_by_keyset()
        combined_proofs = []
        combined_proof_objs =[]
        
        # Let's check all the proofs before we do anything

        async with httpx.AsyncClient(timeout=timeout) as client:
            for each_keyset in keyset_proofs:
                check = []
                mint_verify_url = f"{self.known_mints[each_keyset]}/v1/checkstate"
                for each_proof in keyset_proofs[each_keyset]:
                    check.append(each_proof.Y)

                Ys = {"Ys": check}
                try:
                    response = await client.post(url=mint_verify_url, headers=headers, json=Ys)
                    response.raise_for_status()
                    check_response = response.json()
                    proofs_to_check = check_response["states"]
                    for each_proof in proofs_to_check:
                        if each_proof.get("state") != "UNSPENT":
                            raise ValueError(f"Proof state not spendable: {each_proof.get('state')}")
                except (httpx.HTTPError, KeyError, ValueError, TypeError) as exc:
                    self.logger.warning(
                        "op=async_swap status=checkstate_failed mint=%s keyset=%s error=%s",
                        self.known_mints.get(each_keyset),
                        each_keyset,
                        exc,
                    )
                    return f"there is a problem with the mint {self.known_mints[each_keyset]}"
                
            # return
            # All the proofs are verified, we are good to go for the swap
            # In multi_each we are going to swap for each proof
            for each_keyset in keyset_proofs:
                mint_key_url = f"{self.known_mints[each_keyset]}/v1/keys/{each_keyset}"
                try:
                    response = await client.get(mint_key_url, headers=headers)
                    response.raise_for_status()
                    keys = response.json()["keysets"][0]["keys"]
                except (httpx.HTTPError, KeyError, ValueError, TypeError) as exc:
                    self.logger.error(
                        "op=async_swap status=key_fetch_failed keyset=%s mint=%s error=%s",
                        each_keyset,
                        self.known_mints.get(each_keyset),
                        exc,
                    )
                    raise RuntimeError(f"Unable to fetch keys for keyset {each_keyset}") from exc

                swap_url = f"{self.known_mints[each_keyset]}/v1/swap"
                
                for each_proof in keyset_proofs[each_keyset]:
                    blinded_values =[]
                    blinded_messages = []
                    secret = secrets.token_hex(32)
                    B_, r, Y = step1_alice(secret)
                    blinded_values.append((B_,r, secret,Y))
                    
                    blinded_messages.append(    BlindedMessage( amount=each_proof.amount,
                                                                id=each_keyset,
                                                                B_=B_.serialize().hex(),
                                                                Y = Y.serialize().hex(),
                                                                ).model_dump()
                                            )
                    data_to_send = {
                                "inputs":   [each_proof.model_dump()],
                                "outputs": blinded_messages
                                
                    }
                    proofs = []
                    proof_objs = []
                    try:
                        response = await client.post(url=swap_url, json=data_to_send, headers=headers)
                        response.raise_for_status()
                        promises = response.json()['signatures']
                        
                        i = 0
                
                        for each in promises:
                            pub_key_c = PublicKey()
                            pub_key_c.deserialize(unhexlify(each['C_']))
                            promise_amount = each['amount']
                            A = keys[str(int(promise_amount))]
                            pub_key_a = PublicKey()
                            pub_key_a.deserialize(unhexlify(A))
                            r = blinded_values[i][1]
                            Y = blinded_values[i][3]
                            C = step3_alice(pub_key_c,r,pub_key_a)
                            proof = {   "amount": promise_amount,
                                "id": each_keyset,
                                "secret": blinded_values[i][2],
                                "C":    C.serialize().hex(),
                                "Y":    Y.serialize().hex()
                                }
                            proofs.append(proof)
                            proof_obj = Proof(amount=promise_amount,
                                          id=each_keyset,
                                          secret=blinded_values[i][2],
                                          C=C.serialize().hex(),
                                          Y = Y.serialize().hex()
                                          )
                            proof_objs.append(proof_obj)
                            i+=1
                    except (httpx.HTTPError, KeyError, ValueError, TypeError) as exc:
                        self.logger.warning(
                            "op=async_swap status=swap_step_failed keyset=%s mint=%s error=%s",
                            each_keyset,
                            self.known_mints.get(each_keyset),
                            exc,
                        )
                        continue

                    combined_proofs = combined_proofs + proofs
                    combined_proof_objs = combined_proof_objs + proof_objs

        self.logger.debug("op=async_swap status=write_proofs proofs=%s", len(combined_proof_objs))
        self.proofs = combined_proof_objs
        await self.write_proofs()
        
        # self._load_proofs()
        FILTER = [{
            'limit': RECORD_LIMIT,
            'authors': [self.pubkey_hex],
            'kinds': [7375]
        }]
        await self._async_load_proofs(FILTER)

        return     
    def swap_for_payment(self, proofs_to_use: List[Proof], payment_amount: int)->List[Proof]:
        # create proofs to melt, and proofs_remaining

        swap_amount =0
        count = 0
        
        headers = { "Content-Type": "application/json"}
        keyset_url = f"{self.mints[0]}/v1/keysets"
        response = requests.get(keyset_url, headers=headers)
        keyset = response.json()['keysets'][0]['id']

        swap_url = f"{self.mints[0]}/v1/swap"

        swap_proofs = []
        blinded_values =[]
        blinded_messages = []
        proofs = []
        proofs_to_melt = []
        proofs_remaing = []
        # Figure out proofs_to_use_amount
        proofs_to_use_amount = 0
        for each in proofs_to_use:
            proofs_to_use_amount += each.amount
       
        powers_of_2_payment = self.powers_of_2_sum(payment_amount)
        

        for each in powers_of_2_payment:
            secret = secrets.token_hex(32)
            B_, r, Y = step1_alice(secret)
            blinded_values.append((B_,r, secret))
            
            blinded_messages.append(    BlindedMessage( amount=each,
                                                        id=keyset,
                                                        B_=B_.serialize().hex(),
                                                        Y = Y.serialize().hex(),
                                                        ).model_dump()
                                    )
        if proofs_to_use_amount > payment_amount:
            powers_of_2_leftover = self.powers_of_2_sum(proofs_to_use_amount- payment_amount)
            for each in powers_of_2_leftover:
                secret = secrets.token_hex(32)
                B_, r, Y = step1_alice(secret)
                blinded_values.append((B_,r, secret))
            
                blinded_messages.append(    BlindedMessage( amount=each,
                                                        id=keyset,
                                                        B_=B_.serialize().hex(),
                                                        Y = Y.serialize().hex(),
                                                        ).model_dump()
                                    )

        proofs_to_send =[]
        for each in proofs_to_use:
            proofs_to_send.append(each.model_dump())

        data_to_send = {
                        "inputs":  proofs_to_send,
                        "outputs": blinded_messages
                        
        }

        # print(powers_of_2_payment, powers_of_2_leftover)
        # print(proofs_to_use)
        # print(blinded_messages)
        # print(data_to_send)

        try:
            # print("are we here?")
            response = requests.post(url=swap_url, json=data_to_send, headers=headers)
            
            self.logger.debug("op=swap_for_payment status=response_received")
            promises = response.json()['signatures']
            self.logger.debug("op=swap_for_payment status=promises count=%s", len(promises))

        
            mint_key_url = f"{self.mints[0]}/v1/keys/{keyset}"
            response = requests.get(mint_key_url, headers=headers)
            keys = response.json()["keysets"][0]["keys"]
            # print(keys)
            
            i = 0
        
            for each in promises:
                pub_key_c = PublicKey()
                self.logger.debug("op=swap_for_payment status=promise amount=%s", each.get("amount"))
                pub_key_c.deserialize(unhexlify(each['C_']))
                promise_amount = each['amount']
                A = keys[str(int(promise_amount))]
                # A = keys[str(j)]
                pub_key_a = PublicKey()
                pub_key_a.deserialize(unhexlify(A))
                r = blinded_values[i][1]
                self.logger.debug("op=swap_for_payment status=unblind amount=%s", promise_amount)
                C = step3_alice(pub_key_c,r,pub_key_a)
                
                proof = Proof(  amount=promise_amount,
                                id=keyset,
                                secret=blinded_values[i][2],
                                C=C.serialize().hex() )
                
                proofs.append(proof)
                # print(proofs)
                i+=1
        except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
            ValueError('test')
        
        for each in proofs:
            self.logger.debug("op=swap_for_payment status=proof amount=%s", each.amount)
        # now need break out proofs for payment and proofs remaining

        return proofs

    async def swap_for_payment_multi(self, keyset_to_use:str, proofs_to_use: List[Proof], payment_amount: int)->List[Proof]:
        # create proofs to melt, and proofs_remaining

        swap_amount =0
        count = 0
        
        headers = { "Content-Type": "application/json"}
        timeout = httpx.Timeout(30.0, connect=5.0)
        keyset_url = f"{self.known_mints[keyset_to_use]}/v1/keysets"
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(keyset_url, headers=headers)
            response.raise_for_status()
            keyset = response.json()['keysets'][0]['id']

        swap_url = f"{self.known_mints[keyset_to_use]}/v1/swap"
        checkstate_url = f"{self.known_mints[keyset_to_use]}/v1/checkstate"

        swap_proofs = []
        blinded_values =[]
        blinded_messages = []
        proofs = []
        checkstate_ys = []

        self.logger.debug("op=swap_for_payment_multi status=checkstate_start")
        for each in proofs_to_use:
            self.logger.debug("op=swap_for_payment_multi status=checkstate_y")
            checkstate_ys.append(each.Y)

        data_to_send = {"Ys": checkstate_ys}  
        self.logger.debug("op=swap_for_payment_multi status=checkstate_payload")
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url=checkstate_url, json=data_to_send, headers=headers)
            response.raise_for_status()
            self.logger.debug("op=swap_for_payment_multi status=checkstate_response")

        # Figure out proofs_to_use_amount
        proofs_to_use_amount = 0
        for each in proofs_to_use:
            proofs_to_use_amount += each.amount
       
        powers_of_2_payment = self.powers_of_2_sum(payment_amount)
        

        for each in powers_of_2_payment:
            secret = secrets.token_hex(32)
            B_, r, Y = step1_alice(secret)
            blinded_values.append((B_,r, secret))
            
            blinded_messages.append(    BlindedMessage( amount=each,
                                                        id=keyset,
                                                        B_=B_.serialize().hex(),
                                                        Y = Y.serialize().hex(),
                                                        ).model_dump()
                                    )
        if proofs_to_use_amount > payment_amount:
            powers_of_2_leftover = self.powers_of_2_sum(proofs_to_use_amount- payment_amount)
            for each in powers_of_2_leftover:
                secret = secrets.token_hex(32)
                B_, r, Y = step1_alice(secret)
                blinded_values.append((B_,r, secret))
            
                blinded_messages.append(    BlindedMessage( amount=each,
                                                        id=keyset,
                                                        B_=B_.serialize().hex(),
                                                        Y = Y.serialize().hex(),
                                                        ).model_dump()
                                    )

        proofs_to_send =[]
        for each in proofs_to_use:
            proofs_to_send.append(each.model_dump())

        data_to_send = {
                        "inputs":  proofs_to_send,
                        "outputs": blinded_messages
                        
        }

        # print(powers_of_2_payment, powers_of_2_leftover)
        # print(proofs_to_use)
        # print(blinded_messages)
        # print(data_to_send)

        try:
            self.logger.debug("are we here?")
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(url=swap_url, json=data_to_send, headers=headers)
                response.raise_for_status()
                promises = response.json()['signatures']

                mint_key_url = f"{self.known_mints[keyset_to_use]}/v1/keys/{keyset}"
                response = await client.get(mint_key_url, headers=headers)
                response.raise_for_status()
                keys = response.json()["keysets"][0]["keys"]
            # print(keys)
            
            i = 0
        
            for each in promises:
                pub_key_c = PublicKey()
                # print("each:", each['C_'])
                pub_key_c.deserialize(unhexlify(each['C_']))
                promise_amount = each['amount']
                A = keys[str(int(promise_amount))]
                # A = keys[str(j)]
                pub_key_a = PublicKey()
                pub_key_a.deserialize(unhexlify(A))
                r = blinded_values[i][1]
                secret_msg = blinded_values[i][2]
                Y: PublicKey = hash_to_curve(secret_msg.encode("utf-8"))
                self.logger.debug(f"{pub_key_c} {promise_amount},{A}, {r}")
                C = step3_alice(pub_key_c,r,pub_key_a)
                
                proof = Proof(  amount=promise_amount,
                                id=keyset,
                                secret=secret_msg,
                                C=C.serialize().hex(),
                                Y = Y.serialize().hex()
                              
                                 
                                )
                
                proofs.append(proof)
                # print(proofs)
                i+=1
        except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as e:
            self.logger.warning("op=swap_for_payment_multi status=failed error=%s", e)
            raise RuntimeError(f"ERROR {e}")
        
        for each in proofs:
            pass
            # print(each.amount)
        # now need break out proofs for payment and proofs remaining

        return proofs

    def swap_for_payment_inputs(self, keyset_to_use:str, proofs_to_use: List[Proof], payment_amount: int)->List[Proof]:
        # create proofs to melt, and proofs_remaining

        swap_amount =0
        count = 0
        
        headers = { "Content-Type": "application/json"}
        keyset_url = f"{self.known_mints[keyset_to_use]}/v1/keysets"
        response = requests.get(keyset_url, headers=headers)
        keyset = response.json()['keysets'][0]['id']

        swap_url = f"{self.known_mints[keyset_to_use]}/v1/swap"

        swap_proofs = []
        blinded_values =[]
        blinded_messages = []
        proofs = []
        
        # Figure out proofs_to_use_amount
        proofs_to_use_amount = 0
        for each in proofs_to_use:
            proofs_to_use_amount += each.amount
       
        powers_of_2_payment = self.powers_of_2_sum(payment_amount)
        

        for each in powers_of_2_payment:
            secret = secrets.token_hex(32)
            B_, r, Y = step1_alice(secret)
            blinded_values.append((B_,r, secret))
            
            blinded_messages.append(    BlindedMessage( amount=each,
                                                        id=keyset,
                                                        B_=B_.serialize().hex(),
                                                        Y = Y.serialize().hex(),
                                                        ).model_dump()
                                    )
        if proofs_to_use_amount > payment_amount:
            powers_of_2_leftover = self.powers_of_2_sum(proofs_to_use_amount- payment_amount)
            for each in powers_of_2_leftover:
                secret = secrets.token_hex(32)
                B_, r, Y = step1_alice(secret)
                blinded_values.append((B_,r, secret))
            
                blinded_messages.append(    BlindedMessage( amount=each,
                                                        id=keyset,
                                                        B_=B_.serialize().hex(),
                                                        Y = Y.serialize().hex(),
                                                        ).model_dump()
                                    )

        proofs_to_send =[]
        for each in proofs_to_use:
            proofs_to_send.append(each.model_dump())

        data_to_send = {
                        "inputs":  proofs_to_send,
                        "outputs": blinded_messages
                        
        }



        try:
            self.logger.debug("are we here?")
            response = requests.post(url=swap_url, json=data_to_send, headers=headers)
            
            # print(response.json())
            promises = response.json()['signatures']
            # print("promises:", promises)

        
            mint_key_url = f"{self.known_mints[keyset_to_use]}/v1/keys/{keyset}"
            response = requests.get(mint_key_url, headers=headers)
            keys = response.json()["keysets"][0]["keys"]
            # print(keys)
            
            i = 0
        
            for each in promises:
                pub_key_c = PublicKey()
                # print("each:", each['C_'])
                pub_key_c.deserialize(unhexlify(each['C_']))
                promise_amount = each['amount']
                A = keys[str(int(promise_amount))]
                # A = keys[str(j)]
                pub_key_a = PublicKey()
                pub_key_a.deserialize(unhexlify(A))
                r = blinded_values[i][1]
                secret_msg = blinded_values[i][2]
                Y: PublicKey = hash_to_curve(secret_msg.encode("utf-8"))
                self.logger.debug(f"{pub_key_c} {promise_amount},{A}, {r}")
                C = step3_alice(pub_key_c,r,pub_key_a)
                
                proof = Proof(  amount=promise_amount,
                                id=keyset,
                                secret=secret_msg,
                                C=C.serialize().hex(),
                                Y = Y.serialize().hex()
                              
                                 
                                )
                
                proofs.append(proof)
                # print(proofs)
                i+=1
        except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as e:
            self.logger.warning("op=swap_for_payment_inputs status=failed error=%s", e)
        
        for each in proofs:
            pass
            # print(each.amount)
        # now need break out proofs for payment and proofs remaining

        return proofs
            
    async def accept_token(
        self,
        cashu_token: str,
        comment: str = "ecash deposit",
        tendered_amount: float | None = None,
        tendered_currency: str = "SAT",
    ):
        self.logger.debug("op=accept_token status=start comment=%s", comment)
        # asyncio.run(self.nip17_accept(cashu_token))
        # msg_out, token_accepted_amount = await self._async_token_accept(cashu_token)
        # self.set_wallet_info(label="trusted_mints", label_info=json.dumps(self.trusted_mints))

        
        
        # return f'Not implemented', 0
        
        lock_acquired = False
        try:

            
            token_amount =0

            if cashu_token[:6] == "cashuA":

                
                token_obj = TokenV3.deserialize(cashu_token)
                
                
                        # need to inspect if a new mint

                proofs=[]
                proof_obj_list: List[Proof] = []
                for each in token_obj.token: 
                    # print(each.mint)
                    for each_proof in each.proofs:
                        
                        proofs.append(each_proof.model_dump())
                        proof_obj_list.append(each_proof)
                        id = each_proof.id
                        self.known_mints[id]=each.mint
                        token_amount += each_proof.amount
                        # print(id, each.mint)

            


            elif cashu_token[:6] == "cashuB":
                    token_obj = TokenV4.deserialize(cashu_token)
                    # print(token_obj)
                    proofs=[]
                    proof_obj_list: List[Proof] = []
                    for each_proof in token_obj.proofs:
                        proofs.append(each_proof.model_dump())
                        proof_obj_list.append(each_proof)
                        id = each_proof.id
                        token_amount += each_proof.amount
                    self.known_mints[id]=token_obj.mint
            else:
                raise ValueError("Not a valid cashu token format")
              
            swap_proofs = await self.swap_proofs(proof_obj_list)
            self.logger.debug(
                "op=accept_token status=swapped token_amount=%s input_proofs=%s output_proofs=%s",
                token_amount,
                len(proof_obj_list),
                len(swap_proofs),
            )
            
            await self.acquire_lock()
            lock_acquired = True
            await self.add_proofs_obj(swap_proofs)

        
            
            self.logger.info("op=accept_token status=success token_amount=%s", token_amount)
        except (ValueError, TypeError, RuntimeError, httpx.HTTPError) as e:
            self.logger.error("op=accept_token status=failed error=%s", e)
            raise RuntimeError(f"Is token already spent? {e}") from e
            
        
        finally:
            if lock_acquired:
                await self.release_lock()
        self.balance+=token_amount
        # print(f"accept token new balance is: {self.balance}")
        await self.add_tx_history(
            tx_type='C',
            amount=token_amount,
            comment=comment,
            tendered_amount=tendered_amount,
            tendered_currency=tendered_currency,
        )
        return f'Successfully accepted {token_amount} sats!', token_amount


       

        


    async def issue_token(self, amount:int, comment:str = "ecash withdrawal"):

        lock_acquired = False
        try:
            await self.acquire_lock()
            lock_acquired = True
            # print("issue token")
            available_amount = 0
            chosen_keyset = None
            keyset_proofs,keyset_amounts = self._proofs_by_keyset()
            for each in keyset_amounts:
                available_amount += keyset_amounts[each]
            
            
            
            self.logger.debug("op=issue_token status=balance amount=%s available=%s", amount, available_amount)
            if available_amount < amount:                
                raise ValueError("Insufficient balance.")
                # msg_out = "insufficient balance. you need more funds!"
                # return msg_out
            
            for key in sorted(keyset_amounts, key=lambda k: keyset_amounts[k]):
                
                self.logger.debug(f"{key} {keyset_amounts[key]}")
                if keyset_amounts[key] >= amount:
                    chosen_keyset = key
                    break
            if not chosen_keyset:
               
                self.logger.error("op=issue_token status=no_single_keyset amount=%s", amount)
                raise ValueError("Insufficient balance in a single keyset; swap required.")
            
            proofs_to_use = []
            proof_amount = 0
            proofs_from_keyset = keyset_proofs[chosen_keyset]
            while proof_amount < amount:
                pay_proof = proofs_from_keyset.pop()
                proofs_to_use.append(pay_proof)
                proof_amount += pay_proof.amount
                self.logger.debug("op=issue_token selecting_proof keyset=%s amount=%s", chosen_keyset, pay_proof.amount)
                
            self.logger.debug(
                "op=issue_token status=prepared keyset=%s proofs_to_use=%s",
                chosen_keyset,
                len(proofs_to_use),
            )
            
            proofs_remaining = await self.swap_for_payment_multi(chosen_keyset,proofs_to_use, amount)
            

            self.logger.debug("op=issue_token status=swap_complete amount=%s proofs_remaining=%s", amount, len(proofs_remaining))
            # Implement from line 824
            sum_proofs =0
            spend_proofs = []
            keep_proofs = []
            for each in proofs_remaining:
                
                sum_proofs += each.amount
                if sum_proofs <= amount:
                    spend_proofs.append(each)
                    self.logger.debug(f"pay with {each.amount}, {each.secret}")
                else:
                    keep_proofs.append(each)
                    self.logger.debug(f"keep {each.amount}, {each.secret}")
            self.logger.debug(f"spend proofs: {spend_proofs}") 
            self.logger.debug(f"keep proofs: {keep_proofs}")

            for each in keep_proofs:
                proofs_from_keyset.append(each)
            # print("self proofs", self.proofs)
            # need to reassign back into 
            keyset_proofs[chosen_keyset]= proofs_from_keyset
            # OK - now need to put proofs back into a flat lish
            post_payment_proofs = []
            for key in keyset_proofs:
                each_proofs = keyset_proofs[key]
                for each_proof in each_proofs:
                    post_payment_proofs.append(each_proof)
            self.proofs = post_payment_proofs
            
            #TODO change this to write_proof
            await self.write_proofs()
            # await self.add_proofs_obj(post_payment_proofs)
            
            # await self._load_proofs()


            
            tokens = TokenV3Token(mint=self.known_mints[chosen_keyset],
                                            proofs=spend_proofs)
            
            v3_token = TokenV3(token=[tokens],memo="hello", unit="sat")
            # print("proofs remaining:", proofs_remaining)
        except (ValueError, TypeError, RuntimeError, httpx.HTTPError) as e:
            self.logger.error("op=issue_token status=failed amount=%s error=%s", amount, e)
            raise RuntimeError(f"Error issuing token: {e}") from e
        finally:
            if lock_acquired:
                await self.release_lock()

        self.balance -= amount
        await self.add_tx_history(tx_type='D',amount=amount,comment=comment)
        
        return v3_token.serialize()   

    async def zap(self, amount:int, event_id, comment): 
        out_msg = ""
        prs = []
        orig_address = event_id

        try:
            if '.' in event_id:
                if '@' in event_id:
                    pass
                else:
                    event_id = "_@" + event_id
            
                npub_hex, relays = nip05_to_npub(event_id)
                npub = hex_to_bech32(npub_hex)
                self.logger.debug(f"npub: {npub}")
                event_id = npub
            
        except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
            raise ValueError(f"could not resolve nip05")
            

        if event_id.startswith("note"):
            try:
                event_id = bech32_to_hex(event_id)
            except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
                return "Note id format is invalid. Please check and try again."
            try:
                zap_filter = [{  
                'ids'  :  [event_id]          
                
                }]
                prs = await self._async_query_zap(amount, comment,zap_filter)
            except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
                raise ValueError("Could not find event. Try an additional relay?")
                # return "Could not find event. Try an additional relay?"
            

        elif event_id.startswith("npub"):  
            pub_hex = bech32_to_hex(event_id)
            profile_filter =  [{
                'limit': 1,
                'authors': [pub_hex],
                'kinds': [0]
            }]
            prs = await self._async_query_npub(amount, comment, profile_filter)
            self.logger.debug(f"Filter: {profile_filter}")
            # raise ValueError(f"You are zapping to a npub {event_id}") 
            out_msg = f"You are zapping {amount} to {orig_address} with {prs}"
        else:
            raise ValueError(f"need a note or npub") 

        try:
            for each_pr in prs:
                await self.pay_multi_invoice(each_pr)
                out_msg+=f"\nZapped {amount} to destination: {orig_address}."
        except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as e:
            out_msg = f"Error {e}"
        
        return out_msg   
    
    async def _async_query_zap(self, amount:int, comment:str, filter: List[dict]): 
    # does a one off query to relay prints the events and exits
        json_obj = {}
        zaps_to_send = []
        event = None
        # print("are we here today", self.relays)
        async with ClientPool([self.home_relay]+self.relays) as c:        
            events = await c.query(filter)
        try:
            event = events[0]  
            self.logger.debug(f"event: {event}")  
            json_str =   f"{event.id}  {event.pub_key}  {event.content} {event.tags}"
            self.logger.debug(f"json_str: {json_str}")
            # json_obj = json.loads(json_str)
            # json_obj = json.loads(json_str)
        except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
            {"status": "could not access profile"}
            pass
       
        if event == None:
            raise RuntimeError("no event")
        
        for each in event.tags:
            if each[0] == "zap":
                zaps_to_send.append((each[1],each[2],each[3]))
        if zaps_to_send == []:
            zaps_to_send =[(event.pub_key,None,1)]
        
        self.logger.debug(f"zaps to send: {zaps_to_send}")

        prs = []
        for each_zap in zaps_to_send:
            zap_amount = int(amount * float(each_zap[2]))
            zap_amount = 1 if zap_amount ==0 else zap_amount
            profile_filter =  [{
                'limit': 1,
                'authors': [each_zap[0]],
                'kinds': [0]
            }]    
            async with ClientPool([self.home_relay]+self.relays) as c:        
                events_profile = await c.query(profile_filter)
            try:
                self.logger.debug("getting profile")
                event_profile = events_profile[0]  
                self.logger.debug(event)  
                profile_str =   event_profile.content
                self.logger.debug(f"profile {profile_str}")
                profile_obj = json.loads(profile_str)
                lnaddress = profile_obj['lud16']
                self.logger.debug(f" Pay to:{lnaddress}, {lnaddress_to_lnurl(lnaddress)}")

                
            except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
                {"status": "could not access profile"}
                self.logger.error("could not get profile")
                pass
            
            # Now we can create zap request
            self.logger.debug("create zap request")
            tags =  [   ["lnurl",lnaddress_to_lnurl(lnaddress)],
                        ["relays"] + self.relays,
                        ["amount",str(zap_amount*1000)],
                        ["p",each_zap[0]],
                        ["e",filter[0]['ids'][0]]
                    ]
            zap_request = Zevent(
                                kind=9734,
                                content=comment,
                                tags = tags,
                                pub_key=self.pubkey_hex                            
                                )
            zap_request.sign(self.privkey_hex)
            self.logger.debug(f"zap is valid: {zap_request.is_valid()}")
            self.logger.debug(f" {zap_request}, {zap_request.tags}, {zap_request.id}")
            self.logger.debug(f"serialize: {zap_request.serialize()}")
            self.logger.debug(f"to_dict: {zap_request.to_dict()}")
            zap_dict= zap_request.to_dict()
            self.logger.debug(f"zap_dict: {zap_dict}" )
            
            zap_test = Event().load(zap_dict)
            self.logger.debug(f"zap_test.id: {zap_test.id}")
            self.logger.debug(f"zap test  {zap_test}, {zap_test.is_valid()}")
            pr,_,_ = zap_address_pay(zap_amount,lnaddress,zap_dict)
            self.logger.debug(f"pay this invoice from the safebox: {pr}")
            prs.append(pr)
        
        return prs
    async def _async_query_npub(self, amount:int, comment:str, filter: List[dict]):
        prs = []
        async with ClientPool([self.home_relay]+self.relays) as c:        
            events_profile = await c.query(filter)
            try:
                self.logger.debug("getting profile")
                event_profile = events_profile[0]  
                self.logger.debug(event_profile)  
                profile_str =   event_profile.content
                self.logger.debug(f"profile {profile_str}")
                profile_obj = json.loads(profile_str)
                lnaddress = profile_obj['lud16']
                self.logger.debug(f" Pay to:{lnaddress}, {lnaddress_to_lnurl(lnaddress)}")

                # Now we can create zap request
                self.logger.debug("create zap request for profile")
                tags =  [   ["lnurl",lnaddress_to_lnurl(lnaddress)],
                            ["relays"] + self.relays,
                            ["amount",str(amount*1000)],
                            ["p",event_profile.pub_key]
                            
                        ]
                zap_request = Zevent(
                                    kind=9734,
                                    content=comment,
                                    tags = tags,
                                    pub_key=self.pubkey_hex                            
                                    )
                zap_request.sign(self.privkey_hex)
                self.logger.debug(f"zap is valid: {zap_request.is_valid()}")
                self.logger.debug(f" {zap_request}, {zap_request.tags}, {zap_request.id}")
                self.logger.debug(f"serialize: {zap_request.serialize()}")
                self.logger.debug(f"to_dict: {zap_request.to_dict()}")
                zap_dict= zap_request.to_dict()
                self.logger.debug(f"zap_dict: {zap_dict}" )
                
                zap_test = Event().load(zap_dict)
                self.logger.debug(f"zap_test.id: {zap_test.id}")
                self.logger.debug(f"zap test  {zap_test}, {zap_test.is_valid()}")

                #### End of Zap stuff

                # ln_return = lightning_address_pay(amount=amount,lnaddress=lnaddress,comment=comment)
                # pr = ln_return['pr']

                pr,_,_ = zap_address_pay(amount,lnaddress,zap_dict)

                self.logger.debug(f"zap pr: {pr}")
                prs.append(pr)
               
                
            except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
                {"status": "could not access profile"}
                self.logger.error("could not get profile")
                pass
       
        return prs
    
    def monitor(self, nrecipient: str, relays: List[str]=None):
        self.logger.debug("op=monitor status=start recipient=%s", nrecipient)
        try:
            if '@' in nrecipient:
                npub_hex, relays = nip05_to_npub(nrecipient)
                npub = hex_to_bech32(npub_hex)
                self.logger.debug("op=monitor status=resolved_npub npub=%s", npub)
                
            else:
                npub = nrecipient
                npub_hex = bech32_to_hex(nrecipient)
        except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
            return "error"
        
        self.logger.debug("op=monitor status=resolved recipient=%s", npub)
        # url = ['wss://relay.damus.io']
        url = relays
        asyncio.run(self.listen_notes(url, npub))
        while True:
            
            pass
        return 
    



    async def listen_notes(self, url, npub):


        AS_K = self.privkey_bech32
        # print("privkey", self.privkey_bech32)
        TO_K = npub
        tail = util_funcs.str_tails
        since = datetime.now().timestamp()
        # nip59 gift wrapper
        my_k = Keys(AS_K)
        my_gift = GiftWrap(BasicKeySigner(my_k))
        send_k = Keys(pub_k=TO_K)

        self.logger.info("op=listen_notes status=running")

        # q before printing events
        print_q = asyncio.Queue()

        # as we're using a pool we'll see the same events multiple times
        # DeduplicateAcceptor is used to ignore them
        # my_dd = DeduplicateAcceptor()


        # used for both eose and adhoc
        def my_handler(the_client: Client, sub_id: str, evt: Event):
            print_q.put_nowait(evt)

        def on_connect(the_client: Client):
            # oxchat seems to use a large date jitter... think 8 days is enough
            since = util_funcs.date_as_ticks(datetime.now() - timedelta(hours=24*8))

            the_client.subscribe(handlers=my_handler,
                                filters=[
                                    # can only get events for us from relays, we need to store are own posts
                                    {
                                        'kinds': [Event.KIND_GIFT_WRAP],
                                        '#p': [my_k.public_key_hex()]
                                    }
                                ]
                                )


        def on_auth(the_client: Client, challenge):
            self.logger.debug("op=listen_notes status=auth_requested")


        # create the client and start it running
        c = ClientPool(url,
                    on_connect=on_connect,
                    on_auth=on_auth,
                    on_eose=my_handler)
        asyncio.create_task(c.run())

        def sigint_handler(signal, frame):
            self.logger.debug("op=listen_notes status=stopping_listener")
            c.end()
            sys.exit(0)

        signal.signal(signal.SIGINT, sigint_handler)

        async def output(since):
            while True:
                events: List[Event] = await print_q.get()
                # because we use from both eose and adhoc, when adhoc it'll just be single event
                # make [] to simplify code
                if isinstance(events, Event):
                    events = [events]

                events = [await my_gift.unwrap(evt) for evt in events]
                # can't be sorted till unwrapped
                events.sort(reverse=True)

                for c_event in events:
                    if c_event.created_at.timestamp() > since:
                        self.logger.debug("op=listen_notes status=event event_id=%s", c_event.id)
                        content = c_event.content
                        array_token = content.splitlines()
                    
                        
                        for each in array_token:
                            if each.startswith("cashuA"):
                                
                                
                                # print(f"found token! {each}")
                                msg_out = await self._async_token_accept(each)
                                self.logger.info("op=listen_notes status=token_processed")
                                    
                                
                            elif each.startswith("creqA"):
                                self.logger.debug("op=listen_notes status=request_found token=%s", each)
                    


        asyncio.create_task(output(since))

        msg_n = ''
        while msg_n != 'exit':
            msg_n = await aioconsole.ainput('')
            # msg_n = msg.lower().replace(' ', '')


            send_evt = Event(content=msg_n,
                            tags=[
                                ['p', send_k.public_key_hex()]
                            ])

            wrapped_evt, trans_k = await my_gift.wrap(send_evt,
                                                    to_pub_k=send_k.public_key_hex())
            c.publish(wrapped_evt)
            # print("published")
            self.logger.debug(f"send dm to {send_k.public_key_hex()}")

            # this version is for us.. this seems to be the way oxchat does it I think but you could
            # just store locally though it'd be a pain getting your events on different instance
            await asyncio.sleep(0.2)
            # wrapped_evt, trans_k = await my_gift.wrap(send_evt,
            #                                       to_pub_k=my_k.public_key_hex())
            # c.publish(wrapped_evt)


            # if msg_n != '' and msg_n != 'exit':
            #     tags = []
            #     if to_user:
            #         tags = [['p', to_user.public_key_hex()]]
            #
            #     n_event = Event(kind=Event.KIND_TEXT_NOTE,
            #                     content=msg,
            #                     pub_key=as_user.public_key_hex(),
            #                     tags=tags)
            #     n_event.sign(as_user.private_key_hex())
            #     client.publish(n_event)

        self.logger.debug("op=listen_notes status=stopped")
        c.end()

    async def listen_nip17(self, url):


        AS_K = self.privkey_bech32

        tail = util_funcs.str_tails
        since = datetime.now().timestamp()
        since_ticks = util_funcs.date_as_ticks(datetime.now() - timedelta(minutes=1))
        # since_ticks = util_funcs.date_as_ticks(datetime.now())

        # nip59 gift wrapper
        my_k = Keys(AS_K)
        my_gift = GiftWrap(BasicKeySigner(my_k))


  

        # print(f'running as npub{tail(my_k.public_key_bech32()[4:])}, messaging npub{tail(send_k.public_key_bech32()[4:])}')
        self.logger.info("op=listen_nip17 status=running")

        # q before printing events
        print_q = asyncio.Queue()

        # as we're using a pool we'll see the same events multiple times
        # DeduplicateAcceptor is used to ignore them
        # my_dd = DeduplicateAcceptor()


        # used for both eose and adhoc
        def my_handler(the_client: Client, sub_id: str, evt: Event):
            print_q.put_nowait(evt)

        def on_connect(the_client: Client):
            # oxchat seems to use a large date jitter... think 8 days is enough
            since = util_funcs.date_as_ticks(datetime.now() - timedelta(hours=24*8))

            the_client.subscribe(handlers=my_handler,
                                filters=[
                                    # can only get events for us from relays, we need to store are own posts
                                    {
                                        'kinds': [Event.KIND_GIFT_WRAP],
                                        '#p': [my_k.public_key_hex()]
                                    }
                                ]
                                )


        def on_auth(the_client: Client, challenge):
            self.logger.debug("op=listen_nip17 status=auth_requested")


        # create the client and start it running
        c = ClientPool(url,
                    on_connect=on_connect,
                    on_auth=on_auth,
                    on_eose=my_handler)
        asyncio.create_task(c.run())

        def sigint_handler(signal, frame):
            self.logger.debug("op=listen_nip17 status=stopping_listener")
            c.end()
            sys.exit(0)

        signal.signal(signal.SIGINT, sigint_handler)

        async def output(since):
            # print("output")
            home_directory = os.path.expanduser('~')
            log_directory = '.safebox'
            log_file = 'log.txt'
            log_directory = os.path.join(home_directory, log_directory)
            file_path = os.path.join(home_directory, log_directory, log_file)

            while True:
                events: List[Event] = await print_q.get()
                # because we use from both eose and adhoc, when adhoc it'll just be single event
                # make [] to simplify code
                if isinstance(events, Event):
                    events = [events]

                events = [await my_gift.unwrap(evt) for evt in events]
                # can't be sorted till unwrapped
                events.sort(reverse=True)

                for c_event in events:
                    if c_event.created_at.timestamp() > since:
                        msg_out =''
                        self.logger.debug("op=listen_nip17 status=event event_id=%s", c_event.id)
                        content = c_event.content                           

                        array_token = content.splitlines()                        
                            
                        for each in array_token:
                            if each.startswith("cashuA"):                                   
                                    
                                # print(f"found token! {each}")
                                msg_out = await self.nip17_accept(each)
                                # print(self.trusted_mints)
                                # await self._async_set_wallet_info(label="trusted_mints", label_info=json.dumps(self.trusted_mints))
                                # print(msg_out)
                                        
                                    
                            elif each.startswith("creqA"):
                                msg_out = "creqA"
                            
                        TO_K = c_event.pub_key
                        send_k = Keys(pub_k=TO_K)
                        # print(send_k, c_event.content)
                        msg_n = c_event.content
                        send_evt = Event(content=msg_n,
                            tags=[
                                ['p', send_k.public_key_hex()]
                            ])

                        wrapped_evt, trans_k = await my_gift.wrap(send_evt,
                                                    to_pub_k=send_k.public_key_hex())
                        c.publish(wrapped_evt)

                        with open(file_path, "a+") as f:   
                            pass    
                            f.write(f"{c_event.created_at} {c_event.pub_key} {content} {msg_out}\n")
                            f.flush()  # Ensure the log is written to disk


        asyncio.create_task(output(since_ticks))
        msg_n = ''
        while msg_n != 'exit':
            msg_n = await aioconsole.ainput('')
                  
            
            await asyncio.sleep(0.2)
            

           

        self.logger.debug("op=listen_nip17 status=stopped")
        c.end()

       

    def run(self, listen_relay: List[str]= None):
        # print(f"\n listening for ecash for: {self.pubkey_bech32}")
        
        # asyncio.run(self._async_run())
        # npub = 'npub19xlhmu806lf7yh62kmr6gg4qus9uyss4sr9jeylqqvtud36cuxls2h9s37'
        
        if listen_relay:
            url = listen_relay
        else:
            url = [self.home_relay]
        
        asyncio.run(self.listen_nip17(url))
      
        

    async def _async_run(self):
       
        task1 = asyncio.create_task(self._async_task())
       
        await asyncio.sleep(10)
        self.logger.debug("op=async_run status=start")
        await task1

    async def _async_task(self):
       
     
        await asyncio.sleep(1)
        self.logger.debug("op=async_task status=start")

    def create_payment_request( self, 
                                amount:int, 
                                unit:str='sat', 
                                single_use: bool=True,
                                description: str = "Payment"):
        payment_request_dict = {}
        random_id = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))

        payment_request_dict['i'] = random_id
        payment_request_dict['a'] = amount
        payment_request_dict['u'] = unit
        payment_request_dict['s'] = single_use
        payment_request_dict['d'] = description
        payment_request_dict['m'] = self.mints
        payment_request_dict['t'] = {
                                    "t":"nostr",
                                    "a": "nprofile",
                                    "g": [["n","17"]]

                                    }

        self.logger.debug("op=get_payment_request status=payload_ready")
        cbor_data = cbor2.dumps(payment_request_dict)
        base64_encoded_data = base64.b64encode(cbor_data)
        base64_string = base64_encoded_data.decode('utf-8')

        payment_request = "creqA" + base64_string
        return payment_request

    async def _async_token_accept(self, token:str):
        return

    async def issue_private_record(self, content:str, holder:str=None, kind:int =34002, origsha256:str = None)->Event:
        """Issue private record"""
        holder_pubhex = ""
        if holder:
            try:
                holder_key = Keys(pub_k=holder)
                holder_pubhex = holder_key.public_key_hex()
            except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
                self.logger.warning("Invalid holder key supplied for private record: %s", exc)
            
        
        tags = [["safebox", self.pubkey_hex], ["safebox_owner", npub_to_hex(self.owner)],["safebox_holder", holder_pubhex]]
        if origsha256:
            tags.append(["origsha25",origsha256])

        issued_record = Event(  pub_key=self.pubkey_hex,
                                kind=kind,
                                tags = tags,
                                content=content)
        issued_record.sign(self.privkey_hex)

        return issued_record
    
    async def create_grant_from_offer(self, offer_kind:int, offer_name:str, holder: str, grant_kind:int=None,shared_secret_hex: str=None, relays: List[str]=None, blossom_xfer_server:str=None):
        """This function creates a corresponding grant for an offer and if an orginal record (blob) exists for the record, it will create the transfer blob"""
        blob_data: bytes = None
        blob_type: str = None
        original_record: OriginalRecordTransfer = None
        h_pubhex = Keys(pub_k=holder).public_key_hex()

        blossom_server = "https://blossom.getsafebox.app"
        if not blossom_xfer_server:
            blossom_xfer_server = "https://nostr.download"
        
        # blossom_xfer_server = "https://blossom.getsafebox.app"

        mime_type_guess = None
        origsha256 = None
        encrypt_parms = None

        if not (30000 <= offer_kind < 40000 and offer_kind % 2 == 1):
            """Create a grant from an offer"""
            raise ValueError("offer_kind must be an odd integer in the range 30000–39999")
        
        # If grant kind is not supplied, the convention is that the grant kind is an increment of 1
        if not grant_kind:
            grant_kind = offer_kind +1
        
        # Get the offer

        
        safebox_record: SafeboxRecord = await self.get_record_safebox(record_name=offer_name,record_kind=offer_kind)
        
        self.logger.debug("op=create_grant_from_offer status=payload_loaded")
        blob_type,blob_data = await self.get_record_blobdata(record_name=offer_name,record_kind=offer_kind)
        
        issued_private_record: Event = await self.issue_private_record(content=safebox_record.payload,holder=h_pubhex,kind=grant_kind)
        # Need to create original_transfer to tell where to pick up

        if blob_data:
            
            self.logger.debug("op=create_grant_from_offer status=blob_found type=%s size=%s", blob_type, len(blob_data))


            self.logger.debug("op=create_grant_from_offer status=encrypt_blob")
            origsha256 = hashlib.sha256(blob_data).hexdigest()
            self.logger.debug("op=create_grant_from_offer status=origsha256")
            origmime_type_guess = filetype.guess(blob_data).mime
            self.logger.debug("op=create_grant_from_offer status=mime mime=%s", origmime_type_guess)
            if shared_secret_hex:
                blob_key = bytes.fromhex(shared_secret_hex)
                self.logger.debug("op=create_grant_from_offer status=shared_secret_from_kem")
            else:
                blob_key = os.urandom(32)  # 256-bit key
            try:    
                self.logger.debug("op=create_grant_from_offer status=encrypting")
                encrypt_result:EncryptionResult = encrypt_bytes(blob_data, blob_key)
                encrypt_parms = EncryptionParms(alg=encrypt_result.alg,key=blob_key.hex(),iv=encrypt_result.iv.hex())
            except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as e:
                self.logger.exception("Encryption error while creating grant from offer")
                raise RuntimeError(f"encryption error while creating grant: {e}") from e

            # final_blob_data = blob_data
            final_blob_data = encrypt_result.cipherbytes
            self.logger.debug("op=create_grant_from_offer status=upload_blob")
            blob_nsec = Keys().private_key_bech32()
            client_xfer = BlossomClient(nsec=blob_nsec, default_servers=[blossom_xfer_server])
            upload_result = client_xfer.upload_blob(blossom_xfer_server, data=final_blob_data,
                            description='Blob to server')
            sha256 = upload_result['sha256']
            blob_ref = upload_result.get('url', f"{blossom_xfer_server}/{sha256}")
            # blob_ref = upload_result['sha256']
            blob_type = upload_result['type']
            self.logger.debug("op=create_grant_from_offer status=blob_uploaded")
            # await asyncio.sleep(5)

            # Create what is necessary for original record trasfer
            original_record = OriginalRecordTransfer(   origsha256=origsha256,
                                                        origmimetype=origmime_type_guess,
                                                        encryptparms=encrypt_parms,
                                                        blobserver= blossom_xfer_server,
                                                        blobsha256=sha256,
                                                        blobmimetype=blob_type,
                                                        blobref=blob_ref,
                                                        blobnsec=blob_nsec
                                                    )


            #TODO Eliminate the delete function once the receiving party can clean it up
            # delete_result = client_xfer.delete_blob(server=blossom_xfer_server,sha256=sha256)
            # print(f"Delete result: {delete_result}")
        else:
            self.logger.debug("op=create_grant_from_offer status=no_blob offer=%s kind=%s", offer_name, offer_kind)


        issued_private_record: Event = await self.issue_private_record(content=safebox_record.payload,holder=h_pubhex,kind=grant_kind, origsha256=origsha256)
        self.logger.debug("op=create_grant_from_offer status=issued")
        return issued_private_record, original_record
    
    async def create_request_from_grant(self, grant_name:str, grant_kind:int=34102, shared_secret_hex: str=None, relays: List[str]=None, blossom_xfer_server:str=None):
        """This function creates a request that can be sent for verififcation and if an orginal record (blob) exists for the record, it will create the transfer blob"""
        blob_data: bytes = None
        blob_type: str = None
        original_record: OriginalRecordTransfer = None
        

        blossom_server = "https://blossom.getsafebox.app"
        if not blossom_xfer_server:
            blossom_xfer_server = "https://nostr.download"
        
        # blossom_xfer_server = "https://blossom.getsafebox.app"

        mime_type_guess = None
        origsha256 = None
        encrypt_parms = None

        self.logger.debug("op=create_request_from_grant status=grant_kind kind=%s", grant_kind)

        if not (30000 <= grant_kind < 40000 and grant_kind % 2 == 0):
            """Create a grant from an offer"""
            raise ValueError("offer_kind must be an odd integer in the range 30000–39999")
        

        
        # Get the grant record to send

        self.logger.debug("op=create_request_from_grant status=load_record grant=%s kind=%s", grant_name, grant_kind)
        safebox_record: SafeboxRecord = await self.get_record_safebox(record_name=grant_name,record_kind=grant_kind)
        
        self.logger.debug("op=create_request_from_grant status=payload_loaded")
        blob_type,blob_data = await self.get_record_blobdata(record_name=grant_name,record_kind=grant_kind)
        
        # issued_private_record: Event = await self.issue_private_record(content=safebox_record.payload,# holder=h_pubhex,kind=grant_kind)
        # The grant record is a signed event that stored as a serialized payload in the safebox record
        try:
            payload_json = json.loads(safebox_record.payload)
            self.logger.debug("op=create_request_from_grant status=payload_json_loaded")
            payload_json['pub_key'] = payload_json['pubkey'] 
            del payload_json['pubkey']
            issued_grant_record = Event(**payload_json)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            self.logger.exception("Error retrieving grant record")
            raise ValueError(f"error retrieving grant record {e}") from e
        # Need to create original_transfer to tell where to pick up

        if blob_data:
            
            self.logger.debug("op=create_request_from_grant status=blob_found type=%s size=%s", blob_type, len(blob_data))


            self.logger.debug("op=create_request_from_grant status=encrypt_blob")
            origsha256 = hashlib.sha256(blob_data).hexdigest()
            self.logger.debug("op=create_request_from_grant status=origsha256")
            origmime_type_guess = filetype.guess(blob_data).mime
            self.logger.debug("op=create_request_from_grant status=mime mime=%s", origmime_type_guess)
            if shared_secret_hex:
                blob_key = bytes.fromhex(shared_secret_hex)
                self.logger.debug("op=create_request_from_grant status=shared_secret_from_kem")
            else:
                blob_key = os.urandom(32)  # 256-bit key
            try:    
                self.logger.debug("op=create_request_from_grant status=encrypting")
                encrypt_result:EncryptionResult = encrypt_bytes(blob_data, blob_key)
                encrypt_parms = EncryptionParms(alg=encrypt_result.alg,key=blob_key.hex(),iv=encrypt_result.iv.hex())
            except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as e:
                self.logger.exception("Encryption error while creating request from grant")
                raise RuntimeError(f"encryption error while creating request: {e}") from e

            # final_blob_data = blob_data
            final_blob_data = encrypt_result.cipherbytes
            self.logger.debug("op=create_request_from_grant status=upload_blob")
            blob_nsec = Keys().private_key_bech32()
            client_xfer = BlossomClient(nsec=blob_nsec, default_servers=[blossom_xfer_server])
            upload_result = client_xfer.upload_blob(blossom_xfer_server, data=final_blob_data,
                            description='Blob to server')
            sha256 = upload_result['sha256']
            blob_ref = upload_result.get('url', f"{blossom_xfer_server}/{sha256}")
            # blob_ref = upload_result['sha256']
            blob_type = upload_result['type']
            self.logger.debug("op=create_request_from_grant status=blob_uploaded")
            # await asyncio.sleep(5)

            # Create what is necessary for original record trasfer
            original_record = OriginalRecordTransfer(   origsha256=origsha256,
                                                        origmimetype=origmime_type_guess,
                                                        encryptparms=encrypt_parms,
                                                        blobserver= blossom_xfer_server,
                                                        blobsha256=sha256,
                                                        blobmimetype=blob_type,
                                                        blobref=blob_ref,
                                                        blobnsec=blob_nsec
                                                    )


            #TODO Eliminate the delete function once the receiving party can clean it up
            # delete_result = client_xfer.delete_blob(server=blossom_xfer_server,sha256=sha256)
            # print(f"Delete result: {delete_result}")
        else:
            self.logger.debug("op=create_request_from_grant status=no_blob grant=%s kind=%s", grant_name, grant_kind)


        # print(f"issued grant: {issued_grant_record.data()}")
        return issued_grant_record, original_record
    
    async def get_trusted_entities(self,kind:int=37376, relays: List[str]=None):

        pubhex_list_out = []
        try:
            record_out = await self.get_wallet_info(label="trusted entities", record_kind=kind)
            if record_out is None:
                return []
            record_out_json = json.loads(record_out)
            pubs_to_process = record_out_json.get("payload", "").split(" ")
        except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
            self.logger.debug("No trusted entities configured: %s", exc)
            return []
       
        for each in pubs_to_process:
            try:
                k_to_add = Keys(pub_k=each)
                # Now we are going to get the followers
                
                pubhex_list_out.append(k_to_add.public_key_hex())
            except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
                self.logger.debug("Skipping invalid root entity=%s error=%s", each, exc)
        
        self.logger.debug("op=get_trusted_entities status=expanded_roots count=%s relays=%s", len(pubhex_list_out), self.relays)
        FILTER = [{
            'limit': RECORD_LIMIT,
            'authors': pubhex_list_out,
            'kinds': [3]
        }]
        async with ClientPool(relays) as c:  
            events = await c.query(FILTER)
            if events:
                for each in events:
                    self.logger.debug("op=get_trusted_entities status=follow_tags event=%s tags=%s", each.id, each.tags)
                    for each_tag in each.tags:
                        if each_tag[0] == "p":
                            pubhex_list_out.append(each_tag[1])
        pubhex_list_out = list(set(pubhex_list_out))
        return pubhex_list_out

    async def get_root_entities(self,kind:int=37376, relays: List[str]=None):

        try:
            record_out = await self.get_wallet_info(label="trusted entities",record_kind=kind)
            if record_out is None:
                return ""
            record_out_json = json.loads(record_out)
            final_out = record_out_json.get('payload', "")
            if not isinstance(final_out, str):
                final_out = str(final_out)
        except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
            self.logger.debug("No root entities payload found: %s", exc)
            final_out = ""
        return final_out

    async def set_trusted_entities(self,kind:int=37376, pub_list_str: str=None):

        pubs_to_validate = pub_list_str.split()
        pubs_to_store = ''
        for each in pubs_to_validate:
            try:
                k_to_validate = Keys(pub_k=each)
                pubs_to_store += k_to_validate.public_key_bech32() + ' '
            except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
                self.logger.debug("Skipping invalid trusted entity npub=%s error=%s", each, exc)

        
        
        await self.put_record(record_name="trusted entities", record_value=pubs_to_store, record_kind=kind, record_type="internal")
        
        
        return True
        
    async def set_wot_entities(self,kind:int=37376, pub_list_str: str=None):

        pubs_to_validate = pub_list_str.split()
        self.logger.debug("op=set_wot_entities status=validate_input count=%s", len(pubs_to_validate))
        pubs_to_store = ''
        for each in pubs_to_validate:
            each_component = each.split(":")
            self.logger.debug("op=set_wot_entities status=parse_component component=%s", each_component)
            each_npub = each_component[0]
            part_2 = ':'+ each_component[1] if len(each_component)>=2 else ''
            part_3 = ':'+ each_component[2] if len(each_component)>=3 else ''
           

            try:
                k_to_validate = Keys(pub_k=each_npub)
                pubs_to_store += f"{k_to_validate.public_key_bech32()}{part_2}{part_3}" + ' '
            except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
                self.logger.debug("Skipping invalid wot entity npub=%s error=%s", each_npub, exc)

        
        
        await self.put_record(record_name="wot entities", record_value=pubs_to_store, record_kind=kind, record_type="internal")
        
        
        return True
    
    async def get_wot_entities(self,kind:int=37376, relays: List[str]=None):

        pubhex_list_out = []    
        try:
            record_out = await self.get_wallet_info(label="wot entities",record_kind=kind)
            if not record_out:
                return []
            record_out_json = json.loads(record_out)
            pubs_to_process = record_out_json.get('payload', '').split(' ')
            self.logger.debug("op=get_wot_entities status=processing count=%s", len(pubs_to_process))
        
            for each in pubs_to_process:
                each_component = each.split(":")   
                self.logger.debug("op=get_wot_entities status=parse_component component=%s", each_component)
                each_npub = each_component[0]
                if len(each_component)>=2:
                    part_2 = ':'+each_component[1] 
                else: 
                    part_2 = ''
                if len(each_component)>=3:
                    part_3 = ':'+each_component[2] 
                else: 
                    part_3 = ''


                    
                
                try:
                    k_to_add = Keys(pub_k=each_npub)
                    final_entry = f"{k_to_add.public_key_bech32()}{part_2}{part_3}"
                    self.logger.debug("op=get_wot_entities status=valid_entry entry=%s", final_entry)
                    
                    pubhex_list_out.append(final_entry)
                   
                except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
                    self.logger.debug("Skipping malformed wot score entity=%s error=%s", each, exc)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            self.logger.debug("Could not load wot entities: %s", exc)
            return []
        except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
            self.logger.warning("Could not load wot entities: %s", exc)
            return []
        
       

        return pubhex_list_out
    
    async def get_wot_scores(self, pub_key_to_score: str, relays: List[str]=None):
        rank = '0'
        scores_out = []
        try:
            k_to_use = Keys(pub_k=pub_key_to_score)
            pubhex = k_to_use.public_key_hex()
        except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
            return "invalid npub"
        

        
        wot_entities = await self.get_wot_entities()
        for each_wot in wot_entities:
            each_wot_npub, each_wot_tag, each_wot_relay = (each_wot.split(':') + [None, None, None])[:3]
            each_wot_relay = each_wot_relay if not each_wot_relay or each_wot_relay.startswith("wss://") else f"wss://{each_wot_relay}"
            self.logger.debug("op=get_wot_scores status=processing_entity npub=%s", each_wot_npub)
            FILTER = [{
            'limit': RECORD_LIMIT,
             '#d': [pubhex],                       
            'authors': [Keys(pub_k=each_wot_npub).public_key_hex()],
            'kinds': [30382]
            }]
            self.logger.debug("op=get_wot_scores status=query_filter")
            each_event: Event
            try:
                async with ClientPool(clients=[each_wot_relay],timeout=3) as c:  
                    events = await c.query(FILTER)
                    if events:
                        self.logger.debug("op=get_wot_scores status=events count=%s", len(events))
                        for each_event  in events:
                            self.logger.debug("op=get_wot_scores status=event_tags pubkey=%s", each_event.pub_key)
                            for each_tag in each_event.tags:
                                if each_tag[0] == each_wot_tag:
                                    score = 0
                                    score = each_tag[1]
                                    scores_out.append([each_wot_tag,score])
            except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
                self.logger.warning("Failed querying wot score relay=%s error=%s", each_wot_relay, exc)
        

        return scores_out

        try:
            k_to_use = Keys(pub_k=pub_key_to_score)
            pubhex = k_to_use.public_key_hex()
        except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
            pubhex = None

        FILTER = [{
            'limit': RECORD_LIMIT,
             '#d': [pubhex],                       
            'authors': wot_entities,
            'kinds': [30382]
        }]

        # print(f"FILTER {FILTER} with relays: {relays}")
        each: Event
        async with ClientPool(relays) as c:  
            events = await c.query(FILTER)
            if events:
                # print(f"total events: {len(events)}")
                for each  in events:
                    # print(f"tags from {each.pub_key} {each.tags}")
                    for each_tag in each.tags:
                        if each_tag[0] == 'rank':
                            rank = each_tag[1]

                        
        


        return rank
       
    async def get_social_profile(self,npub: str, relays: List[str]=None):
        try:
            pubhex = Keys(pub_k=npub).public_key_hex()
        except (RuntimeError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError, httpx.HTTPError) as exc:
            raise ValueError("Invalid public key")
        
        FILTER = [{
                'limit': 1,                                
                'authors': [pubhex],
                'kinds': [0]
                }]
        
        async with ClientPool(relays) as c:  
                    event: Event
                    events = await c.query(FILTER)
                    if events:
                        event = events[0]
                        social_profile = json.loads(event.content)

        return social_profile       
        
if __name__ == "__main__":
    
    # url = ['wss://relay.0xchat.com','wss://relay.damus.io']
    # this relay seems to work the best with these kind of anon published events, atleast for now
    # others it seems to be a bit of hit and miss...
    url = ['wss://relay.getsafebox.app']
    # asyncio.run(listen_notes(url))  
