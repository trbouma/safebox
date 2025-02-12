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
from zoneinfo import ZoneInfo
from datetime import timezone

from hotel_names import hotel_names
# from coolname import generate, generate_slug
from binascii import unhexlify
import hashlib
import signal, sys, string, cbor2, base64,os
from bip_utils import Bip39SeedGenerator, Bip32Slip10Ed25519



from monstr.encrypt import Keys
from monstr.encrypt import NIP44Encrypt, NIP4Encrypt
from monstr.client.client import Client, ClientPool
from monstr.event.event import Event


from monstr.signing.signing import BasicKeySigner
from monstr.giftwrap import GiftWrap
from monstr.util import util_funcs
from monstr.entities import Entities
from monstr.client.event_handlers import DeduplicateAcceptor

from safebox.monstrmore import KindOtherGiftWrap

tail = util_funcs.str_tails

from safebox.b_dhke import step1_alice, step3_alice, hash_to_curve
from safebox.secp import PrivateKey, PublicKey
from safebox.lightning import lightning_address_pay, lnaddress_to_lnurl, zap_address_pay
from safebox.nostr import bech32_to_hex, hex_to_bech32, nip05_to_npub

from safebox.models import nostrProfile, SafeboxItem, mintRequest, mintQuote, BlindedMessage, Proof, Proofs, proofEvent, proofEvents, KeysetsResponse, PostMeltQuoteResponse, walletQuote, NIP60Proofs
from safebox.models import TokenV3, TokenV3Token, cliQuote, proofsByKeyset, Zevent
from safebox.models import TokenV4, TokenV4Token
from safebox.models import WalletConfig, WalletRecord,WalletReservedRecords

from safebox.func_utils import generate_name_from_hex, name_to_hex, generate_access_key_from_hex

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
    home_relay: str
    home_mint: str
    known_mints: dict = {}
    local_currency: str = "SAT"
    authorities: List[str] = None
    providers: List[str] = None
    user_records = []
    relays: List[str]
    mints: List[str]
    safe_box_items: List[SafeboxItem]
    proofs: List[Proof]
    profile_found_on_home_relay = False
    events: int
    balance: int
    proof_events: proofEvents 
    replicate: bool
    RESERVED_RECORDS: List[str] = ["balance","privkey"]
    wallet_reserved_records: object
    logger: object
    TZ: str = "America/New_York"
    



    def __init__(   self, 
                    nsec: str, 
                    relays: List[str]|None=None, 
                    mints: List[str]|None=None,
                    home_relay:str|None=None, 
                    replicate = False, 
                    logging_level=logging.INFO) -> None:
        
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
   
    async def load_data(self):
        self.logger.debug("load data")

        try:
            wallet_info = await self.get_wallet_info(label="wallet")
            self.acorn_tags = json.loads(wallet_info)
            # self.acorn_tags = json.loads(self.get_wallet_info(label="wallet"))
           
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
        except Exception as e:
            print(f"error reading {e}")
            wallet_info_str = "None"
            # self.home_mint = mints[0]

        await self._load_proofs()
        return
    
    async def set_owner_data(self, npub:str = None, local_currency=None):

        update_tags = []
        if npub ==None and local_currency== None:
            return
        if npub:            
            try:
                npub_obj = Keys(pub_k=npub)
                update_tags.append(["owner",npub])                
            except:
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
                bip32_ctx = Bip32Slip10Ed25519.FromSeed(seed)
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
                bip32_ctx = Bip32Slip10Ed25519.FromSeed(seed)
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
        print("nprofile_str", n_profile_str)

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
            print(hello_msg)
            asyncio.run(self._async_send_post(hello_msg))
            print(out)

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
                print(profile_str)
                # this seems to work
                profile_2 = json.dumps(nostr_profile.model_dump(mode='json'))
                n_msg = Event(kind=0,
                        content=profile_2,
                        pub_key=self.pubkey_hex)
                n_msg.sign(self.privkey_hex)
                c.publish(n_msg)
            except:
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
                bip32_ctx = Bip32Slip10Ed25519.FromSeed(seed)
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
                bip32_ctx = Bip32Slip10Ed25519.FromSeed(seed)
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

        return self.privkey_bech32

    def get_profile(self, name="wallet"):
        mints = []
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

        return out_string






        return out_string
    
    def get_instance(self):
        pass
        return "this is the instance"

    async def get_user_records(self, record_kind:int=37375, since:int = None):

        events_out = []
        my_enc = NIP44Encrypt(self.k)
        my_gift = GiftWrap(BasicKeySigner(self.k))
        m = hashlib.sha256()
        m.update(self.privkey_hex.encode())
        # m.update(label.encode())
        # label_hash = m.digest().hex()
        decrypt_content = None

        # handle records that are coming in via giftware
        # 1059 are regular DMs
        # 1060 are health records
        # 1061 are health authentication messages
        # 1062 are shared notes
        # 1063 are official docs and credentials

        if record_kind in [1059,1060,1061,1062,1063,21059,21060,21061,21062,21063]:
            
           if since:        
                FILTER = [{
                'limit': 100, 
                '#p'  :  [self.pubkey_hex],              
                'kinds': [record_kind],
                'since': since
                
                }]
           else:
                FILTER = [{
                'limit': 100, 
                '#p'  :  [self.pubkey_hex],              
                'kinds': [record_kind]
                
                }]
               
        else:
                FILTER = [{
                'limit': 100,
                'authors': [self.pubkey_hex],
                'kinds': [record_kind]   
                
            }]


        async with ClientPool([self.home_relay]) as c:  
            events = await c.query(FILTER)           
        
        events.sort(reverse=True)

        for each in events:
            # print("x:", each.tags, each.kind, each.created_at)

            if record_kind in [1059,1060,1061,1062,1063,21059,21060,21061,21062,21063]:
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
                        
                        

                    except:
                
                        parsed_record = {   "tag": ["message"],
                                            "type": "dm",
                                            "created_at": unwrapped_event.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                                            "payload":unwrapped_event.content,
                                            "id": unwrapped_event.id
                                            }


                except Exception as e:
                    print(f"error: {e}")
            


            else:
                try:
                    decrypt_content = my_enc.decrypt(each.content, self.pubkey_hex)
                except:
                    # Try Gift Unwrapping
                    decrypt_event = my_enc.decrypt_event(each)
                    decrypt_content = decrypt_event.content
            
                try:
                    parsed_record = json.loads(decrypt_content)
                except:                
                    parsed_record = {"payload": decrypt_content}

                # check for special wallet record which is a list
                if isinstance(parsed_record,list):
                    pass
                else:
                    parsed_record['created_at'] = each.created_at.strftime("%Y-%m-%d %H:%M:%S")
                    parsed_record['id'] = each.id

            # Convert payload to json
            # See if payload is in stringifed json and convert
                    
            try:
                payload_obj = json.loads(parsed_record['payload'])
                parsed_record['payload'] = payload_obj
                        
            except:
                pass

            #check to see if wallet record and skip
            if isinstance(parsed_record,list):
                pass
            else:
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
        except:
            {"staus": "could not access profile"}
            pass
       
        # print("json_obj", json_obj)
        
        return json_str
        
    def replicate_safebox(self, replicate_relays = List[str]):
        
        print("replicate relays:", replicate_relays)

        FILTER = [{
            'limit': 1,
            'authors': [self.pubkey_hex],
            'kinds': [0]
        }]
        
        try:
            profile =asyncio.run(self.async_query_client_profile([self.home_relay],FILTER))
            profile_obj = nostrProfile(**json.loads(profile))
            print(profile_obj)
            asyncio.run(self._async_create_profile(profile_obj, replicate_relays=replicate_relays))
        except:
            out_string = "No profile found!"
            return out_string
        


        self.set_wallet_info(label="test", label_info="test record booga", replicate_relays=replicate_relays)
        # self.set_wallet_info(label="profile", label_info=json.dumps(nostr_profile.model_dump()))
       
        # replicate the reserved records

        profile = self.get_wallet_info(label="profile")
        print("replicate profile:", profile)
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
        print("trusted mints to replicate:", trusted_mints)
        self.set_wallet_info(label="trusted_mints", label_info=json.dumps(self.trusted_mints), replicate_relays=replicate_relays)
        
        quote = self.get_wallet_info(label="quote")
        print("quote to replicate:", quote)
        self.set_wallet_info(label="quote", label_info=quote,replicate_relays=replicate_relays)
        
        index = self.get_wallet_info(label="index")
        print("index to replicate:", index)
        self.set_wallet_info(label="index", label_info=index, replicate_relays=replicate_relays)
        
        last_dm = self.get_wallet_info(label="last_dm")
        print("last_dm to replicate:", last_dm)
        self.set_wallet_info(label="last_dm", label_info=last_dm, replicate_relays=replicate_relays)
        
        replicate_proofs = []
        for each in self.proofs:
            each_dump = each.model_dump()
            replicate_proofs.append(each_dump)
        print("now need to replicate the proofs", replicate_proofs)
        # self.add_proofs(json.dumps(replicate_proofs), replicate_relays=replicate_relays)
        self.add_proofs_obj(self.proofs, replicate_relays=replicate_proofs)
        return profile 
    
    async def _async_store_event(self, event_content_str:str, event_kind: int, relays: List[str]):

        async with ClientPool(relays) as c:
      
            print(event_content_str)
      
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
            'limit': 10,
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

    def send_ecash_dm(self,amount: int, nrecipient: str, ecash_relays:List[str], comment: str ="Sent!"):
        relays = []
        try:
            if '@' in nrecipient:
                npub_hex, relays = nip05_to_npub(nrecipient)
                npub = hex_to_bech32(npub_hex)
                print("npub", npub)
            else:
                npub = nrecipient
        except:
            return "error"
        try:
            token_amount = self.issue_token(amount=amount)
            token_msg = comment +"\n\n" + token_amount
        except:
            return "insufficient funds"
        
        print(f"sending via {ecash_relays}")
        out_msg = self.secure_dm(nrecipient=npub,message=token_msg,dm_relays=ecash_relays)
        # out_msg= asyncio.run(self._async_send_ecash_dm(token_msg,npub, ecash_relays+relays ))
        return out_msg
    

    async def _async_send_ecash_dm(self,token_message: str, npub: str, ecash_relays:List[str]):
        print("npub:", npub)
        
        my_enc = NIP4Encrypt(self.k)
        k_to_send = Keys(pub_k=npub)
        k_to_send_pubkey_hex = k_to_send.public_key_hex()
        print("k_to_send:", k_to_send_pubkey_hex)
        ecash_msg = token_message
        # ecash_info_encrypt = my_enc.encrypt(ecash_msg,to_pub_k=k_to_send_pubkey_hex)

        print("are we here?", ecash_relays)
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
    
    
    def get_ecash_dm(self):
        
        
        tags = ["#p", self.pubkey_hex]
        # last_dm = float(self.get_wallet_info("last_dm"))
        last_dm = float(self.wallet_reserved_records['last_dm'])
        # last_dm = 0
        print("last dm in wallet:", last_dm)
        print(datetime.fromtimestamp(float(last_dm)))
        #TODO need to figure out why the kind is not 1059
        dm_filter = [{
            
            'limit': 100, 
            '#p'  :  [self.pubkey_hex],
            'since': int(last_dm +1)
            
        }]
        final_dm, tokens =asyncio.run(self._async_query_ecash_dm(dm_filter))
        # final_dm, tokens =asyncio.run(self._async_query_secure_ecash_dm(dm_filter))
        print(tokens)
        for each in  tokens:
            self.accept_token(each)
        
        print(f"last dm is: {final_dm}")
        self.set_wallet_info("last_dm", str(final_dm))
        # self.swap_multi_each()
        
        return final_dm
    
    async def _async_query_ecash_dm(self, filter: List[dict]):
    # does a one off query to relay prints the events and exits
        my_enc = NIP4Encrypt(self.k)
        posts = ""
        tags = []
        tokens =[]
        
        last_dm = self.wallet_reserved_records['last_dm']
        final_dm = int(last_dm)
        print("filterxx:", filter)
        relay_pool = [self.home_relay]+self.relays
        print(relay_pool)
        async with ClientPool(relay_pool) as c:
        # async with Client(relay) as c:
            events: List[Event] = await c.query(filter)
            print("ecash events", events)
            if events:
                print("we got events!")
                for each in events:
                    try:
                        decrypt_content = my_enc.decrypt_event(each)
                    except:
                        print("no go")
                    
                    print("message", each.id, each.kind, each.created_at.timestamp(), decrypt_content.content )
                    # last_dm = each.created_at.timestamp() if each.created_at.timestamp() > last_dm else last_dm
                    # print("last event update", datetime.fromtimestamp(last_dm),)

                    dm_timestamp = int(each.created_at.timestamp())
                    print ("final_dm, dm_timestamp:",final_dm, dm_timestamp)
                    final_dm = dm_timestamp if dm_timestamp > final_dm else final_dm
                    print ("final_dm, dm_timestamp:",final_dm, dm_timestamp)
                    array_token = decrypt_content.content.splitlines()
                    print("array_token:", array_token)
                    
                    for each in array_token:
                        if each.startswith("cashuA"):
                            print("found")
                            token = each
                            tokens.append(token)
                            break
            else:
                print("no events!")    
                
                
        print("last update:", last_dm)    
        return final_dm, tokens          

    async def _async_query_secure_ecash_dm(self, filter: List[dict]):
    # does a one off query to relay prints the events and exits
        my_enc = NIP4Encrypt(self.k)
        posts = ""
        tags = []
        tokens =[]
        
        last_dm = self.wallet_reserved_records['last_dm']
        final_dm = int(last_dm)
        print("secure ecash filterxx:", filter)
        relay_pool = [self.home_relay]+self.relays
        print(relay_pool)
        async with ClientPool(relay_pool) as c:
        # async with Client(relay) as c:
            events: List[Event] = await c.query(filter)
            print("ecash events", events)
            if events:
                print("we got events!")
                for each in events:
                   
                    
                    print("message", each.id, each.kind, each.created_at.timestamp() )
                   
            else:
                print("no events!")    
                
                
        print("last update:", last_dm)    
        return final_dm, tokens               
       
    async def delete_dms(self, tags):
         async with ClientPool([self.home_relay]+self.relays) as c:
            print("hello")
            n_msg = Event(kind=Event.KIND_DELETE,
                        content=None,
                        pub_key=self.pubkey_hex,
                        tags=tags)
            print("dm tags",tags)
            n_msg.sign(self.privkey_hex)
            c.publish(n_msg)
            print("hello again")   

            
    async def secure_dm(self,nrecipient:str, message: str, dm_relays: List[str]):
        try:
            if '@' in nrecipient:
                npub_hex, relays = nip05_to_npub(nrecipient)
                npub = hex_to_bech32(npub_hex)
                print("npub", npub)
                dm_relays = dm_relays
            else:
                npub_hex = bech32_to_hex(nrecipient)
        except:
            return "error"
        self.logger.debug(f"send to: {nrecipient} {npub_hex}, {message} using {dm_relays}")

        await self._async_secure_dm(npub_hex=npub_hex, message=message,dm_relays=dm_relays) 
        return "message sent" 
    
    async def _async_secure_dm(self, npub_hex, message:str, dm_relays: List[str]):
       
        my_gift = GiftWrap(BasicKeySigner(self.k))
        
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
                
    async def secure_transmittal(self,nrecipient:str, message: str,  dm_relays: List[str],transmittal_kind: int=1060):
        try:
            if '@' in nrecipient:
                npub_hex, relays = nip05_to_npub(nrecipient)
                npub = hex_to_bech32(npub_hex)
                print("npub", npub)
                dm_relays = dm_relays
            else:
                npub_hex = bech32_to_hex(nrecipient)
        except:
            return "error"
        self.logger.debug(f"send to: {nrecipient} {npub_hex}, {message} using {dm_relays}")

        await self._async_secure_transmittal(npub_hex=npub_hex, message=message, dm_relays=dm_relays, transmittal_kind=transmittal_kind) 
        return "message sent" 
    
    async def _async_secure_transmittal(self, npub_hex, message:str,  dm_relays: List[str],transmittal_kind):
       
        my_gift = KindOtherGiftWrap(BasicKeySigner(self.k),kind_gift_wrap=transmittal_kind)
        
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

    async def set_wallet_info(self,label: str,label_info: str, replicate_relays: List[str]=None, record_kind: int=37375):
        await self._async_set_wallet_info(label,label_info,replicate_relays=replicate_relays, record_kind=record_kind)  
    
    async def _async_set_wallet_info(self, label:str, label_info: str, replicate_relays:List[str]=None, record_kind: int = 37375):

        m = hashlib.sha256()
        m.update(self.privkey_hex.encode())
        m.update(label.encode())
                 
        label_name_hash = m.digest().hex()
        
        # print(label, label_info)
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

    async def get_wallet_info(self, label:str=None, record_kind:int=37375):
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
            'limit': 100,
            'authors': [self.pubkey_hex],
            'kinds': [record_kind],
            '#d': [label_hash]   
            
            
        }]

        # print("are we here?", label_hash)
        event =await self._async_get_wallet_info(FILTER, label_hash)
        
        # print(event.data())
        try:
            decrypt_content = my_enc.decrypt(event.content, self.pubkey_hex)
        except:
            return f"Could not retrieve info for: {label}. Does a record exist?"
        


        return decrypt_content
    
    async def delete_wallet_info(self, label:str=None, record_kind:int=37375):
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
            'limit': 100,
            'authors': [self.pubkey_hex],
            'kinds': [record_kind],
            '#d': [label_hash]   
            
            
        }]

        # print("are we here?", label_hash)
        event =await self._async_get_wallet_info(FILTER, label_hash)
        
        # Do the delete here
        tags = [["e", event.id]]
        print("tags to delete: ", tags)
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
        my_enc = NIP44Encrypt(self.k)
        # target_tag = filter[0]['d']
        target_tag = label_hash
        
        
        self.logger.debug(f"target tag: {target_tag}")
        event_select = None
        async with ClientPool([self.home_relay]) as c:
        
            
            events = await c.query(filter)
            
            self.logger.debug(f"no of events: {len(events)}")

            return events[0]


        
    async def get_record(self,record_name, record_kind: int =37375):
        #FIXME - not sure if this function is used
        record_out = await self.get_wallet_info(label=record_name,record_kind=record_kind)
        try:
            record_obj = json.loads(record_out)
        except:
            record_obj = record_out

        return record_obj


   
    def get_proofs(self):
        #TODO add in a group by keyset
        
        return self.proofs
    
    def set_index_info(self,index_info: str):
        asyncio.run(self._async_set_index_info(index_info))  
    
    async def _async_set_index_info(self, index_info: str):
        
        print("the latest index info", index_info)
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
            print(n_msg.data())
            c.publish(n_msg)
            # await asyncio.sleep(1)

    def get_index_info(self):
        my_enc = NIP44Encrypt(self.k)
        
        DEFAULT_RELAY = self.relays[0]
        FILTER = [{
            'limit': 100,
            'authors': [self.pubkey_hex],
            'kinds': [17375]
            
        }]
        try:
            event =asyncio.run(self._async_get_index_info(FILTER))
        
            # print(event.data())
            decrypt_content = my_enc.decrypt(event.content, self.pubkey_hex)

            index_obj = json.loads(decrypt_content)

            return index_obj
        except:
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

    async def put_record(self,record_name, record_value, record_type="generic", record_kind: int = 37375):
        print("reserved records:", self.RESERVED_RECORDS)
        if record_name in self.RESERVED_RECORDS:
            print("careful this is a reserved record.")
            await self.set_wallet_info(record_name,record_value,record_kind=record_kind)
            return record_name
        else:
            record_obj = { "tag"   : [record_name],
                            "type"  : record_type,
                            "payload": record_value
                          }
            record_json_str = json.dumps(record_obj)
            await self.update_tags([["user_record",record_name,record_type]])

            await self.set_wallet_info(record_name,record_json_str,record_kind=record_kind)
            # print(user_records)
            return record_name
    
    async def update_tags(self,tag_values):
        
        for tag_value in tag_values:
            if tag_value[0]=="user_record":
                if tag_value in self.acorn_tags:
                    print("user record already in!")
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

            
        
        print(self.acorn_tags)
        await self.set_wallet_info(label=self.name,label_info=json.dumps(self.acorn_tags))

    async def _mint_proofs(self, quote:str, amount:int, mint:str=None):
        # print("mint proofs")
        headers = { "Content-Type": "application/json"}
        if mint:
            keyset_url = f"https://{mint}/v1/keysets"
        else:
            keyset_url = f"{self.home_mint}/v1/keysets"

        response = requests.get(keyset_url, headers=headers)
        keyset = response.json()['keysets'][0]['id']

        keysets_obj = KeysetsResponse(**response.json())

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
            blinded_values.append((B_,r, secret))
            
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
        try:
            response = requests.post(mint_url, json=request_body, headers=headers)
            promises = response.json()['signatures']
            # print("promises:", promises)
        except:
            return False

        
        if mint:
            mint_key_url = f"https://{mint}/v1/keys/{keyset}"
        else:
            mint_key_url = f"{self.home_mint}/v1/keys/{keyset}"

        response = requests.get(mint_key_url, headers=headers)
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
                           Y=Y.serialize().hex()
            )

            proof_objs.append(proof)
            
            i+=1
        
        self.logger.debug(f"Adding proofs from mint: {proof_objs}")

        
        await self.add_proofs_obj(proof_objs)
        
        return True

    async def check_quote(self, quote:str, amount:int, mint:str = None):
        print(f"check quote {quote}")
        
        # return "check_quote"
        
       
        return await self._check_quote(quote, amount,mint)
    
    def deposit(self, amount:int, mint:str = None)->cliQuote:
        
        #FIXME parameter passing with scheme
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
        # print(f"Please pay invoice: {invoice}") 
        # print(self.powers_of_2_sum(int(amount)))
        # add quote as a replaceable event

        wallet_quote_list =[]
        
        # wallet_quote_list_str = self.get_wallet_info("quote")
        # wallet_quote_list_json = json.loads(wallet_quote_list_str)
        # for each in wallet_quote_list_json:
        #    wallet_quote_list.append(each)
        
        # wallet_quote = walletQuote(quote=quote,amount=amount, invoice=invoice)
        # wallet_quote_list.append(wallet_quote.model_dump())
        
        # label_info = json.dumps(wallet_quote_list)
        # print(label_info)
        # self.set_wallet_info(label="quote", label_info=label_info)


        # TODO this is after quote has been paid - refactor into function
        # self._mint_proofs(quote,amount)

         
        return cliQuote(invoice=invoice, quote=quote, mint_url=url)
        # return f"Please pay invoice \n{invoice} \nfor quote: \n{quote}."
    
    async def poll_for_payment(self, quote:str, amount: int, mint:str=None):
        start_time = time()  # Record the start time
        end_time = start_time + 60  # Set the loop to run for 60 seconds
        success = False
        #FIXME figure out the prefit
        mint = mint.replace("https://","")
        while time() < end_time:
            
            self.logger.debug(f"polling for payment {quote} amount {amount} {mint}")
            success = await self.check_quote(quote=quote, amount=amount,mint=mint)
            if success:
                self.logger.debug("quote is paid!")
                break
            sleep(3)  # Sleep for 3 seconds
        
        self.logger.debug("polling done!")
    
    def withdraw(self, lninvoice:str):

        msg_out = self.pay_multi_invoice(lninvoice=lninvoice)
        
        return msg_out

    def add_proofs(self,text, replicate_relays: List[str]=None):
        # make sure have latest kind
        print("get rid of this function")

        asyncio.run(self._async_add_proofs(text, replicate_relays))  

    async def add_proofs_obj(self,proofs_arg: List[Proof], replicate_relays: List[str]=None):
        # make sure have latest kind
       
        #FIXME This might be the offending error
        self.logger.debug(f"adding proofs_obj {proofs_arg}")

        #  proofs_to_store = json.dump
        # for each in proofs_arg:
        #    pass
        #    proof_to_store = [each.model_dump()]
        #    text = json.dumps(proof_to_store)
        #    asyncio.run(self._async_add_proofs(text, replicate_relays))
        
        # Create the format for NIP 60 proofs
        nip60_proofs = NIP60Proofs(mint=self.known_mints[proofs_arg[0].id])
        for each in proofs_arg:
            nip60_proofs.proofs.append(each)
        
        record = nip60_proofs.model_dump_json()
        
        
        self.logger.debug(f"nip60 proofs text: {record}")
        await self._async_add_proofs(record, replicate_relays)
        
        return

    async def write_proofs(self, replicate_relays: List[str]=None):
        # make sure have latest kind
        #TODO this is a workaround

        self.logger.debug(f"writing proofs ")
        try:
            await self.delete_proof_events()
            # get proofs by keyset
            all_proofs, amount = self._proofs_by_keyset()
            
            for key, value in all_proofs.items():

                await self.add_proofs_obj(value) 
            await self._load_proofs()
        except Exception as e:
            raise Exception(e)

        
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
        # print("length of proof text:", len(text), text)
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
            'limit': 100,
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
                            except:
                                decrypt_content = "could not decrpyt"
                                                        
                            reserved_record_label = reverse_hash.get(each_tag[1])
                            
                            if reverse_hash.get(each_tag[1]):
                                self.wallet_reserved_records[reserved_record_label]=decrypt_content
                                
                
                    
        self.logger.debug(f"Finished loading reserved records of {len(record_events)} events")   
        return True
    
    async def _load_proofs(self):
        
        
        FILTER = [{
            'limit': 1024,
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
                    self.logger.debug(f"load nip60 proofs {nip60_proofs}")
                    self.known_mints[nip60_proofs.proofs[0]['id']]= nip60_proofs.mint
                    for each in nip60_proofs.proofs:
                        self.proofs.append(each)
                        proof_event.proofs.append(each)
                        # print(proof.amount, proof.secret)
                    # self.proof_events.proof_events.append(proof_event)          
                except:
                    content = each.content

                
                proofs += str(content) +"\n\n"

            
            balance = 0
            for each in self.proofs:
                # print(each.amount, each.secret)
                balance += each.amount
            self.balance = balance
            self.logger.debug(f"balance from loaded proofs: {balance}")
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


    async def _check_quote(self,quote, amount:int, mint:str = None):
        # print("check quote", quote)
        #TODO error handling
        success_mint = True    
          
        if mint:
            url = f"https://{mint}/v1/mint/quote/bolt11/{quote}"
        else:
             url = f"{self.home_mint}/v1/mint/quote/bolt11/{quote}" 

        self.logger.debug(f"mint quote: {url}")

        headers = { "Content-Type": "application/json"}
        response = requests.get(url, headers=headers)
           
        mint_quote = mintQuote(**response.json())
        if mint_quote.paid == True:
                success_mint = await self._mint_proofs(mint_quote.quote,amount,mint)


                    
                    
                    
                    
                # return mint_quote.paid
        else:
                success_mint = False

        return success_mint

        event_quotes = [] 
        # event_quote_info_list = self.get_wallet_info("quote")
        event_quote_info_list = self.wallet_reserved_records["quote"]
        event_quote_info_list_json = json.loads(event_quote_info_list)
       
        self.logger.debug(f"event quote list: {event_quote_info_list_json}")
        event_quote_info_list_json = self.quote
        for each in event_quote_info_list_json:
            event_quotes.append(walletQuote(**each))

        # event_quote_info_obj = walletQuote(**event_quote_info_json)

        for each_quote in event_quotes:
            
            

            url = f"{self.mints[0]}/v1/mint/quote/bolt11/{each_quote.quote}"
            self.logger.debug(f"mint quote: {url}")
            
            
            # print("event quote info:", each_quote)
            headers = { "Content-Type": "application/json"}
            response = requests.get(url, headers=headers)
            # print("response", response.json())
            mint_quote = mintQuote(**response.json())
            # print("mint_quote:", mint_quote.paid)
            if mint_quote.paid == True:
                success_mint = self._mint_proofs(each_quote.quote,each_quote.amount)

                # Remove quote from array. Just reset the record for now.
                if success_mint:
                    my_list = [x.model_dump() for x in event_quotes if x != each_quote]                    
                    self.set_wallet_info(label="quote", label_info=json.dumps(my_list))
                    
                    
                    
                    
                # return mint_quote.paid
            else:
                success_for_all = False
        self._load_proofs()    
        return success_for_all
    



    async def pay_multi(  self, 
                    amount:int, 
                    lnaddress: str, 
                    comment: str = "Paid!"): 
                    
        
        # print("pay from multiple mints")
        available_amount = 0
        chosen_keyset = None
        chosen_keysets = [] # This is for multipath payments
        multi_path = False
        keyset_proofs,keyset_amounts = self._proofs_by_keyset()
        headers = { "Content-Type": "application/json"}

        try:
            callback = lightning_address_pay(amount, lnaddress,comment=comment)         
            pr = callback['pr']  
        except Exception as e:
            msg_out = f"Could not resolve {lnaddress}. Check if correct address"
            self.logger.error(msg_out)
            return msg_out

        for each in keyset_amounts:
            available_amount += keyset_amounts[each]
        
        
        print("available amount:", available_amount)
        if available_amount < amount:
            msg_out = "insufficient balance. you need more funds!"
            
            return msg_out
        
        for key in sorted(keyset_amounts, key=lambda k: keyset_amounts[k]):
            # print(key, keyset_amounts[key])
            if keyset_amounts[key] >= amount:
                chosen_keyset = key
                break
        if not chosen_keyset:
            # print("insufficient balance in any one keyset, you need to swap or do mpp!") 
            multi_path = True
               
        
        if multi_path:
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
            
            print(f"amount to pay: {amount} with chosen keysets: {chosen_keysets}")
            amount_remaining = amount
            total_fees = 0
            total_melt_amount = 0
            for each_keyset in chosen_keysets:
                print(f"amount remaining: {amount_remaining}")
                # There are three possible use cases
                if amount_remaining <= 0:
                    print("we are done!")
                    break
                elif amount_remaining > keyset_amounts[each_keyset]:
                    print("use whole keyset amount")
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
                try:
                    response = requests.post(url=melt_quote_url, json=data_to_send,headers=headers)
                    post_melt_response = PostMeltQuoteResponse(**response.json())
                    print(f"{self.known_mints[each_keyset]} supports melt response: {post_melt_response}")

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
                            print("WARNING")
                        else:
                            print(f"melt amount ok")

                    total_melt_amount += melt_amount
                    total_fees += post_melt_response.fee_reserve
                    # amount_paid_by_keyset = amount_to_use - post_melt_response.fee_reserve
                    print(f"can pay amount {amount_to_pay} from keyset total {keyset_amounts[each_keyset]} with: {post_melt_response.fee_reserve}  melt amount is {melt_amount}")
                    # Redo the melt request
                    data_to_send = {    "request": pr,
                                    "unit": "sat",
                                    "options": {"mpp": {"amount": amount_to_pay}}
                            }
                    response = requests.post(url=melt_quote_url, json=data_to_send,headers=headers)
                    post_melt_response = PostMeltQuoteResponse(**response.json())
                    print(f"adjusted post melt response {post_melt_response}")
                    amount_remaining = amount_remaining - amount_to_pay   
                    print(f"amount remaining after adjusted {amount_remaining}")                                   
                    keysets_to_use_for_multi.append((each_keyset,melt_amount,amount_to_pay,post_melt_response))
                except:
                    pass
                    # print(f"{self.known_mints[each_keyset]} does not support")
            if amount_remaining > 0:
                 raise ValueError(f"There are not sufficient mints to support multipath payments. Try smaller amounts?")

            # Now we have the meltquotes
            print(f"keysets to use for multi {keysets_to_use_for_multi}")
            print(f"pay amount {amount} total fees: {total_fees}, total melt amount {total_melt_amount}")
            
            self._multi_melt(keysets_to_use_for_multi) 
            
            # self.write_proofs()

            msg_out = f"pay amount with mpp {amount} total fees: {total_fees}, total melt amount {total_melt_amount}"
            return msg_out
            # raise ValueError(f"Need to implement multipath payment for {amount} with {available_amount} available")

        else: # Can pay with a single keyset

            self.logger.debug(f"chosen keyset for payment {chosen_keyset}")
        
            # Now do the pay routine
            melt_quote_url = f"{self.known_mints[chosen_keyset]}/v1/melt/quote/bolt11"
            melt_url = f"{self.known_mints[chosen_keyset]}/v1/melt/bolt11"

            print(amount, lnaddress)
            data_to_send = {    "request": pr,
                                "unit": "sat"

                            }
            response = requests.post(url=melt_quote_url, json=data_to_send,headers=headers)
            # print("post melt response:", response.json())
            post_melt_response = PostMeltQuoteResponse(**response.json())
            # print("mint response:", post_melt_response)
            proofs_to_use = []
            proof_amount = 0
            amount_needed = amount + post_melt_response.fee_reserve
            self.logger.debug(f"amount needed: {amount_needed}")
            if amount_needed > keyset_amounts[chosen_keyset]:
                print("insufficient balance in keyset. you need to swap, or use another keyset")
                chosen_keyset = None
                for key in sorted(keyset_amounts, key=lambda k: keyset_amounts[k]):
                    # print(key, keyset_amounts[key])
                    if keyset_amounts[key] >= amount_needed:
                        chosen_keyset = key
                        self.logger.debug(f"new chosen keyset: {key}")
                        break
                if not chosen_keyset:
                    print("you don't have a sufficient balance in a keyset, you need to swap")
                    return
                
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
                response = requests.post(url=melt_quote_url, json=data_to_send,headers=headers)
                # print("post melt response:", response.json())
                post_melt_response = PostMeltQuoteResponse(**response.json())
                # print("mint response:", post_melt_response)

                if not chosen_keyset:
                    print("insufficient balance in any one keyset, you need to swap!") 
                    return 
                
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
                

        
            proofs_remaining = self.swap_for_payment_multi(chosen_keyset,proofs_to_use, amount_needed)
            

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
            response = requests.post(url=melt_url,json=data_to_send,headers=headers) 
            
            self.logger.debug(f"response json: {response.json()}")
            payment_json = response.json()
            #TODO Need to do some error checking
            
            self.logger.debug(f"need to do some error checking")
            # {'detail': 'Lightning payment unsuccessful. no_route', 'code': 20000}
            # add keep proofs back into selected keyset proofs
            if payment_json.get("paid",False):        
                self.logger.info(f"lightning payment ok")
            else:
                self.logger.info(f"lighting payment did no go through")
                # Add back in spend proofs
                for each in spend_proofs:   
                    proofs_from_keyset.append(each)
            

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
            
            await self.write_proofs()
            msg_out = f"Payment of {amount} sats with single mint fee {amount_needed-amount} sats to {lnaddress} successful! \nYou have {self.balance} sats remaining."
            self.logger.info(msg_out)
            return msg_out

    def _multi_melt(self, keysets_to_use):

        
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
            print(f"multi melt: {amount_needed}, \nmelt request: {post_melt_response}  \nproofs: {proofs_from_keyset}")
            while proof_amount < amount_needed:
                pay_proof = proofs_from_keyset.pop()
                proofs_to_use.append(pay_proof)
                proof_amount += pay_proof.amount
            
            proofs_remaining = self.swap_for_payment_multi(chosen_keyset,proofs_to_use, amount_needed)
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
        asyncio.run(self._do_mpp_requests(mpp_mint_melt_request)) 
        print("we are done with the requests")




            
        return 
           
    async def _do_mpp_requests(self, mpp_requests):
        tasks = []
        for each_request in mpp_requests:
            print(f"do each request: {each_request}")
            asyncio.create_task(self._post_request(each_request))
        
        print("tasks have been completed!")
    
    async def _post_request(self,request_item):
        response = requests.post(url=request_item[0], json=request_item[1])
        return
        async with httpx.AsyncClient() as client:
            print(f"doing each request: {request_item}")
            response = client.post(url=request_item[0], json=request_item[1])
        pass    

            

    async def pay_multi_invoice(  self, 
                     
                    lninvoice: str, 
                    comment: str = "Paid!"): 
                    
        # decode amount from invoice
        try:
            ln_amount = int(bolt11.decode(lninvoice).amount_msat//1e3)
        except Exception as e:
            return f"error {e}"

        self.logger.debug("pay from multiple mints")
        available_amount = 0
        chosen_keyset = None
        keyset_proofs,keyset_amounts = self._proofs_by_keyset()
        for each in keyset_amounts:
            available_amount += keyset_amounts[each]
        
        
        self.logger.debug(f"available amount: {available_amount}")
        if available_amount < ln_amount:
            msg_out ="insufficient balance. you need more funds!"
            return msg_out
        
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
        response = requests.post(url=melt_quote_url, json=data_to_send,headers=headers)
        self.logger.debug(f"post melt response: {response.json()}")
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
                self.logger.debug("you don't have a sufficient balance in a keyset, you need to swap")
                return
            
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
            response = requests.post(url=melt_quote_url, json=data_to_send,headers=headers)
            self.logger.debug(f"post melt response: {response.json()}")
            post_melt_response = PostMeltQuoteResponse(**response.json())
            self.logger.debug(f"mint response: {post_melt_response}")

            if not chosen_keyset:
                self.logger.debug("insufficient balance in any one keyset, you need to swap!") 
                return 
            
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
        proofs_remaining = self.swap_for_payment_multi(chosen_keyset,proofs_to_use, amount_needed)
        

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
        response = requests.post(url=melt_url,json=data_to_send,headers=headers) 
        self.logger.debug(response.json())   
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

           
        
        await self.write_proofs()
        msg_out = f"Paid {ln_amount} sats with fee {amount_needed-ln_amount} sats successful! \nYou have {self.balance} sats remaining."
        self.logger.info(msg_out)
        return msg_out

    async def delete_kind_events(self, record_kind:int):
        """
            Delete kind events
        """
        # first, get all of the events for the kind

        FILTER = [{
                'limit': 100, 
                '#p'  :  [self.pubkey_hex],              
                'kinds': [record_kind]
                
                }]
  

        async with ClientPool([self.home_relay]) as c:  
            events = await c.query(FILTER) 

        for each in events:
            print(each.id)
        
        tags = []
        for each_event in events:
            tags.append(["e",each_event.id])
            
        tags.append(["k",str(record_kind)])
        print(f"tags for events to delete {tags}")
        
        
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
                print("should have deleted")
        except:
            raise Exception("error deleting proof events")  
        
        return f"events of kind {record_kind} deleted" 


    async def _async_delete_proof_events(self):
        """
            Delete proof events
        """
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
            for each in self.proof_event_ids:
                tags.append(["e",each])
            tags.append(["k","7375"])
            self.logger.debug(f"tags for proof events to delete {tags}")
            
            async with ClientPool([self.home_relay]) as c:
            
                n_msg = Event(kind=Event.KIND_DELETE,
                            content=None,
                            pub_key=self.pubkey_hex,
                            tags=tags)
                n_msg.sign(self.privkey_hex)
                c.publish(n_msg)
                # added a delay here so the delete event get published
                await asyncio.sleep(1)
        except:
            raise Exception("error deleting proof events")    

    def swap_proofs(self, incoming_swap_proofs: List[Proof]):
        '''This function swaps proofs'''
        self.logger.debug("Swap proofs")
        swap_amount =0
        count = 0
        
        headers = { "Content-Type": "application/json"}
        
        #keyset_url = f"{self.mints[0]}/v1/keysets"
        keyset_url = f"{self.known_mints[incoming_swap_proofs[0].id]}/v1/keysets"
        response = requests.get(keyset_url, headers=headers)
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
        print("total:", swap_amount,count, powers_of_2) 
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
                response = requests.post(url=swap_url, json=data_to_send, headers=headers)
                # print(response.json())
                promises = response.json()['signatures']
                # print("promises:", promises)

            
                mint_key_url = f"{self.known_mints[incoming_swap_proofs[0].id]}/v1/keys/{keyset}"
                response = requests.get(mint_key_url, headers=headers)
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
        except:
                ValueError('test')

        # need to convert new_proofs into objects
        new_proof_obj_list = []
        for each in new_proofs:
            new_proof_obj_list.append(Proof(**each))

        return new_proof_obj_list
    
    def swap(self):
        #TODO This function is no longer used
        swap_amount =0
        count = 0
        
        headers = { "Content-Type": "application/json"}
        
        keyset_url = f"{self.mints[0]}/v1/keysets"
        response = requests.get(keyset_url, headers=headers)
        keyset = response.json()['keysets'][0]['id']

        swap_url = f"{self.mints[0]}/v1/swap"

        for each in self.trusted_mints:
            
            keyset_each = each
            keyset_url_each = self.known_mints[each]
            print(keyset, keyset_url_each)

        

            swap_proofs = []
            blinded_swap_proofs = []
            blinded_values =[]
            blinded_messages = []
            for each in self.proof_events.proof_events:
                # print(each.id)
                for each_proof in each.proofs:
                    # print(each_proof.amount)
                    swap_amount+=each_proof.amount
                    swap_proofs.append(each_proof.model_dump())
                    
                    count +=1
            
            # print("swap proofs:", swap_proofs)
            r = PrivateKey()

            # print("create blinded swap proofs")
            powers_of_2 = self.powers_of_2_sum(swap_amount)
            print("total:", swap_amount,count, powers_of_2)   
            for each in powers_of_2:
                secret = secrets.token_hex(32)
                B_, r, Y = step1_alice(secret)
                blinded_values.append((B_,r, secret))
                
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
        
            # print(data_to_send)
            try:
                response = requests.post(url=swap_url, json=data_to_send, headers=headers)
                # print(response.json())
                promises = response.json()['signatures']
                # print("promises:", promises)

            
                mint_key_url = f"{self.mints[0]}/v1/keys/{keyset}"
                response = requests.get(mint_key_url, headers=headers)
                keys = response.json()["keysets"][0]["keys"]
                # print(keys)
                proofs = []
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
                    proof = {   "amount": promise_amount,
                            "id": keyset,
                            "secret": blinded_values[i][2],
                            "C":    C.serialize().hex()
                            }
                    proofs.append(proof)
                    # print(proofs)
                    i+=1
            
                # delete old proofs
                asyncio.run(self._async_delete_proof_events())
                print("XXXXX swap")
                self.add_proofs(json.dumps(proofs))
                self._load_proofs()
                
            except:
                ValueError('test')
            
            # print(request_body) 
            # refresh balance
            
            swap_balance = 0
            for each in self.proofs:
                swap_balance += each.amount
            print(len(self.proofs)) 
        
        return f"swap ok sats "
    
    async def swap_multi_consolidate(self):
        #TODO run swap_multi_each first to get rid of any potential doublespends
        #TODO figure out how to catch doublespends in this routine
        headers = { "Content-Type": "application/json"}
        keyset_proofs,keyset_amounts = self._proofs_by_keyset()
        combined_proofs = []
        combined_proof_objs =[]
        proof_objs = []
        
        # Let's check all the proofs before we do anything

        for each_keyset in keyset_proofs:
            check = []
            mint_verify_url = f"{self.known_mints[each_keyset]}/v1/checkstate"
            for each_proof in keyset_proofs[each_keyset]:
                check.append(each_proof.Y)

            # print(mint_verify_url, check)
            Ys = {"Ys": check}
            try:
                response = requests.post(url=mint_verify_url,headers=headers,json=Ys)
                check_response = response.json()
                proofs_to_check = check_response['states']
                for each_proof in proofs_to_check:
                    assert each_proof['state'] == "UNSPENT"
                    # print(each_proof['state'])
            except:
                return f"there is a problem with {self.known_mints[each_keyset]}"
                
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
                response = requests.post(url=swap_url, json=data_to_send, headers=headers)
                # print(response.json())
                promises = response.json()['signatures']
                # print("promises:", promises)

            
                mint_key_url = f"{self.known_mints[each_keyset]}/v1/keys/{each_keyset}"
                response = requests.get(mint_key_url, headers=headers)
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
            
                

                
            except:
                ValueError('duplicate proofs')
                # return "duplicate proofs"
                proofs = []
            
            combined_proofs = combined_proofs + proofs
            combined_proof_objs = combined_proof_objs + proof_objs
            # print(request_body) 
            # refresh balance
            
            swap_balance = 0
            for each in self.proofs:
                swap_balance += each.amount
            # print(len(self.proofs))
            # delete old proofs
            await self._async_delete_proof_events()
            # self.add_proofs(json.dumps(combined_proofs))

            self.proofs = combined_proof_objs
            await self.write_proofs()

            # self.add_proofs_obj(combined_proof_objs)
            # self._load_proofs()
        
        return "multi swap ok"

    async def swap_multi_each(self):
        #TODO this is used before consolidate to throw out any dups or doublespend. Fix events
        headers = { "Content-Type": "application/json"}
        keyset_proofs,keyset_amounts = self._proofs_by_keyset()
        combined_proofs = []
        combined_proof_objs =[]
        
        # Let's check all the proofs before we do anything

        for each_keyset in keyset_proofs:
            check = []
            mint_verify_url = f"{self.known_mints[each_keyset]}/v1/checkstate"
            for each_proof in keyset_proofs[each_keyset]:
                check.append(each_proof.Y)

            # print(mint_verify_url, check)
            Ys = {"Ys": check}
            try:
                response = requests.post(url=mint_verify_url,headers=headers,json=Ys)
                check_response = response.json()
                proofs_to_check = check_response['states']
                for each_proof in proofs_to_check:
                    assert each_proof['state'] == "UNSPENT"
                    # print(each_proof['state'])
            except:
                return f"there is a problem with the mint {self.known_mints[each_keyset]}"
                
        # return
        # All the proofs are verified, we are good to go for the swap   
        # In multi_each we are going to swap for each proof 
        
 
        for each_keyset in keyset_proofs:
            
            each_keyset_url = self.known_mints[each_keyset]

            mint_key_url = f"{self.known_mints[each_keyset]}/v1/keys/{each_keyset}"
            response = requests.get(mint_key_url, headers=headers)
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
                    response = requests.post(url=swap_url, json=data_to_send, headers=headers)
                    # print(response.json())
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
                        
                    
                    

                except:
                    ValueError("duplicate proofs")
                    self.logger.debug("duplicate proof, ignore")

                combined_proofs = combined_proofs + proofs
                combined_proof_objs = combined_proof_objs + proof_objs

        await self.delete_proof_events()
        self.logger.debug("XXXXX swap multi each")
        await self.add_proofs_obj(combined_proof_objs)
        
        await self._load_proofs()
        
                   
        
        return "multi swap ok"
    async def _async_swap(self):
        # This is the async version of swap
        headers = { "Content-Type": "application/json"}
        keyset_proofs,keyset_amounts = self._proofs_by_keyset()
        combined_proofs = []
        combined_proof_objs =[]
        
        # Let's check all the proofs before we do anything

        for each_keyset in keyset_proofs:
            check = []
            mint_verify_url = f"{self.known_mints[each_keyset]}/v1/checkstate"
            for each_proof in keyset_proofs[each_keyset]:
                check.append(each_proof.Y)

            # print(mint_verify_url, check)
            Ys = {"Ys": check}
            try:
                response = requests.post(url=mint_verify_url,headers=headers,json=Ys)
                check_response = response.json()
                proofs_to_check = check_response['states']
                for each_proof in proofs_to_check:
                    assert each_proof['state'] == "UNSPENT"
                    # print(each_proof['state'])
            except:
                return f"there is a problem with the mint {self.known_mints[each_keyset]}"
                
        # return
        # All the proofs are verified, we are good to go for the swap   
        # In multi_each we are going to swap for each proof 
        
 
        for each_keyset in keyset_proofs:
            
            each_keyset_url = self.known_mints[each_keyset]

            mint_key_url = f"{self.known_mints[each_keyset]}/v1/keys/{each_keyset}"
            response = requests.get(mint_key_url, headers=headers)
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
                    response = requests.post(url=swap_url, json=data_to_send, headers=headers)
                    # print(response.json())
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
                        
                    
                    

                except:
                    ValueError("duplicate proofs")
                    print("duplicate proof, ignore")

                combined_proofs = combined_proofs + proofs
                combined_proof_objs = combined_proof_objs + proof_objs

        await self._async_delete_proof_events()
        print("XXXXX async swap multi each")
        # self.add_proofs_obj(combined_proof_objs)
        await self._async_add_proofs_obj(combined_proof_objs)
        
        # self._load_proofs()
        FILTER = [{
            'limit': 1024,
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
            
            print(response.json())
            promises = response.json()['signatures']
            print("promises:", promises)

        
            mint_key_url = f"{self.mints[0]}/v1/keys/{keyset}"
            response = requests.get(mint_key_url, headers=headers)
            keys = response.json()["keysets"][0]["keys"]
            # print(keys)
            
            i = 0
        
            for each in promises:
                pub_key_c = PublicKey()
                print("each:", each['C_'])
                pub_key_c.deserialize(unhexlify(each['C_']))
                promise_amount = each['amount']
                A = keys[str(int(promise_amount))]
                # A = keys[str(j)]
                pub_key_a = PublicKey()
                pub_key_a.deserialize(unhexlify(A))
                r = blinded_values[i][1]
                print(pub_key_c, promise_amount,A, r)
                C = step3_alice(pub_key_c,r,pub_key_a)
                
                proof = Proof(  amount=promise_amount,
                                id=keyset,
                                secret=blinded_values[i][2],
                                C=C.serialize().hex() )
                
                proofs.append(proof)
                # print(proofs)
                i+=1
        except:
            ValueError('test')
        
        for each in proofs:
            print(each.amount)
        # now need break out proofs for payment and proofs remaining

        return proofs

    def swap_for_payment_multi(self, keyset_to_use:str, proofs_to_use: List[Proof], payment_amount: int)->List[Proof]:
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

        # print(powers_of_2_payment, powers_of_2_leftover)
        # print(proofs_to_use)
        # print(blinded_messages)
        # print(data_to_send)

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
        except Exception as e:
            print(e)
        
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
        except Exception as e:
            print(e)
        
        for each in proofs:
            pass
            # print(each.amount)
        # now need break out proofs for payment and proofs remaining

        return proofs
            
    def receive_token(self,cashu_token: str):
        headers = { "Content-Type": "application/json"}
        token_amount =0
        receive_url = f"{self.mints[0]}/v1/mint/quote/bolt11"

        try:
            token_obj = TokenV3.deserialize(cashu_token)
        except:
            return "bad token"
        for each in token_obj.token:
            print(each.mint)
            for each_proof in each.proofs:
                token_amount += each_proof.amount
                print("received proof: ", each.mint, each_proof.id, each_proof.amount,each_proof.secret)
        
            melt_quote_url = f"{each.mint}/v1/melt/quote/bolt11"
            melt_url = f"{each.mint}/v1/melt/bolt11"

            print(token_amount,melt_quote_url, melt_url)
        
       


        # Step 1 - create a mint request from the home mint corresponding to the amount in the token
        
        # Step 2 - create  melt quote request from the mint in the token
            # need to calculate amount to receive based on fee reserve
        
        # Step 3 - do steps 1 and 2 again Adjust everything accordingly based on the quotes

        # Step 4 - create the proofs
        
        # Step 1 - create mint request
        mint_request = mintRequest(amount=token_amount)
        mint_request_dump = mint_request.model_dump()
        payload_json = mint_request.model_dump_json()
        response = requests.post(url=receive_url, data=payload_json, headers=headers)
        
        mint_quote = mintQuote(**response.json())
        # print(mint_quote)
        mint_invoice = response.json()['request']
        mint_quote = response.json()['quote']
        print(mint_invoice, mint_quote)

        # Step 2 - create melt request
        data_to_send = {    "request": mint_invoice,
                            "unit": "sat"

                        }
        post_melt_response = requests.post(url=melt_quote_url, json=data_to_send,headers=headers)
        print("token sending melt response:", post_melt_response.json())
        post_melt_response_obj = PostMeltQuoteResponse(**post_melt_response.json())
        
        
        print("mint melt response:", post_melt_response_obj)


        amount_to_receive = token_amount - post_melt_response_obj.fee_reserve
        print("amount to receive:", amount_to_receive)


        # Step 3 - do steps 1 and 2 again Adjust everything accordingly based on the quotes
        # Step 1 repeated
        receive_mint_request = mintRequest(amount=amount_to_receive)
        receive_mint_request_dump = receive_mint_request.model_dump()
        receive_payload_json = receive_mint_request.model_dump_json()
        receive_response = requests.post(url=receive_url, data=receive_payload_json, headers=headers)
        
        receive_mint_quote = mintQuote(**receive_response.json())
        # print(mint_quote)
        receive_mint_invoice = receive_response.json()['request']
        receive_mint_quote = receive_response.json()['quote']
        print("adjusted:", receive_mint_invoice, receive_mint_quote)

        # Step 2 repeated
        melt_data_to_send = {   "request": receive_mint_invoice,
                                "unit": "sat"

                        }
        melt_response = requests.post(url=melt_quote_url, json=melt_data_to_send,headers=headers)
        print("token sending melt response:", melt_response.json())
        post_melt_response = PostMeltQuoteResponse(**melt_response.json())
        print("mint melt response:", post_melt_response.quote)

       
        check_amount = amount_to_receive + post_melt_response.fee_reserve
        print("check amount:", check_amount, token_amount)
        assert(check_amount == token_amount)

        # Step 4 - generate the proofs_to_use
        token_proofs_to_use = []
        token_proof_amount = 0
        
        for each in token_obj.token:
            melt_url = f"{each.mint}/v1/melt/bolt11"
            print(each.mint)
            for each_proof in each.proofs:
                token_proofs_to_use.append(each_proof.model_dump())
         
            print(f"proofs to use with ", token_proofs_to_use)

            # Step 4a create the outputs to receive
            powers_of_2_sum = self.powers_of_2_sum(amount_to_receive)
            powers_of_2_sum_change = self.powers_of_2_sum(token_amount-amount_to_receive)
            concat_list = powers_of_2_sum + powers_of_2_sum_change
        
            print("amount of proofs to melt", powers_of_2_sum, amount_to_receive)
            print("concatenated list ", concat_list)
            print("melt url ", melt_url)
            # Now build the inputs and outputs for the melt_url
            data_to_send = {    "quote": post_melt_response.quote,
                                "inputs": token_proofs_to_use }
        
            print(data_to_send)
            # print("we are here!!!")
            response = requests.post(url=melt_url,json=data_to_send,headers=headers)
            print(response.json())
        
            # Now we need to check the receive mint to issue proofs
            print("receive mint quote", receive_mint_quote)

            self._mint_proofs(receive_mint_quote,amount_to_receive)
            

        return "test"
    
    async def accept_token(self,cashu_token: str):
        print("accept token")
        # asyncio.run(self.nip17_accept(cashu_token))
        msg_out = await self.nip17_accept(cashu_token)
        # self.set_wallet_info(label="trusted_mints", label_info=json.dumps(self.trusted_mints))
        return msg_out

        


    async def issue_token(self, amount:int):
        print("issue token")
        available_amount = 0
        chosen_keyset = None
        keyset_proofs,keyset_amounts = self._proofs_by_keyset()
        for each in keyset_amounts:
            available_amount += keyset_amounts[each]
        
        
        print("available amount:", available_amount)
        if available_amount < amount:
            msg_out = "insufficient balance. you need more funds!"
            return msg_out
        
        for key in sorted(keyset_amounts, key=lambda k: keyset_amounts[k]):
            print(key, keyset_amounts[key])
            if keyset_amounts[key] >= amount:
                chosen_keyset = key
                break
        if not chosen_keyset:
            print("insufficient balance in any one keyset, you need to swap!") 
            return   
        
        proofs_to_use = []
        proof_amount = 0
        proofs_from_keyset = keyset_proofs[chosen_keyset]
        while proof_amount < amount:
            pay_proof = proofs_from_keyset.pop()
            proofs_to_use.append(pay_proof)
            proof_amount += pay_proof.amount
            print(f"pop proof amount of {pay_proof.amount} from {chosen_keyset}")
            
        print("proofs to use:", proofs_to_use)
        print("remaining", proofs_from_keyset)
        print("chosen keyset for payment", chosen_keyset)
        
        proofs_remaining = self.swap_for_payment_multi(chosen_keyset,proofs_to_use, amount)
        

        print("proofs remaining:", proofs_remaining)
        print(f"amount needed: {amount}")
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
        await self._async_delete_proof_events()
        
        
        await self.add_proofs_obj(post_payment_proofs)
        
        await self._load_proofs()


        
        tokens = TokenV3Token(mint=self.known_mints[chosen_keyset],
                                        proofs=spend_proofs)
        
        v3_token = TokenV3(token=[tokens],memo="hello", unit="sat")
        # print("proofs remaining:", proofs_remaining)
        
        return v3_token.serialize()   

    def testpay(self, amount:int):
        amount_needed = amount
        print("pay from multiple mints")
        available_amount = 0
        chosen_keyset = None
        keyset_proofs,keyset_amounts = self._proofs_by_keyset()
        for each in keyset_amounts:
            available_amount += keyset_amounts[each]
        
        
        print("available amount:", available_amount)
        if available_amount < amount:
            msg_out = "insufficient balance. you need more funds!"
            return msg_out
        
        for key in sorted(keyset_amounts, key=lambda k: keyset_amounts[k]):
            print(key, keyset_amounts[key])
            if keyset_amounts[key] >= amount:
                chosen_keyset = key
                break
        if not chosen_keyset:
            print("insufficient balance in any one keyset, you need to swap!") 
            return   
        
        print("chosen keyset for payment", chosen_keyset)
        # Now do the pay routine
        melt_quote_url = f"{self.known_mints[chosen_keyset]}/v1/melt/quote/bolt11"
        melt_url = f"{self.known_mints[chosen_keyset]}/v1/melt/bolt11"
        print(melt_quote_url,melt_url)
        headers = { "Content-Type": "application/json"}
        
        proofs_to_use = []
        proof_amount = 0
        proofs_from_keyset = keyset_proofs[chosen_keyset]
        while proof_amount < amount_needed:
            pay_proof = proofs_from_keyset.pop()
            proofs_to_use.append(pay_proof)
            proof_amount += pay_proof.amount
            print("pop", pay_proof.amount)
            
        print("proofs to use:", proofs_to_use)
        print("remaining", proofs_from_keyset)
        
        return "test"

    
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
            
        except:
            raise ValueError(f"could not resolve nip05")
            

        if event_id.startswith("note"):
            try:
                event_id = bech32_to_hex(event_id)
            except:
                return "Note id format is invalid. Please check and try again."
            try:
                zap_filter = [{  
                'ids'  :  [event_id]          
                
                }]
                prs = await self._async_query_zap(amount, comment,zap_filter)
            except:
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
        except Exception as e:
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
        except:
            {"status": "could not access profile"}
            pass
       
        if event == None:
            raise Exception("no event")
        
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

                
            except:
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
               
                
            except:
                {"status": "could not access profile"}
                self.logger.error("could not get profile")
                pass
       
        return prs
    
    def share_record(self,record: str, nrecipient: str, share_relays:List[str], comment: str ="Sent!"):
        
        try:
            if '@' in nrecipient:
                npub_hex, relays = nip05_to_npub(nrecipient)
                npub = hex_to_bech32(npub_hex)
                print("npub", npub)
            else:
                npub = nrecipient
        except:
            return "error"
        
        # Now let's get the record
        out_record = self.get_wallet_info(record)
        dm_msg = f"I've shared with you the record: {record}. The contents are below. \n{out_record}"

        out_msg = f"{nrecipient} {npub}, {npub_hex}, {out_record}"

        # out_msg= asyncio.run(self._async_share_record(record_message=out_record,npub=npub, share_relays=share_relays ))
        asyncio.run(self._async_secure_dm(npub_hex=npub_hex, message=dm_msg,dm_relays=relays+ share_relays)) 
        return out_msg
    

    async def _async_share_record(self,record_message: str, npub: str, share_relays:List[str]):
        print("npub:", npub)
        
        my_enc = NIP4Encrypt(self.k)
        k_to_send = Keys(pub_k=npub)
        k_to_send_pubkey_hex = k_to_send.public_key_hex()
        print("k_to_send:", k_to_send_pubkey_hex)
        
       

        print("are we here?", share_relays)
        async with ClientPool(share_relays) as c:
            n_msg = Event(kind=Event.KIND_ENCRYPT,
                      content=record_message,
                      pub_key=k_to_send_pubkey_hex)

            # print("are we here_async?", ecash_relays)
            # returns event we to_p_tag and content encrypted
            n_msg = my_enc.encrypt_event(evt=n_msg,
                                    to_pub_k=k_to_send_pubkey_hex)

            n_msg.sign(self.privkey_hex)
            c.publish(n_msg)
        
        return f"{record_message}  to {npub} {share_relays}"   
    
    def monitor(self, nrecipient: str, relays: List[str]=None):
        print(f"monitor {nrecipient}")
        try:
            if '@' in nrecipient:
                npub_hex, relays = nip05_to_npub(nrecipient)
                npub = hex_to_bech32(npub_hex)
                print("npub", npub)
                
            else:
                npub = nrecipient
                npub_hex = bech32_to_hex(nrecipient)
        except:
            return "error"
        
        print(f"monitor {npub}")
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

        print(f'running as npub{tail(my_k.public_key_bech32()[4:])}, messaging npub{tail(send_k.public_key_bech32()[4:])}')

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
            print('auth requested')


        # create the client and start it running
        c = ClientPool(url,
                    on_connect=on_connect,
                    on_auth=on_auth,
                    on_eose=my_handler)
        asyncio.create_task(c.run())

        def sigint_handler(signal, frame):
            print('stopping listener...')
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
                        print(c_event.id[:4],c_event.pub_key, c_event.created_at, c_event.content)
                        content = c_event.content
                        array_token = content.splitlines()
                    
                        
                        for each in array_token:
                            if each.startswith("cashuA"):
                                
                                
                                # print(f"found token! {each}")
                                msg_out = await self.nip17_accept(each)
                                print(msg_out)
                                    
                                
                            elif each.startswith("creqA"):
                                print(f"found request {each}")
                    


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

        print('stopping...')
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
        print(f"listening for nip17 as {self.pubkey_bech32} using {url}. \nType 'exit' to stop")

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
            print('auth requested')


        # create the client and start it running
        c = ClientPool(url,
                    on_connect=on_connect,
                    on_auth=on_auth,
                    on_eose=my_handler)
        asyncio.create_task(c.run())

        def sigint_handler(signal, frame):
            print('stopping listener...')
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
                        print(c_event.id[:4],c_event.pub_key, c_event.created_at, c_event.content)
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
            

           

        print('stopping...')
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
        print("run")
        await task1

    async def _async_task(self):
       
     
        await asyncio.sleep(1)
        print("task")

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

        print(payment_request_dict)
        cbor_data = cbor2.dumps(payment_request_dict)
        base64_encoded_data = base64.b64encode(cbor_data)
        base64_string = base64_encoded_data.decode('utf-8')

        payment_request = "creqA" + base64_string
        return payment_request

    async def nip17_accept(self, token:str):
        # self.accept_token(token)
        # print("accept token")
        headers = { "Content-Type": "application/json"}
        token_amount =0
        receive_url = f"{self.home_mint}/v1/mint/quote/bolt11"

        if token[:6] == "cashuA":

            try:
                token_obj = TokenV3.deserialize(token)
            except:
                raise ValueError("bad token")
            
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
                    # print(id, each.mint)

        


        elif token[:6] == "cashuB":
                token_obj = TokenV4.deserialize(token)
                # print(token_obj)
                proofs=[]
                proof_obj_list: List[Proof] = []
                for each_proof in token_obj.proofs:
                    proofs.append(each_proof.model_dump())
                    proof_obj_list.append(each_proof)
                    id = each_proof.id
                self.known_mints[id]=token_obj.mint

        
        swap_proofs = self.swap_proofs(proof_obj_list)

        try:
            await self.add_proofs_obj(swap_proofs)
        except Exception as e:
            self.logger.debug(f"Proof not accepted {e}")
            return f"Proof not accepted. Doublespent?"

        # await self._async_add_proofs_obj(swap_proofs)


        FILTER = [{
            'limit': 1024,
            'authors': [self.pubkey_hex],
            'kinds': [7375]
        }]
        
        await self._async_load_proofs(FILTER)

        #TODO don't do this every time - only when a new mint shows up
        # await self._async_set_wallet_info(label="trusted_mints", label_info=json.dumps(self.trusted_mints))
        # await self._async_swap()
        self.logger.debug(f"Proofs are added! New balance is: {self.balance}")
        
        return f'Successfully accepted! New balance is {self.balance}'

        

            

       
        
        
if __name__ == "__main__":
    
    # url = ['wss://relay.0xchat.com','wss://relay.damus.io']
    # this relay seems to work the best with these kind of anon published events, atleast for now
    # others it seems to be a bit of hit and miss...
    url = ['wss://relay.getsafebox.app']
    # asyncio.run(listen_notes(url))  