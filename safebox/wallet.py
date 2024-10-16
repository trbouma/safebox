from typing import Any, Dict, List, Optional, Union
import asyncio, json, requests
from time import sleep
import secrets
from datetime import datetime, timedelta
import urllib.parse
import random
from mnemonic import Mnemonic
import bolt11
import aioconsole

from hotel_names import hotel_names
from coolname import generate, generate_slug
from binascii import unhexlify
import hashlib
import signal, sys



from monstr.encrypt import Keys
from monstr.client.client import Client, ClientPool
from monstr.event.event import Event
from monstr.encrypt import NIP44Encrypt, NIP4Encrypt
from monstr.signing.signing import BasicKeySigner
from monstr.giftwrap import GiftWrap
from monstr.util import util_funcs

tail = util_funcs.str_tails

from safebox.b_dhke import step1_alice, step3_alice, hash_to_curve
from safebox.secp import PrivateKey, PublicKey
from safebox.lightning import lightning_address_pay, lnaddress_to_lnurl, zap_address_pay
from safebox.nostr import bech32_to_hex, hex_to_bech32, nip05_to_npub

from safebox.models import nostrProfile, SafeboxItem, mintRequest, mintQuote, BlindedMessage, Proof, Proofs, proofEvent, proofEvents, KeysetsResponse, PostMeltQuoteResponse, walletQuote
from safebox.models import TokenV3, TokenV3Token, cliQuote, proofsByKeyset, Zevent
from safebox.models import WalletConfig, WalletRecord,WalletReservedRecords

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
class Wallet:
    k: Keys
    nsec: str
    pubkey_bech32: str
    pubkey_hex: str
    privkey_hex: str
    privkey_bech32: str
    home_relay: str
    relays: List[str]
    mints: List[str]
    safe_box_items: List[SafeboxItem]
    proofs: List[Proof]
    events: int
    balance: int
    proof_events: proofEvents 
    replicate: bool
    RESERVED_RECORDS: List[str]
    wallet_reserved_records: object
    



    def __init__(self, nsec: str, relays: List[str], mints: List[str]|None=None,home_relay:str|None=None, replicate = False) -> None:
        if nsec.startswith('nsec'):
            self.k = Keys(priv_k=nsec)
            self.pubkey_bech32  =   self.k.public_key_bech32()
            self.pubkey_hex     =   self.k.public_key_hex()
            self.privkey_bech32 =   self.k.private_key_bech32()
            self.privkey_hex    =   self.k.private_key_hex()
            self.relays         =   relays
            # self.mints          =   mints
            self.safe_box_items = []
            self.proofs: List[Proof] = []
            self.balance: int = 0
            self.proof_events = proofEvents()
            self.trusted_mints = {}
            self.home_relay = None
            self.replicate = replicate
            self.wallet_config = None
            self.RESERVED_RECORDS = [   "default",
                                        "profile",
                                        "wallet_config",
                                        "home_relay",
                                        "mints",
                                        "trusted_mints",
                                        "relays",
                                        "quote",
                                        "user_records",
                                        "last_dm"
                                        
                        ]
            self.wallet_reserved_records = {}
        else:
            return "Need nsec" 

        # print("load records")

        if home_relay == None:
            print("need a home relay to boot")
            return None
        else:
            self.home_relay = home_relay
         
        self._load_record_events()
        # print(self.wallet_reserved_records)
        if mints == None:
            
            self.mints = json.loads(self.wallet_reserved_records['mints'])
            
        else:
            self.mints = mints
            self.set_wallet_info(label="mints", label_info=json.dumps(self.mints))

        if relays == None:
            self.relays = json.loads(self.wallet_reserved_records['relays'])
        else:
            self.relays = relays
            self.set_wallet_info(label="relays", label_info=json.dumps(self.relays))

        headers = { "Content-Type": "application/json"}
        keyset_url = f"{self.mints[0]}/v1/keysets"
        try:
            self.trusted_mints = json.loads(self.wallet_reserved_records['trusted_mints'])
            keyset = response.json()['keysets'][0]['id']
            self.trusted_mints[keyset] = self.mints[0]
            self.set_wallet_info(label="trusted_mints", label_info=json.dumps(self.trusted_mints))
        except:
            response = requests.get(keyset_url, headers=headers)
            keyset = response.json()['keysets'][0]['id']
            self.trusted_mints[keyset] = self.mints[0]
            self.set_wallet_info(label="trusted_mints", label_info=json.dumps(self.trusted_mints))

        try:
            self.wallet_config = WalletConfig(**json.loads(self.wallet_reserved_records["wallet_config"]))
            # print("ok wallet_config:",self.wallet_config)
        except:
            self.wallet_config = WalletConfig(kind_cashu = 7375)
            self.set_wallet_info(label="wallet_config", label_info=json.dumps(self.wallet_config.model_dump()))
            # print("new wallet_config:",self.wallet_config)

        try:
            self.quote = json.loads(self.wallet_reserved_records['quote'])
            # print("init quote:", self.quote)
        except:
            self.quote = []

        try:
            user_records= json.loads(self.wallet_reserved_records['user_records'])
            # print("init quote:", self.quote)
        except:
            self.wallet_reserved_records['user_records'] = '[]'
        
       
            


            
        
        
        # print("load proofs")
        self._load_proofs()

        return None
            
        



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
    
    def create_profile(self, nostr_profile_create: bool=False, keepkey:bool=False):
        init_index = {}
        wallet_info = {}

        if keepkey==False:
            self.k= Keys()
            self.pubkey_bech32  =   self.k.public_key_bech32()
            self.pubkey_hex     =   self.k.public_key_hex()
            self.privkey_hex    =   self.k.private_key_hex()
        
        new_name = generate()
        # print(new_name)
        for i in range(len(new_name)):
            if new_name[i].lower() in ["of","from"]:
                if i >=1:
                    pet_name = new_name[i-2] + new_name[i-1] 
                else:
                    pet_name = new_name[i-1]                
                break


        hotel_name = hotel_names.get_hotel_name()
        display_name = ' '.join(n.capitalize() for n in new_name)
        nostr_profile = nostrProfile(   name=pet_name,
                                        display_name=display_name,
                                        about = f"Resident of {hotel_name}",
                                        picture=f"https://robohash.org/{pet_name}/?set=set4",
                                        lud16= f"{self.pubkey_bech32}@openbalance.app",
                                        website=f"https://npub.cash/pay/{self.pubkey_bech32}"
                                         )
        if nostr_profile_create:
            out = asyncio.run(self._async_create_profile(nostr_profile))
            hello_msg = f"Hello World from {pet_name}! #introductions"
            print(hello_msg)
            asyncio.run(self._async_send_post(hello_msg))
            print(out)

        # init_index = "[{\"root\":\"init\"}]"
        init_index["root"] = pet_name
        # self.set_index_info(json.dumps(init_index))
        self.set_wallet_info(label="default", label_info=display_name)
        self.set_wallet_info(label="profile", label_info=json.dumps(nostr_profile.model_dump()))
        
        self.wallet_config = WalletConfig(kind_cashu = 7375)                
        self.set_wallet_info(label="wallet_config", label_info=json.dumps(self.wallet_config.model_dump()))
        self.set_wallet_info(label="mints", label_info=json.dumps(self.mints))
        self.set_wallet_info(label="relays", label_info=json.dumps(self.relays))
        self.set_wallet_info(label="quote", label_info='[]')
        self.set_wallet_info(label="index", label_info='{}')
        self.set_wallet_info(label="last_dm", label_info='0')
        self.set_wallet_info(label="user_records", label_info='[]')
        
 
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
      
                n_msg = Event(kind=0,
                        content=profile,
                        pub_key=self.pubkey_hex)
                n_msg.sign(self.privkey_hex)
                c.publish(n_msg)
            except:
                out_msg = "error"
        return out_msg

    def get_profile(self):
        profile_obj = {}
        nostr_profile = None
        mnemo = Mnemonic("english")
        
        try:
            FILTER = [{
            'limit': 1,
            'authors': [self.pubkey_hex],
            'kinds': [0]
            }]
            profile = asyncio.run(self._async_query_client_profile(FILTER))
        except:        
            profile = self.wallet_reserved_records.get("profile", "{}")
        
        profile_obj = json.loads(profile)
        nostr_profile = nostrProfile(**profile_obj)
        out_string =  "-"*80  
        out_string += f"\nProfile Information for: {nostr_profile.display_name}"
        out_string += "\n"+ "-"*80  
        out_string += f"\nnpub: {str(self.pubkey_bech32)}"
        out_string += f"\npubhex: {str(self.pubkey_hex)}"
        out_string += f"\nnsec: {str(self.k.private_key_bech32())}"
        out_string += f"\n\nseed phrase: \n{'-'*80}\n{mnemo.to_mnemonic(bytes.fromhex(self.pubkey_hex))}"
        out_string += "\n"+ "-"*80    
    
        for key, value in nostr_profile.__dict__.items():        
            out_string += f"\n{str(key).ljust(15)}: {value}"
        
        out_string += "\n"+ "-"*80  
        out_string += f"\nMints {self.mints}"
        out_string += f"\nHome Relay {self.home_relay}"
        out_string += f"\nRelays {self.relays}"
        out_string += "\n"+ "-"*80  

        #TODO this has to be put into a function (repeats create_profile code)
        if self.replicate:
            print("REPLICATE")



        return out_string
    
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
        
        out_msg= asyncio.run(self._async_send_ecash_dm(token_msg,npub, ecash_relays+relays ))
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

            
    def secure_dm(self,nrecipient:str, message: str, dm_relays: List[str]):
        try:
            if '@' in nrecipient:
                npub_hex, relays = nip05_to_npub(nrecipient)
                npub = hex_to_bech32(npub_hex)
                print("npub", npub)
                dm_relays = relays + dm_relays
            else:
                npub_hex = bech32_to_hex(nrecipient)
        except:
            return "error"
        print(npub_hex,message)

        asyncio.run(self._async_secure_dm(npub_hex=npub_hex, message=message,dm_relays=dm_relays))  
    
    async def _async_secure_dm(self, npub_hex, message:str, dm_relays: List[str]):
       
        my_gift = GiftWrap(BasicKeySigner(self.k))
        relays = ['wss://strfry.openbalance.app']
        async with ClientPool(relays) as c:


            send_evt = Event(content=message,
                         tags=[
                             ['p', npub_hex]
                         ])
           
            
            wrapped_evt, trans_k = await my_gift.wrap(send_evt,
                                                  to_pub_k=npub_hex)
            # wrapped_evt.sign(self.privkey_hex)
            c.publish(wrapped_evt)
                
                
                
        


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

    def set_wallet_info(self,label: str,label_info: str, replicate_relays: List[str]=None):
        asyncio.run(self._async_set_wallet_info(label,label_info,replicate_relays=replicate_relays))  
    
    async def _async_set_wallet_info(self, label:str, label_info: str, replicate_relays:List[str]=None):

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
            n_msg = Event(kind=37375,
                        content=wallet_info_encrypt,
                        pub_key=self.pubkey_hex,
                        tags=tags)
            
            # n_msg = my_enc.encrypt_event(evt=n_msg,
            #                         to_pub_k=self.pubkey_hex)
            
            n_msg.sign(self.privkey_hex)
            # print("label, event id:", label, n_msg.id)
            c.publish(n_msg)
            # await asyncio.sleep(1)

    def get_wallet_info(self, label:str=None):
        my_enc = NIP44Encrypt(self.k)

        m = hashlib.sha256()
        m.update(self.privkey_hex.encode())
        m.update(label.encode())
        label_hash = m.digest().hex()
        
        # d_tag_encrypt = my_enc.encrypt(d_tag,to_pub_k=self.pubkey_hex)
        # a_tag = ["a", label_hash]
        # print("a_tag:",a_tag)
        print("getting:", label)
        DEFAULT_RELAY = self.relays[0]
        FILTER = [{
            'limit': 100,
            'authors': [self.pubkey_hex],
            'kinds': [37375]
            
            
        }]

        # print("are we here?", label_hash)
        event =asyncio.run(self._async_get_wallet_info(FILTER, label_hash))
        
        # print(event.data())
        try:
            decrypt_content = my_enc.decrypt(event.content, self.pubkey_hex)
        except:
            return f"Could not retrieve info for: {label}. Does a record exist?"
        
        # print("tags", event.tags)
        # encrypt_d = "None"
        for each in event.tags:
            
            if each[0] == 'd':
                # print(each)
                orig_d = each[1]
                # decrypt_d = my_enc.decrypt(orig_d, self.pubkey_hex)
            
                break
        try:
            decrypt_d = my_enc.decrypt(orig_d, self.pubkey_hex)
        except:    
            decrypt_d = "Nothing"

        return decrypt_content
    
    async def _async_get_wallet_info(self, filter: List[dict],label_hash):
    # does a one off query to relay prints the events and exits
        # print("filter", filter[0]['d'])
        my_enc = NIP44Encrypt(self.k)
        # target_tag = filter[0]['d']
        target_tag = label_hash
        
        print("target tag:", target_tag)
        event_select = None
        async with ClientPool([self.home_relay]) as c:
        # async with Client(relay) as c:
            
            events = await c.query(filter)
            
            print(f"37375 events: {len(events)}")

            


            for each in events:
               
                try:
                    # print("EACH!!: ", each.data())
                    # print("TAGS: ", each.tags)
                    for each_tag in each.tags:
                        if each_tag[0] == 'd':
                            # print(each_tag[1])
                            if each_tag[1] == target_tag:
                                # print("MATCH HELLO!!")
                                event_select = each                   

                except:
                    # print('no d tag')
                    pass
                
            
            return event_select
        
    def get_record(self,record_name):
        print("reserved records:", self.RESERVED_RECORDS)
        if record_name in self.RESERVED_RECORDS:
            print("this is a reserved record")
            return self.wallet_reserved_records[record_name]
        else:
            return self.wallet_reserved_records[record_name]
   
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

    def put_record(self,record_name, record_value):
        print("reserved records:", self.RESERVED_RECORDS)
        if record_name in self.RESERVED_RECORDS:
            print("careful this is a reserved record.")
            self.set_wallet_info(record_name,record_value)
            return record_name
        else:
            print("this is a user record")
            user_records = json.loads(self.wallet_reserved_records['user_records'])
            user_records.append(record_name)
            user_records = sorted(list(set(user_records)))
            self.set_wallet_info('user_records',json.dumps(user_records))
            self.set_wallet_info(record_name,record_value)
            print(user_records)
            return record_name
    
    def _mint_proofs(self, quote:str, amount:int):
        # print("mint proofs")
        headers = { "Content-Type": "application/json"}
        keyset_url = f"{self.mints[0]}/v1/keysets"
        response = requests.get(keyset_url, headers=headers)
        keyset = response.json()['keysets'][0]['id']

        keysets_obj = KeysetsResponse(**response.json())

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
        mint_url = f"{self.mints[0]}/v1/mint/bolt11"

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

        
        mint_key_url = f"{self.mints[0]}/v1/keys/{keyset}"
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
            # print(pub_key_c, promise_amount,A, r)
            C = step3_alice(pub_key_c,r,pub_key_a)
            
            proof = Proof ( amount= promise_amount,
                           id = keyset,
                           secret=blinded_values[i][2],
                           C=C.serialize().hex(),
                           Y=Y.serialize().hex()
            )
            proofs.append(proof.model_dump())
            proof_objs.append(proof)
            print(proofs)
            i+=1
        
        # self.add_proofs(json.dumps(proofs))
        print("adding deposit proof objects")
        self.add_proofs_obj(proof_objs)
        
        return True

    def check(self):
        
       
        return self._check_quote()
    
    def deposit(self, amount:int)->cliQuote:
        url = f"{self.mints[0]}/v1/mint/quote/bolt11"
       
        # url = "https://mint.nimo.cash/v1/mint/quote/bolt11"
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
        
        wallet_quote_list_str = self.get_wallet_info("quote")
        wallet_quote_list_json = json.loads(wallet_quote_list_str)
        for each in wallet_quote_list_json:
            wallet_quote_list.append(each)
        
        wallet_quote = walletQuote(quote=quote,amount=amount, invoice=invoice)
        wallet_quote_list.append(wallet_quote.model_dump())
        # label_info = json.dumps(wallet_quote.model_dump())
        label_info = json.dumps(wallet_quote_list)
        # print(label_info)
        self.set_wallet_info(label="quote", label_info=label_info)
        # self.add_tokens(f"tokens {amount} {payload_json} {response.json()['request']}")
        # quote=self.check_quote()

        # TODO this is after quote has been paid - refactor into function
        # self._mint_proofs(quote,amount)

         
        return cliQuote(invoice=invoice, quote=quote)
        # return f"Please pay invoice \n{invoice} \nfor quote: \n{quote}."
    def withdraw(self, lninvoice:str):

        msg_out = self.pay_multi_invoice(lninvoice=lninvoice)
        
        return msg_out

    def add_proofs(self,text, replicate_relays: List[str]=None):
        # make sure have latest kind
        print("get rid of this function")

        asyncio.run(self._async_add_proofs(text, replicate_relays))  

    def add_proofs_obj(self,proofs_arg: List[Proofs], replicate_relays: List[str]=None):
        # make sure have latest kind
        #TODO this is a workaround



        proofs_to_store = json.dump
        for each in proofs_arg:
            pass
            proof_to_store = [each.model_dump()]
            text = json.dumps(proof_to_store)
            asyncio.run(self._async_add_proofs(text, replicate_relays))
        
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
            # print("add proofs with kind:", self.wallet_config.kind_cashu)
            n_msg = Event(kind=self.wallet_config.kind_cashu,
                        content=payload_encrypt,
                        pub_key=self.pubkey_hex)
            n_msg.sign(self.privkey_hex)
            c.publish(n_msg)
            # await asyncio.sleep(1)

    def add_proof_event(self, proofs:List[Proof]):
        asyncio.run(self._async_add_proof_event(proofs))  
    
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
            n_msg = Event(kind=self.wallet_config.kind_cashu,
                        content=payload_encrypt,
                        pub_key=self.pubkey_hex)
            n_msg.sign(self.privkey_hex)
            c.publish(n_msg)
            # await asyncio.sleep(1) 
    
    def _load_record_events(self):
        FILTER = [{
            'limit': 100,
            'authors': [self.pubkey_hex],
            'kinds': [37375]
        }]
        content =asyncio.run(self._async_load_record_events(FILTER))
        
        return content
    
    async def _async_load_record_events(self, filter: List[dict]):
    # does a query for record events, does not decrypt
       
        async with ClientPool([self.home_relay]) as c:
            my_enc = NIP44Encrypt(self.k)
            # get reserved records  
            reverse_hash = {}        
            record_events = await c.query(filter)
            
            # print(f"load record  events: {len(record_events)}")
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
                            # print("found!", each_tag)
                            try:
                                decrypt_content = my_enc.decrypt(each_record.content, self.pubkey_hex)
                            except:
                                decrypt_content = "could not decrpyt"
                            # print("tag",each_tag[1], reverse_hash.get(each_tag[1]))
                            
                            reserved_record_label = reverse_hash.get(each_tag[1])
                            if reverse_hash.get(each_tag[1]):
                                self.wallet_reserved_records[reverse_hash.get(each_tag[1])]=decrypt_content
                                # print(f"load {reverse_hash.get(each_tag[1])}:{each_tag[1]},{decrypt_content}")  
                    
            # print(self.wallet_reserved_records)

    def _load_proofs(self):
        
        
        FILTER = [{
            'limit': 1024,
            'authors': [self.pubkey_hex],
            'kinds': [self.wallet_config.kind_cashu]
        }]
        content =asyncio.run(self._async_load_proofs(FILTER))
        
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
                proof_event = proofEvent(id=each_event.id)
                try:
                    content = my_enc.decrypt(each_event.content, self.pubkey_hex)
                    content_json = json.loads(content)
                    # print("event_id:", each_event.id)
                    
                    for each_content in content_json:
                        
                        proof = Proof(**each_content)
                        self.proofs.append(proof)
                        proof_event.proofs.append(proof)
                        # print(proof.amount, proof.secret)
                    self.proof_events.proof_events.append(proof_event)          
                except:
                    content = each.content

                
                proofs += str(content) +"\n\n"

            
            balance = 0
            for each in self.proofs:
                # print(each.amount, each.secret)
                balance += each.amount
            self.balance = balance
            # print("balance:", balance)
            # print("proofs:", len(self.proofs))

                
            # print("let's dedup proofs just in case")
            #TODO this is to mitigate some dup errors reading from multiple relays
            self.proofs = list(set(self.proofs))     
           
            return proofs
    
    def delete_proofs(self):
        asyncio.run(self._async_delete_proof_events())

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
        print(keyset_amounts)
        return all_proofs, keyset_amounts


    def _check_quote(self):
        # print("check quote", quote)
        #TODO error handling
        success_for_all = True
           
        
        event_quotes = [] 
        # event_quote_info_list = self.get_wallet_info("quote")
        event_quote_info_list = self.wallet_reserved_records["quote"]
        event_quote_info_list_json = json.loads(event_quote_info_list)
        print(event_quote_info_list_json)
        event_quote_info_list_json = self.quote
        for each in event_quote_info_list_json:
            event_quotes.append(walletQuote(**each))

        # event_quote_info_obj = walletQuote(**event_quote_info_json)

        for each_quote in event_quotes:
            
            

            url = f"{self.mints[0]}/v1/mint/quote/bolt11/{each_quote.quote}"
            
            
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
            
        return success_for_all
    

    def pay(self, amount:int, lnaddress: str, comment: str = "Paid!"):

        melt_quote_url = f"{self.mints[0]}/v1/melt/quote/bolt11"
        melt_url = f"{self.mints[0]}/v1/melt/bolt11"
        
        headers = { "Content-Type": "application/json"}
        callback = lightning_address_pay(amount, lnaddress,comment=comment)
        pr = callback['pr']
        
        print(pr)
        print(amount, lnaddress)
        # need to get enough proofs to cover amount
        data_to_send = {    "request": pr,
                            "unit": "sat"

                        }
        response = requests.post(url=melt_quote_url, json=data_to_send,headers=headers)
        print("post melt response:", response.json())
        post_melt_response = PostMeltQuoteResponse(**response.json())
        print("mint response:", post_melt_response)

        proofs_to_use = []
        proof_amount = 0
        amount_needed = amount + post_melt_response.fee_reserve
        print("amount needed:", amount_needed)
        if amount_needed > self.balance:
            print("insufficient balance")
            return
        while proof_amount < amount_needed:
            pay_proof = self.proofs.pop()
            proofs_to_use.append(pay_proof)
            proof_amount += pay_proof.amount
            print("pop", pay_proof.amount)
            
        print("proofs to use", proofs_to_use)
        print("remaining", self.proofs)

        # Now need to do the melt
        proofs_remaining = self.swap_for_payment(proofs_to_use, amount_needed)
        

        print("proofs remaining:", proofs_remaining)
        print(f"amount needed: {amount_needed}")
        sum_proofs =0
        spend_proofs = []
        keep_proofs = []
        for each in proofs_remaining:
            
            sum_proofs += each.amount
            if sum_proofs <= amount_needed:
                spend_proofs.append(each)
                print(f"pay with {each.amount}, {each.secret}")
            else:
                keep_proofs.append(each)
                print(f"keep {each.amount}, {each.secret}")
        print("spend:",spend_proofs) 
        print("keep:", keep_proofs) 

        melt_proofs = []
        for each_proof in spend_proofs:
                melt_proofs.append(each_proof.model_dump())

        data_to_send = {"quote": post_melt_response.quote,
                      "inputs": melt_proofs }
        
        print(data_to_send)
        print("we are here!!!")
        response = requests.post(url=melt_url,json=data_to_send,headers=headers) 
        print(response.json())   
        # delete old proofs
        for each in keep_proofs:
            self.proofs.append(each)
        # print("self proofs", self.proofs)
        asyncio.run(self._async_delete_proof_events())
        self.add_proof_event(self.proofs)
        self._load_proofs()
        
        

    def pay_multi(  self, 
                    amount:int, 
                    lnaddress: str, 
                    comment: str = "Paid!"): 
                    
        
        # print("pay from multiple mints")
        available_amount = 0
        chosen_keyset = None
        keyset_proofs,keyset_amounts = self._proofs_by_keyset()
        for each in keyset_amounts:
            available_amount += keyset_amounts[each]
        
        
        print("available amount:", available_amount)
        if available_amount < amount:
            print("insufficient balance. you need more funds!")
            return
        
        for key in sorted(keyset_amounts, key=lambda k: keyset_amounts[k]):
            # print(key, keyset_amounts[key])
            if keyset_amounts[key] >= amount:
                chosen_keyset = key
                break
        if not chosen_keyset:
            print("insufficient balance in any one keyset, you need to swap!") 
            return   
        
        print("chosen keyset for payment", chosen_keyset)
        # Now do the pay routine
        melt_quote_url = f"{self.trusted_mints[chosen_keyset]}/v1/melt/quote/bolt11"
        melt_url = f"{self.trusted_mints[chosen_keyset]}/v1/melt/bolt11"
        # print(melt_quote_url,melt_url)
        headers = { "Content-Type": "application/json"}
        callback = lightning_address_pay(amount, lnaddress,comment=comment)
        pr = callback['pr']        
        # print(pr)
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
        print("amount needed:", amount_needed)
        if amount_needed > keyset_amounts[chosen_keyset]:
            print("insufficient balance in keyset. you need to swap, or use another keyset")
            chosen_keyset = None
            for key in sorted(keyset_amounts, key=lambda k: keyset_amounts[k]):
                # print(key, keyset_amounts[key])
                if keyset_amounts[key] >= amount_needed:
                    chosen_keyset = key
                    print("new chosen keyset", key)
                    break
            if not chosen_keyset:
                print("you don't have a sufficient balance in a keyset, you need to swap")
                return
            
            # Set to new mints and redo the calls
            melt_quote_url = f"{self.trusted_mints[chosen_keyset]}/v1/melt/quote/bolt11"
            melt_url = f"{self.trusted_mints[chosen_keyset]}/v1/melt/bolt11"
            # print(melt_quote_url,melt_url)
            callback = lightning_address_pay(amount, lnaddress,comment=comment)
            pr = callback['pr']        
            # print(pr)
            print(amount, lnaddress)
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
        print("---we have a sufficient mint---")
        # print(melt_quote_url,melt_url, post_melt_response)
        proofs_to_use = []
        proof_amount = 0
        proofs_from_keyset = keyset_proofs[chosen_keyset]
        while proof_amount < amount_needed:
            pay_proof = proofs_from_keyset.pop()
            proofs_to_use.append(pay_proof)
            proof_amount += pay_proof.amount
            # print("pop", pay_proof.amount)
            
        # print("proofs to use:", proofs_to_use)
        # print("remaining", proofs_from_keyset)
        # Continue implementing from line 818 swap_for_payment may need a parameter
         # Now need to do the melt
       
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
                print(f"pay with {each.amount}, {each.secret}")
            else:
                keep_proofs.append(each)
                print(f"keep {each.amount}, {each.secret}")
        print("spend:",spend_proofs) 
        print("keep:", keep_proofs)
        melt_proofs = []
        for each_proof in spend_proofs:
                melt_proofs.append(each_proof.model_dump())

        data_to_send = {"quote": post_melt_response.quote,
                    "inputs": melt_proofs }
        
        print(data_to_send)
        print("Lightning payment we are here!!!")
        response = requests.post(url=melt_url,json=data_to_send,headers=headers) 
        print(response.json()) 
        payment_json = response.json()
        #TODO Need to do some error checking
        print("need to do some error checking")  
        # {'detail': 'Lightning payment unsuccessful. no_route', 'code': 20000}
        # add keep proofs back into selected keyset proofs
        if payment_json.get("paid",False):        
            print("lightning paid ok")
        else:
            print("payment did not go through") 
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
          
        
        self.proofs = post_payment_proofs
        asyncio.run(self._async_delete_proof_events())
        # self.add_proof_event(self.proofs)
        self.add_proofs_obj(post_payment_proofs)
        self._load_proofs()

    def pay_multi_invoice(  self, 
                     
                    lninvoice: str, 
                    comment: str = "Paid!"): 
                    
        # decode amount from invoice
        try:
            ln_amount = int(bolt11.decode(lninvoice).amount_msat//1e3)
        except Exception as e:
            return f"error {e}"

        print("pay from multiple mints")
        available_amount = 0
        chosen_keyset = None
        keyset_proofs,keyset_amounts = self._proofs_by_keyset()
        for each in keyset_amounts:
            available_amount += keyset_amounts[each]
        
        
        print("available amount:", available_amount)
        if available_amount < ln_amount:
            print("insufficient balance. you need more funds!")
            return
        
        for key in sorted(keyset_amounts, key=lambda k: keyset_amounts[k]):
            print(key, keyset_amounts[key])
            if keyset_amounts[key] >= ln_amount:
                chosen_keyset = key
                break
        if not chosen_keyset:
            print("insufficient balance in any one keyset, you need to swap!") 
            return   
        
        print("chosen keyset for payment", chosen_keyset)
        # Now do the pay routine
        melt_quote_url = f"{self.trusted_mints[chosen_keyset]}/v1/melt/quote/bolt11"
        melt_url = f"{self.trusted_mints[chosen_keyset]}/v1/melt/bolt11"
        print(melt_quote_url,melt_url)
        headers = { "Content-Type": "application/json"}
        # callback = lightning_address_pay(amount, lnaddress,comment=comment)
        pr = lninvoice        
        print(pr)
        print(ln_amount, lninvoice)
        data_to_send = {    "request": pr,
                            "unit": "sat"

                        }
        response = requests.post(url=melt_quote_url, json=data_to_send,headers=headers)
        print("post melt response:", response.json())
        post_melt_response = PostMeltQuoteResponse(**response.json())
        print("mint response:", post_melt_response)
        proofs_to_use = []
        proof_amount = 0
        amount_needed = ln_amount + post_melt_response.fee_reserve
        print("amount needed:", amount_needed)
        if amount_needed > keyset_amounts[chosen_keyset]:
            print("insufficient balance in keyset. you need to swap, or use another keyset")
            chosen_keyset = None
            for key in sorted(keyset_amounts, key=lambda k: keyset_amounts[k]):
                print(key, keyset_amounts[key])
                if keyset_amounts[key] >= amount_needed:
                    chosen_keyset = key
                    print("new chosen keyset", key)
                    break
            if not chosen_keyset:
                print("you don't have a sufficient balance in a keyset, you need to swap")
                return
            
            # Set to new mints and redo the calls
            melt_quote_url = f"{self.trusted_mints[chosen_keyset]}/v1/melt/quote/bolt11"
            melt_url = f"{self.trusted_mints[chosen_keyset]}/v1/melt/bolt11"
            print(melt_quote_url,melt_url)
            callback = lightning_address_pay(ln_amount, lninvoice,comment=comment)
            pr = callback['pr']        
            print(pr)
            print(ln_amount, lninvoice)
            data_to_send = {    "request": pr,
                            "unit": "sat"

                        }
            response = requests.post(url=melt_quote_url, json=data_to_send,headers=headers)
            print("post melt response:", response.json())
            post_melt_response = PostMeltQuoteResponse(**response.json())
            print("mint response:", post_melt_response)

            if not chosen_keyset:
                print("insufficient balance in any one keyset, you need to swap!") 
                return 
            
        # Print now we should be all set to go
        print("---we have a sufficient mint---")
        print(melt_quote_url,melt_url, post_melt_response)
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
        # Continue implementing from line 818 swap_for_payment may need a parameter
         # Now need to do the melt
        proofs_remaining = self.swap_for_payment_multi(chosen_keyset,proofs_to_use, amount_needed)
        

        print("proofs remaining:", proofs_remaining)
        print(f"amount needed: {amount_needed}")
        # Implement from line 824
        sum_proofs =0
        spend_proofs = []
        keep_proofs = []
        for each in proofs_remaining:
            
            sum_proofs += each.amount
            if sum_proofs <= amount_needed:
                spend_proofs.append(each)
                print(f"pay with {each.amount}, {each.secret}")
            else:
                keep_proofs.append(each)
                print(f"keep {each.amount}, {each.secret}")
        print("spend:",spend_proofs) 
        print("keep:", keep_proofs)
        melt_proofs = []
        for each_proof in spend_proofs:
                melt_proofs.append(each_proof.model_dump())

        data_to_send = {"quote": post_melt_response.quote,
                      "inputs": melt_proofs }
        
        print(data_to_send)
        print("we are here!!!")
        response = requests.post(url=melt_url,json=data_to_send,headers=headers) 
        print(response.json())   
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
        self.proofs = post_payment_proofs
        asyncio.run(self._async_delete_proof_events())
        self.add_proofs_obj(post_payment_proofs)
        self._load_proofs()



    async def _async_delete_proof_events(self):
        """
            Example showing how to post a text note (Kind 1) to relay
        """

        tags = []
        for each_event in self.proof_events.proof_events:
            tags.append(["e",each_event.id])
            # print(each_event.id)
            for each_proof in each_event.proofs:
                # print(each_proof.id, each_proof.amount)
                pass
        # print(tags)
        
        async with ClientPool([self.home_relay]) as c:
        
            n_msg = Event(kind=Event.KIND_DELETE,
                        content=None,
                        pub_key=self.pubkey_hex,
                        tags=tags)
            n_msg.sign(self.privkey_hex)
            c.publish(n_msg)
            # await asyncio.sleep(1)

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
            keyset_url_each = self.trusted_mints[each]
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
    
    def swap_multi_consolidate(self):
        #TODO run swap_multi_each first to get rid of any potential doublespends
        #TODO figure out how to catch doublespends in this routine
        headers = { "Content-Type": "application/json"}
        keyset_proofs,keyset_amounts = self._proofs_by_keyset()
        combined_proofs = []
        combined_proof_objs =[]
        
        # Let's check all the proofs before we do anything

        for each_keyset in keyset_proofs:
            check = []
            mint_verify_url = f"{self.trusted_mints[each_keyset]}/v1/checkstate"
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
                return f"there is a problem with {self.trusted_mints[each_keyset]}"
                
        # return
        # All the proofs are verified, we are good to go for the swap    

 
        for each_keyset in keyset_proofs:
            
            each_keyset_url = self.trusted_mints[each_keyset]
            # print(each_keyset,each_keyset_url)
            swap_url = f"{self.trusted_mints[each_keyset]}/v1/swap"
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

            
                mint_key_url = f"{self.trusted_mints[each_keyset]}/v1/keys/{each_keyset}"
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
            asyncio.run(self._async_delete_proof_events())
            # self.add_proofs(json.dumps(combined_proofs))
            self.add_proofs_obj(combined_proof_objs)
            self._load_proofs()
        
        return "multi swap ok"

    def swap_multi_each(self):
        #TODO this is used before consolidate to throw out any dups or doublespend. Fix events
        headers = { "Content-Type": "application/json"}
        keyset_proofs,keyset_amounts = self._proofs_by_keyset()
        combined_proofs = []
        combined_proof_objs =[]
        
        # Let's check all the proofs before we do anything

        for each_keyset in keyset_proofs:
            check = []
            mint_verify_url = f"{self.trusted_mints[each_keyset]}/v1/checkstate"
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
                return f"there is a problem with the mint {self.trusted_mints[each_keyset]}"
                
        # return
        # All the proofs are verified, we are good to go for the swap   
        # In multi_each we are going to swap for each proof 
        
 
        for each_keyset in keyset_proofs:
            
            each_keyset_url = self.trusted_mints[each_keyset]

            mint_key_url = f"{self.trusted_mints[each_keyset]}/v1/keys/{each_keyset}"
            response = requests.get(mint_key_url, headers=headers)
            keys = response.json()["keysets"][0]["keys"]
            # print(each_keyset,each_keyset_url)
            swap_url = f"{self.trusted_mints[each_keyset]}/v1/swap"
            
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

        asyncio.run(self._async_delete_proof_events())
        print("XXXXX swap multi each")
        self.add_proofs_obj(combined_proof_objs)
        
        self._load_proofs()
        
                   
        
        return "multi swap ok"
        
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
        keyset_url = f"{self.trusted_mints[keyset_to_use]}/v1/keysets"
        response = requests.get(keyset_url, headers=headers)
        keyset = response.json()['keysets'][0]['id']

        swap_url = f"{self.trusted_mints[keyset_to_use]}/v1/swap"

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
            print("are we here?")
            response = requests.post(url=swap_url, json=data_to_send, headers=headers)
            
            # print(response.json())
            promises = response.json()['signatures']
            # print("promises:", promises)

        
            mint_key_url = f"{self.trusted_mints[keyset_to_use]}/v1/keys/{keyset}"
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
                print(pub_key_c, promise_amount,A, r)
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
    
    def accept_token(self,cashu_token: str):
        headers = { "Content-Type": "application/json"}
        token_amount =0
        receive_url = f"{self.mints[0]}/v1/mint/quote/bolt11"

        try:
            token_obj = TokenV3.deserialize(cashu_token)
        except:
            return "bad token"
        proofs=[]
        proof_obj_list: List[Proof] = []
        for each in token_obj.token:
            print(each.mint)
            for each_proof in each.proofs:
                proofs.append(each_proof.model_dump())
                proof_obj_list.append(each_proof)
                id = each_proof.id
                self.trusted_mints[id]=each.mint
            
        print(self.trusted_mints)
        self.set_wallet_info(label="trusted_mints", label_info=json.dumps(self.trusted_mints))    
        print(proofs)
            
        #TODO Need to swap before adding
        print("XXXXX accept token")
        # self.swap_multi_consolidate()
        
        # self.add_proofs(json.dumps(proofs))
        self.add_proofs_obj(proof_obj_list)
        # self.swap_multi_consolidate()
        


    def issue_token(self, amount:int):
        print("issue token")
        available_amount = 0
        chosen_keyset = None
        keyset_proofs,keyset_amounts = self._proofs_by_keyset()
        for each in keyset_amounts:
            available_amount += keyset_amounts[each]
        
        
        print("available amount:", available_amount)
        if available_amount < amount:
            print("insufficient balance. you need more funds!")
            return
        
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
                print(f"pay with {each.amount}, {each.secret}")
            else:
                keep_proofs.append(each)
                print(f"keep {each.amount}, {each.secret}")
        print("spend:",spend_proofs) 
        print("keep:", keep_proofs)

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
        asyncio.run(self._async_delete_proof_events())
        
        
        self.add_proofs_obj(post_payment_proofs)
        
        self._load_proofs()


        
        tokens = TokenV3Token(mint=self.trusted_mints[chosen_keyset],
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
            print("insufficient balance. you need more funds!")
            return
        
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
        melt_quote_url = f"{self.trusted_mints[chosen_keyset]}/v1/melt/quote/bolt11"
        melt_url = f"{self.trusted_mints[chosen_keyset]}/v1/melt/bolt11"
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

    
    def zap(self, amount:int, event_id, comment): 
        out_msg = ""
        if event_id.startswith("note"):
            event_id = bech32_to_hex(event_id)
        
        zap_filter = [{  
            'ids'  :  [event_id]          
            
        }]
        prs = asyncio.run(self._async_query_zap(amount, comment,zap_filter))
        for each_pr in prs:
            self.pay_multi_invoice(each_pr)
            out_msg+=f"\nzap {amount} to event: {event_id} {each_pr}"
       
        
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
            print(event)  
            json_str =   f"{event.id}  {event.pub_key}  {event.content} {event.tags}"
            print("json_str", json_str)
            # json_obj = json.loads(json_str)
            # json_obj = json.loads(json_str)
        except:
            {"staus": "could not access profile"}
            pass
       
        if event == None:
            raise Exception("no event")
        
        for each in event.tags:
            if each[0] == "zap":
                zaps_to_send.append((each[1],each[2],each[3]))
        if zaps_to_send == []:
            zaps_to_send =[(event.pub_key,None,1)]
        
        print("zaps to send:", zaps_to_send)

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
                print("getting profile")
                event_profile = events_profile[0]  
                print(event)  
                profile_str =   event_profile.content
                print("profile", profile_str)
                profile_obj = json.loads(profile_str)
                lnaddress = profile_obj['lud16']
                print(lnaddress, lnaddress_to_lnurl(lnaddress))

                
            except:
                {"status": "could not access profile"}
                print("could not get profile")
                pass
            
            # Now we can create zap request
            print("create zap request")
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
            print("is valid:", zap_request.is_valid())
            print(zap_request, zap_request.tags, zap_request.id)
            print("serialize:", zap_request.serialize())
            print("to_dict:", zap_request.to_dict())
            zap_dict= zap_request.to_dict()
            print("zap_dict:",zap_dict )
            
            zap_test = Event().load(zap_dict)
            print("zap_test.id:", zap_test.id)
            print("zap test", zap_test, zap_test.is_valid())
            pr,_,_ = zap_address_pay(zap_amount,lnaddress,zap_dict)
            print("pay this invoice from the safebox:",pr)
            prs.append(pr)
        
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

        out_msg = f"{nrecipient} {npub}, {npub_hex}, {out_record}"

        # out_msg= asyncio.run(self._async_share_record(record_message=out_record,npub=npub, share_relays=share_relays ))
        asyncio.run(self._async_secure_dm(npub_hex=npub_hex, message=out_record,dm_relays=relays+ share_relays)) 
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
    
    def monitor(self, nrecipient: str):
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
        url = ['wss://relay.damus.io']
        asyncio.run(self.listen_notes(url, npub))
        while True:
            
            pass
        return 
    



    async def listen_notes(self, url, npub):



        # AS_K  = 'nsec1jagwdjtyhrln44p8d4pssnh9jdqgsc28lmmzq2lqksplfn9gac2su4790d' # OB
        # AS_K  = 'nsec1ex7f68hn863f8rzpc8gprclh876f7y0tzfaplvcs2rv6ju8wjkts7pu2c5' # TT
        AS_K    = 'nsec123v8adpuhrlurd4qqs5rsja44kz4yap3al3w8jk76wjkutxegtkqnz20zv' #08
        # TO_K = 'npub1q6mcr8tlr3l4gus3sfnw6772s7zae6hqncmw5wj27ejud5wcxf7q0nx7d5'
        # TO_K ='npub1pczukv7wx7l6mlpx54qxuzp0s32s7clejt04y4kl6z9vvgyz4x0qp4ehtq'
        
        # AS_K = self.privkey_bech32
        # AS_K = self.privkey_bech32
        print("privkey", self.privkey_bech32)
        TO_K = npub
        tail = util_funcs.str_tails
        
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

        async def output():
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
                    print(c_event.id[:4],c_event.created_at, c_event.content)
                    test = c_event.pub_key
                    


        asyncio.create_task(output())

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

            # this version is for us.. this seems to be the way oxchat does it I think but you could
            # just store locally though it'd be a pain getting your events on different instance
            await asyncio.sleep(0.2)
            wrapped_evt, trans_k = await my_gift.wrap(send_evt,
                                                    to_pub_k=my_k.public_key_hex())
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





if __name__ == "__main__":
    
    # url = ['wss://relay.0xchat.com','wss://relay.damus.io']
    # this relay seems to work the best with these kind of anon published events, atleast for now
    # others it seems to be a bit of hit and miss...
    url = ['wss://strfry.openbalance.app']
    # asyncio.run(listen_notes(url))  