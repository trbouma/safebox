from typing import Any, Dict, List, Optional, Union
import asyncio, json

from monstr.encrypt import Keys
from monstr.client.client import Client, ClientPool
from monstr.event.event import Event
from monstr.encrypt import NIP44Encrypt, NIP4Encrypt

from safebox.models import nostrProfile, SafeboxItem

class Wallet:
    k: Keys
    nsec: str
    pubkey_bech32: str
    pubkey_hex: str
    privkey_hex: str
    relays: List[str]
    safe_box_items: List[SafeboxItem]



    def __init__(self, nsec: str, relays: List[str]) -> None:
        if nsec.startswith('nsec'):
            self.k = Keys(priv_k=nsec)
            self.pubkey_bech32  =   self.k.public_key_bech32()
            self.pubkey_hex     =   self.k.public_key_hex()
            self.privkey_hex    =   self.k.private_key_hex()
            self.relays         =   relays
            self.safe_box_items = []

        else:
            print("Error")
  

    def get_profile(self) -> nostrProfile:
        
        
        FILTER = [{
            'limit': 1,
            'authors': [self.pubkey_hex],
            'kinds': [0]
        }]
        profile =asyncio.run(self.async_query_client_profile(self.relays,FILTER))

        nostr_profile = nostrProfile(name           = profile.get('name', 'Not Set'),
                                     display_name   = profile.get('display_name', 'Not Set'),
                                     about          = profile.get('about', "Not Set" ),
                                     nip05          = profile.get('nip05', "Not Set" ),
                                     banner         = profile.get('banner', "Not Set" ),
                                     website        = profile.get('website', "Not Set" ),
                                     lud16          = profile.get('lud16', "Not Set" ),

                                     )

        
        
        return nostr_profile
    
    async def async_query_client_profile(self, relay: str, filter: List[dict]):
    # does a one off query to relay prints the events and exits
    
        async with ClientPool([relay, 'wss://relay.damus.io']) as c:
        # async with Client(relay) as c:
            events = await c.query(filter)
            return json.loads(events[0].content)
           
    def get_post(self):
        
        
        FILTER = [{
            'limit': 1,
            'authors': [self.pubkey_hex],
            'kinds': [1]
        }]
        content =asyncio.run(self.query_client_post(FILTER))
        
        return content
    
    async def query_client_post(self, filter: List[dict]):
    # does a one off query to relay prints the events and exits
    
        async with ClientPool(self.relays) as c:
        # async with Client(relay) as c:
            events = await c.query(filter)
            return events[0].content

    def send_post(self,text):
        asyncio.run(self.do_post(text))  
    
    async def do_post(self, text:str):
        """
            Example showing how to post a text note (Kind 1) to relay
        """

        # rnd generate some keys
        
        async with ClientPool(self.relays) as c:
        # async with Client(relay) as c:
            n_msg = Event(kind=Event.KIND_TEXT_NOTE,
                        content=text,
                        pub_key=self.pubkey_hex)
            n_msg.sign(self.privkey_hex)
            c.publish(n_msg)
            # await asyncio.sleep(1)

    def set_wallet_info(self,wallet_name: str, mints: List[str], relays: List[str],wallet_info: str):
        asyncio.run(self._async_set_wallet_info(wallet_name, mints, relays,wallet_info))  
    
    async def _async_set_wallet_info(self, wallet_name:str, mints: List[str], relays: List[str], wallet_info: str):

        print("the latest wallet info", wallet_info)
        my_enc = NIP44Encrypt(self.k)
        wallet_info_encrypt = my_enc.encrypt(wallet_info,to_pub_k=self.pubkey_hex)
       
        

        tags = [['d',wallet_name]]
        
        if mints != None:
            for each in mints:
                tags.append(["mint", each if 'https://' in each else 'https://'+each])
        if relays != None:
            for each in relays:
                tags.append(["relay", each if 'wss://' in each else 'wss://'+each])

        # print(tags)
       
       

        async with ClientPool(self.relays) as c:
        # async with Client(relay) as c:
            n_msg = Event(kind=37375,
                        content=wallet_info_encrypt,
                        pub_key=self.pubkey_hex,
                        tags=tags)
            
            # n_msg = my_enc.encrypt_event(evt=n_msg,
            #                         to_pub_k=self.pubkey_hex)
            
            n_msg.sign(self.privkey_hex)
            print(n_msg.data())
            c.publish(n_msg)
            # await asyncio.sleep(1)

    def get_wallet_info(self, d_tag:str=None):
        my_enc = NIP44Encrypt(self.k)
        
        DEFAULT_RELAY = self.relays[0]
        FILTER = [{
            'limit': 100,
            'authors': [self.pubkey_hex],
            'kinds': [37375],
            'd':d_tag
            
        }]
        event =asyncio.run(self._async_get_wallet_info(FILTER))
        
        # print(event.data())
        decrypt_content = my_enc.decrypt(event.content, self.pubkey_hex)
        # print("tags", event.tags)
        encrypt_d = "None"
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

        return "event " + event.id + " " + decrypt_content +" "+ "d tag:" + orig_d
    
    async def _async_get_wallet_info(self, filter: List[dict]):
    # does a one off query to relay prints the events and exits
        # print("filter", filter[0]['d'])
        my_enc = NIP44Encrypt(self.k)
        target_tag = filter[0]['d']
        event_select = None
        async with ClientPool(self.relays) as c:
        # async with Client(relay) as c:
            
            events = await c.query(filter)
            
            print(f"37375 events: {len(events)}")

            


            for each in events:
               
                try:
                    # print("EACH!!: ", each.data())
                    # print("TAG: ", each.tags)
                    for each_tag in each.tags:
                        if each_tag[0] == 'd':
                            print(each_tag[1])
                            if each_tag[1] == target_tag:
                                # print("MATCH HELLO!!")
                                event_select = each                   

                except:
                    # print('no d tag')
                    pass
                
            
            return event_select
        
    def set_index_info(self,index_info: str):
        asyncio.run(self._async_set_index_info(index_info))  
    
    async def _async_set_index_info(self, index_info: str):

        print("the latest index info", index_info)
        my_enc = NIP44Encrypt(self.k)
        index_info_encrypt = my_enc.encrypt(index_info,to_pub_k=self.pubkey_hex)
    

        async with ClientPool(self.relays) as c:
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

    def get_index_info(self, d_tag:str=None):
        my_enc = NIP44Encrypt(self.k)
        
        DEFAULT_RELAY = self.relays[0]
        FILTER = [{
            'limit': 100,
            'authors': [self.pubkey_hex],
            'kinds': [17375]
            
        }]
        event =asyncio.run(self._async_get_index_info(FILTER))
        
        # print(event.data())
        decrypt_content = my_enc.decrypt(event.content, self.pubkey_hex)


        return "event " + event.id + " " + decrypt_content 
    
    async def _async_get_index_info(self, filter: List[dict]):
    # does a one off query to relay prints the events and exits
        # print("filter", filter[0]['d'])
        my_enc = NIP44Encrypt(self.k)
        
        event_select = None
        async with ClientPool(self.relays) as c:
        # async with Client(relay) as c:
            
            events = await c.query(filter)
            
            print(f"27375 events: {len(events)}")
  
            
            return events[0]

    def add_item(self, safe_box_item: SafeboxItem):
        asyncio.run(self._async_add_item(safe_box_item)) 

        return safe_box_item.model_dump()

    async def _async_add_item(self, safe_box_item: SafeboxItem):

        
        my_enc = NIP44Encrypt(self.k)

        payload = json.dumps(safe_box_item.model_dump())
        
        
        payload_encrypt = my_enc.encrypt(payload,to_pub_k=self.pubkey_hex)
        
        tags = [['d',safe_box_item.get_d_tag(self.pubkey_hex)]]
      

        async with ClientPool(self.relays) as c:
        # async with Client(relay) as c:
            n_msg = Event(kind=37375,
                        content=payload_encrypt,
                        pub_key=self.pubkey_hex,
                        tags=tags)
            
            # n_msg = my_enc.encrypt_event(evt=n_msg,
            #                         to_pub_k=self.pubkey_hex)
            
            n_msg.sign(self.privkey_hex)
            print(n_msg.data())
            c.publish(n_msg)
            # await asyncio.sleep(1)