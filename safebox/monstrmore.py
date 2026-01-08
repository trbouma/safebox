import json
import random
from typing import Union
from datetime import datetime
from monstr.signing.signing import SignerInterface, BasicKeySigner
from monstr.encrypt import Keys
from monstr.event.event import Event
from monstr.util import util_funcs
from monstr.encrypt import NIP44Encrypt

import oqs

# This was created to remove the jittered ticks

class KindOtherGiftWrapException(Exception):
    pass


class KindOtherGiftWrap:
    """
        implementation of NIP59 https://github.com/nostr-protocol/nips/blob/master/59.md
        replaces our inbox class
    """
    KIND_OTHER_GIFT_WRAP: int

    def __init__(self, signer: SignerInterface, kind_gift_wrap: int = 1060):
        self._signer = signer
        # jitter is upto 2 days from now
        self._jitter = 60 * 60 * 24 * 2
        self.KIND_OTHER_GIFT_WRAP = kind_gift_wrap

    def get_jittered_created_ticks(self):
        # remove jittered ticks - deactivate
        return util_funcs.date_as_ticks(datetime.now()) 

    async def _make_rumour(self, evt: Event) -> Event:
        """
            A rumor is the same thing as an unsigned event.
            Any event kind can be made a rumor by removing the signature.
            so we just return a copy evt but make sure no sig, pubkey is us
            end it's seralised with these val
        """

        event_data = evt.data()
        event_data['sig'] = None
        event_data['pubkey'] = await self._signer.get_public_key()
        event_data['kind'] = Event.KIND_RUMOUR

        ret = Event.load(event_data)
        # this forces the id, oxchat didn't see the events without this
        ret.id
        # forces id to be calculated
        return ret

    async def _make_seal(self,
                         rumour_evt: Event,
                         to_pub_k: Union[Keys, str]) -> Event:

        if rumour_evt.sig:
            raise KindOtherGiftWrapException('TemporaryGiftWrap::_make_seal: rumour event should not be signed!')

        if isinstance(to_pub_k, Keys):
            to_pub_k = to_pub_k.public_key_hex()

        ret = Event(kind=Event.KIND_SEAL,
                    content=await self._signer.nip44_encrypt(plain_text=json.dumps(rumour_evt.data()),
                                                             to_pub_k=to_pub_k),
                    created_at=self.get_jittered_created_ticks(),
                    pub_key=await self._signer.get_public_key(),
                    tags=[])

        await self._signer.sign_event(ret)
        return ret

    async def wrap(self, evt: Event, to_pub_k: Union[Keys, str], pow: int = None) -> tuple[Event, Keys]:
        if isinstance(to_pub_k, Keys):
            to_pub_k = to_pub_k.public_key_hex()

        rumour_evt = await self._make_rumour(evt)
        sealed_evt = await self._make_seal(rumour_evt, to_pub_k)

        rnd_k = Keys()
        rnd_sign = BasicKeySigner(rnd_k)

        ret = Event(kind=self.KIND_OTHER_GIFT_WRAP,
                    pub_key=rnd_k.public_key_hex(),
                    created_at=self.get_jittered_created_ticks(),
                    content=await rnd_sign.nip44_encrypt(plain_text=json.dumps(sealed_evt.data()),
                                                         to_pub_k=to_pub_k),
                    tags=[
                        ['p', to_pub_k]
                    ])

        if pow is not None:
            ret.add_pow(pow)

        await rnd_sign.sign_event(ret)
        return ret, rnd_k

    async def _unwrap(self, evt: Event) -> Event:
        wrapped_str = await self._signer.nip44_decrypt(evt.content, evt.pub_key)
        return Event.load(wrapped_str)

    async def unwrap(self, evt: Event):
        to_pub_k = evt.tags.get_tag_value_pos('p')
        our_pub_k = await self._signer.get_public_key()

        if to_pub_k is None:
            raise KindOtherGiftWrap('wraped event is not addressed to anyone, no p ptags!')
        if to_pub_k != our_pub_k:
            raise KindOtherGiftWrap(f'wraped event is not addressed to us,'
                                    f' {util_funcs.str_tails(our_pub_k)} != {util_funcs.str_tails(to_pub_k)}')

        # unwrap the seal event
        seal_evt = await self._unwrap(evt)
        # unseal (unwrap again)
        rumour_evt = await self._unwrap(seal_evt)
        return rumour_evt
    

class ExtendedNIP44Encrypt(NIP44Encrypt):
    NIP44_PAD_MAX = 262143  # New upper bound for padding length (e.g., 128 KB

class PQEvent(Event):
    test: str
    sigalg: str = "ML-DSA-44"

    def sign(self, priv_key):
        
        print(f"length of private key {len(priv_key)}")
        if len(priv_key) > 64: 
            signer = oqs.Signature(self.sigalg,secret_key=bytes.fromhex(priv_key))
            # print(f"sign with {priv_key}")
            self._get_id()
            id_bytes = (bytes(bytearray.fromhex(self._id)))
        
            signature = signer.sign(id_bytes)
            self._sig = signature.hex()
        else:
            self._get_id()

           
            pk = secp256k1.PrivateKey()
            pk.deserialize(priv_key)

            id_bytes = (bytes(bytearray.fromhex(self._id)))
            sig = pk.schnorr_sign(id_bytes, bip340tag='', raw=True)
            sig_hex = sig.hex()

            self._sig = sig_hex

    def is_valid(self):
        is_valid = False
        try:
            if len(self.pub_key) > 64:
            
                verifier = oqs.Signature(self.sigalg)

                id_bytes = (bytes(bytearray.fromhex(self.id)))
                sig_bytes = (bytes(bytearray.fromhex(self.sig)))
                pub_key_bytes = (bytes(bytearray.fromhex(self.pub_key)))

                is_valid = verifier.verify(id_bytes, sig_bytes, pub_key_bytes)
            else:
                
                pub_key = secp256k1.PublicKey(bytes.fromhex('02'+self._pub_key),
                                        raw=True)

                is_valid = pub_key.schnorr_verify(
                            msg=bytes.fromhex(self._id),
                            schnorr_sig=bytes.fromhex(self._sig),
                            bip340tag='', raw=True)
        except:
            is_valid = False   
                 
        return is_valid
    
    @staticmethod    
    def load(event_data: Union[str, dict], validate=False) -> 'PQEvent':
        """
            return a Event object either from a dict or json str this replaces the old from_JSON method
            that was actually just from a string...
            if validate is set True will test the event sig, if it's not None will be returned

        """
        if isinstance(event_data, str):
            try:
                event_data = json.loads(event_data)
            except Exception as e:
                event_data = {}

        id = None
        if 'id' in event_data:
            id = event_data['id']

        sig = None
        if 'sig' in event_data:
            sig = event_data['sig']

        kind = None
        if 'kind' in event_data:
            kind = event_data['kind']

        content = None
        if 'content' in  event_data:
            content = event_data['content']

        tags = None
        if 'tags' in event_data:
            tags = event_data['tags']

        pub_key = None
        if 'pubkey' in event_data:
            pub_key = event_data['pubkey']

        created_at = None
        if 'created_at' in event_data:
            created_at = event_data['created_at']

        ret = PQEvent(
            id=id,
            sig=sig,
            kind=kind,
            content=content,
            tags=tags,
            pub_key=pub_key,
            created_at=created_at
        )

        # None ret if validating and the evnt is not valid
        if validate is True and ret.is_valid() is False:
            ret = None

        return ret