import urllib.parse
import requests, json
import asyncio, base64, io, re
import datetime, hashlib, urllib, uuid
import binascii
import os
from bech32 import bech32_encode, convertbits
from typing import List
from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip32Slip10Ed25519, Bip32Slip10Secp256k1
import bech32

from safebox.models import NIP60Proofs

from monstr.client.client import Client, ClientPool
from monstr.event.event import Event

def generate_name_from_hex(hex_string):
    # Ensure the input is a valid 32-byte hex string
    if len(hex_string) != 64:
        raise ValueError("Input must be a 32-byte hex string (64 characters).")

    # Load BIP-0039 word list
    mnemonic = Mnemonic("english")
    word_list = mnemonic.wordlist

    # Extract the first four bytes (8 hex characters)
    first_four_bytes = hex_string[:8]

    # Convert these bytes to a binary string (32 bits)
    binary_string = bin(int(first_four_bytes, 16))[2:].zfill(32)

    # Split the binary string into two 11-bit values and one 10-bit value
    first_11_bit = int(binary_string[:11], 2)
    second_11_bit = int(binary_string[11:22], 2)
    ten_bit = int(binary_string[22:32], 2)

    # Look up the words corresponding to the 11-bit values
    first_word = word_list[first_11_bit]
    second_word = word_list[second_11_bit]

    # Create the hyphen-separated name
    name = f"{first_word}-{second_word}-{ten_bit}"

    return name


def generate_access_key_from_hex(hex_string):
    # Ensure the input is a valid 32-byte hex string
    if len(hex_string) != 64:
        raise ValueError("Input must be a 32-byte hex string (64 characters).")

    # Load BIP-0039 word list
    mnemonic = Mnemonic("english")
    word_list = mnemonic.wordlist

    # Extract the first four bytes (8 hex characters)
    first_four_bytes = hex_string[:8]

    # Convert these bytes to a binary string (32 bits)
    binary_string = bin(int(first_four_bytes, 16))[2:].zfill(32)

    # Split the binary string into two 11-bit values and one 10-bit value
    first_11_bit = int(binary_string[:11], 2)
    second_11_bit = int(binary_string[11:22], 2)
    ten_bit = int(binary_string[22:32], 2)

    # Look up the words corresponding to the 11-bit values
    first_word = word_list[first_11_bit]
    second_word = word_list[second_11_bit]

    # Create the hyphen-separated name
    access_key = f"{ten_bit}-{first_word}-{second_word}"

    return access_key

def name_to_hex(name):
    # Load the BIP-0039 word list
    mnemonic = Mnemonic("english")
    word_list = mnemonic.wordlist

    # Split the name into parts: first_word, second_word, and number
    try:
        first_word, second_word, number_str = name.replace("@","").split("-")
        number = int(number_str)
    except ValueError:
        raise ValueError("The name format is invalid. Expected format: 'word1-word2-number'")

    # Find the indices of the two words in the BIP-0039 word list
    try:
        first_11_bit = word_list.index(first_word)
        second_11_bit = word_list.index(second_word)
    except ValueError:
        raise ValueError("One or both of the words are not in the BIP-0039 word list.")

    # Convert indices to 11-bit binary strings and the number to a 10-bit binary string
    first_11_binary = format(first_11_bit, '011b')
    second_11_binary = format(second_11_bit, '011b')
    ten_bit_binary = format(number, '010b')

    # Concatenate to get the original 32-bit binary string
    binary_string = first_11_binary + second_11_binary + ten_bit_binary

    # Convert the binary string back to a hex string (4 bytes)
    hex_string = f"{int(binary_string, 2):08x}"

    return hex_string

def recover_nsec_from_seed(seed_phrase: str, legacy: bool = False):
    mnemo = Mnemonic("english")
    print(f"legacy: {legacy}")
    seed = Bip39SeedGenerator(seed_phrase).Generate()
    if legacy:
        bip32_ctx = Bip32Slip10Ed25519.FromSeed(seed)
    else:
        bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed)
    
    seed_private_key_hex = bip32_ctx.PrivateKey().Raw().ToBytes().hex()
   

    data_bytes = bytes.fromhex(seed_private_key_hex)
    data_5bit = convertbits(data_bytes, 8, 5)
    bech32_address = bech32_encode("nsec", data_5bit)

    return bech32_address



def split_proofs_instance(original: NIP60Proofs, num_splits: int = 2) -> List[NIP60Proofs]:
    if num_splits <= 0:
        raise ValueError("num_splits must be greater than zero")

    
    total = len(original.proofs)
    k, r = divmod(total, num_splits)

    result = []
    start = 0
    for i in range(num_splits):
        end = start + k + (1 if i < r else 0)
        split = original.proofs[start:end]
        result.append(NIP60Proofs(mint=original.mint, proofs=split))
        start = end

    return result

def npub_to_hex(npub: str) -> str:
    """
    Converts a Nostr npub public key to its corresponding hex representation.
    
    :param npub: A Nostr public key in Bech32 format (starting with 'npub')
    :return: The corresponding hex public key.
    """
    if not npub.startswith("npub"):
        raise ValueError("Invalid npub format. It should start with 'npub'.")

    # Decode Bech32 npub format
    hrp, data = bech32.bech32_decode(npub)
    
    if hrp != "npub" or data is None:
        raise ValueError("Invalid npub Bech32 encoding.")

    # Convert 5-bit chunks to 8-bit bytes
    decoded_bytes = bech32.convertbits(data, 5, 8, False)
    
    if decoded_bytes is None:
        raise ValueError("Error in converting Bech32 data.")

    # Convert bytes to hex string
    return bytes(decoded_bytes).hex()

async def get_profile_for_pub_hex(pub_hex:str, relays:List=None):
   
    owner = 'No Owner Found'
    events = None

    FILTER = [{
                'limit': 1,
                'authors': [pub_hex],
                'kinds': [0] }]
    
    async with ClientPool(relays) as c:  
            events = await c.query(FILTER)   

    if events:
        print(f"kind 0{events[0].content}")
        json_obj = json.loads(events[0].content)
        owner = f"{json_obj.get("name", "")} {json_obj.get("nip05", "")} "
    else:
        owner = pub_hex
    return owner
