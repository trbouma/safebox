import urllib.parse
import requests, json
import asyncio, base64, io, re
import datetime, hashlib, urllib, uuid
import binascii
import os
from bech32 import bech32_encode, convertbits
from mnemonic import Mnemonic

def generate_name_from_hex(hex_string):
    # Ensure the input is a valid 32-byte hex string
    if len(hex_string) != 64:
        raise ValueError("Input must be a 32-byte hex string (64 characters).")
  

    # Convert the first 3 characters to an integer for the first word index
    first_word_index = int(hex_string[:32], 16) % 2048  # Modulo 2048 to fit in the BIP-39 word list
    # Convert the next 3 characters to an integer for the second word index
    second_word_index = int(hex_string[-32:], 16) % 2048

    # Load the BIP-39 word list
    mnemonic = Mnemonic("english")
    word_list = mnemonic.wordlist

    # Select words based on indices
    first_word = word_list[first_word_index]
    second_word = word_list[second_word_index]

    # Add numeric suffix as the integer representation of the first 6 characters
    suffix = int(hex_string, 16) % 99 + 1

    # Generate the final name
    generated_name = f"{first_word}{second_word}{suffix}"

    return generated_name