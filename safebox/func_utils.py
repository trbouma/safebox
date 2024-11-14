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

def name_to_hex(name):
    # Load the BIP-0039 word list
    mnemonic = Mnemonic("english")
    word_list = mnemonic.wordlist

    # Split the name into parts: first_word, second_word, and number
    try:
        first_word, second_word, number_str = name.split("-")
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