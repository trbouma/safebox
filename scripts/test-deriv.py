from bip_utils import Bip39SeedGenerator, Bip32Slip10Secp256k1,Bip32Slip10Ed25519

from bech32 import bech32_encode, convertbits, bech32_decode
from monstr.encrypt import Keys

import base58

def privkey_hex_to_nsec(priv_hex: str) -> str:
    # sanitize + validate
    h = priv_hex.lower().replace("0x", "")
    if len(h) != 64:
        raise ValueError("Private key must be 32 bytes (64 hex chars).")
    try:
        raw = bytes.fromhex(h)
    except ValueError:
        raise ValueError("Invalid hex private key.")

    # Bech32 encode: HRP 'nsec' + data converted to 5-bit groups
    data5 = convertbits(list(raw), 8, 5, True)
    return bech32_encode("nsec", data5)

def nsec_to_privkey_bytes(nsec: str) -> bytes:
    """
    Convert a Nostr Bech32 'nsec...' string into raw 32-byte private key bytes.
    """
    hrp, data = bech32_decode(nsec)
    if hrp != "nsec" or data is None:
        raise ValueError("Invalid nsec string.")
    raw = bytes(convertbits(data, 5, 8, False))
    if len(raw) != 32:
        raise ValueError(f"nsec payload must be 32 bytes, got {len(raw)}.")
    return raw

def pubkey_hex_to_npub(pub_hex: str) -> str:
    """
    Convert a secp256k1 public key in hex to a Nostr npub (Bech32, NIP-19).
    Accepts either:
      - 64-hex chars (32 bytes x-only)  -> used as-is
      - 66-hex chars (33 bytes compressed SEC1; starts with 02/03) -> strip prefix
    """
    h = pub_hex.lower().replace("0x", "")
    if len(h) == 66:
        # compressed SEC1: 0x02/0x03 + 32-byte X
        if not (h.startswith("02") or h.startswith("03")):
            raise ValueError("Compressed pubkey must start with 02 or 03.")
        h = h[2:]  # drop prefix -> 32-byte x-only
    elif len(h) != 64:
        raise ValueError("Public key must be 32-byte x-only (64 hex) or 33-byte compressed (66 hex).")

    raw32 = bytes.fromhex(h)  # 32 bytes
    data5 = convertbits(list(raw32), 8, 5, True)
    return bech32_encode("npub", data5)


def derive_child_pub_from_xpub(xpub: str, path: str) -> str:
    # path like "m/0/1/2" or "0/1/2" (no hardened segments allowed)
    ctx = Bip32Slip10Secp256k1.FromExtendedKey(xpub)
    segs = [s for s in path.split("/") if s not in ("", "m", "M")]
    for s in segs:
        if s.endswith(("'", "h", "H")):
            raise ValueError("Cannot derive hardened indexes from an xpub: %r" % s)
    if segs:
        ctx = ctx.DerivePath("/".join(segs))
    return ctx.PublicKey().RawCompressed().ToHex()

def derive_child_pub_from_xpub_bech32(xpub_bech32: str, path: str) -> str:
    # path like "m/0/1/2" or "0/1/2" (no hardened segments allowed)
    xpub_base58 = bech32_xpub_to_base58_xpub(xpub_bech32)

    ctx = Bip32Slip10Secp256k1.FromExtendedKey(xpub_base58)
    segs = [s for s in path.split("/") if s not in ("", "m", "M")]
    for s in segs:
        if s.endswith(("'", "h", "H")):
            raise ValueError("Cannot derive hardened indexes from an xpub: %r" % s)
    if segs:
        ctx = ctx.DerivePath("/".join(segs))
    return pubkey_hex_to_npub(ctx.PublicKey().RawCompressed().ToHex())

def derive_child_privkey_from_rootpriv_bech32(privkey_bech32: str, path: str) -> str:

    
    privkey_bytes = nsec_to_privkey_bytes(privkey_bech32)
    
    bip32_ctx = Bip32Slip10Secp256k1.FromPrivateKey(privkey_bytes)
    nostr_node = bip32_ctx.DerivePath(path)
    privkey = nostr_node.PrivateKey().Raw().ToBytes()
    
    privkey_nsec = privkey_hex_to_nsec(privkey.hex())
    # print(privkey_nsec)
    return privkey_nsec

def base58_xpub_to_bech32_xpub(xpub_b58: str, hrp: str = "xpub") -> str:
    """
    Convert a standard Base58Check BIP-32 xpub to a NON-STANDARD Bech32 string with HRP 'xpub' (or custom HRP).
    Keeps the 78-byte BIP-32 serialization intact.
    """
    raw = base58.b58decode_check(xpub_b58)  # 78 bytes: ver|depth|parentfp|child|chaincode|keydata
    if len(raw) != 78:
        raise ValueError(f"Unexpected extended key length: {len(raw)} bytes (expected 78).")
    data5 = convertbits(list(raw), 8, 5, True)  # pad=True for encoding
    return bech32_encode(hrp, data5)

def bech32_xpub_to_base58_xpub(xpub_b32: str, expected_hrp: str = "xpub") -> str:
    """
    Convert a NON-STANDARD Bech32 'xpub' (with HRP 'xpub' or custom) back to standard Base58Check xpub.
    """
    hrp, data = bech32_decode(xpub_b32)
    if data is None:
        raise ValueError("Invalid Bech32 string.")
    if hrp != expected_hrp:
        raise ValueError(f"Unexpected HRP: '{hrp}' (expected '{expected_hrp}').")
    raw = bytes(convertbits(data, 5, 8, False))  # pad=False for decoding
    if len(raw) != 78:
        raise ValueError(f"Unexpected extended key length: {len(raw)} bytes after decode (expected 78).")
    return base58.b58encode_check(raw).decode()

def generate_next_paths(base_path: str, count: int = 100):
    """
    Generate a list of derivation paths incrementing the rightmost index.

    Example:
        base_path = "M/44/1237/0/0/0"
        → returns ["M/44/1237/0/0/1", ..., "M/44/1237/0/0/100"]

    Args:
        base_path (str): The starting derivation path.
        count (int): How many subsequent paths to generate (default = 100).

    Returns:
        list[str]: List of incremented derivation paths.
    """
    # Normalize path (case-insensitive "m" or "M")
    parts = base_path.strip().replace("'", "").split("/")
    
    # Ensure we have at least one numeric component
    try:
        last_index = int(parts[-1])
    except ValueError:
        raise ValueError(f"Last path component is not an integer: {parts[-1]}")

    # Generate next N paths
    new_paths = []
    for i in range(1, count + 1):
        parts_copy = parts[:-1] + [str(last_index + i)]
        new_paths.append("/".join(parts_copy))

    return new_paths

# seed = Bip39SeedGenerator(seed_phrase).Generate()
# bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed)
# seed_private_key_hex = bip32_ctx.PrivateKey().Raw().ToBytes().hex()
# data_bytes = bytes.fromhex(seed_private_key_hex)
# data_5bit = convertbits(data_bytes, 8, 5)
# bech32_address = bech32_encode("nsec", data_5bit)

mnemonic = "abandon "*11 + " about"
seed = Bip39SeedGenerator(mnemonic).Generate()
print(f"seed: {seed.hex()}")

# Create master key
bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed)
master_privkey_hex = bip32_ctx.PrivateKey().Raw().ToHex()
master_pubkey_hex = bip32_ctx.PublicKey().RawCompressed().ToHex()
print(f"bip32 master private key: {master_privkey_hex} nsec {privkey_hex_to_nsec(master_privkey_hex)} pubkey hex: {master_pubkey_hex} npub{pubkey_hex_to_npub(master_pubkey_hex)}")

#Try to create an extended public key
print("extended public key")
xpub_base58 = bip32_ctx.PublicKey().ToExtended()
xpub_bech32 = base58_xpub_to_bech32_xpub(xpub_base58)
print("master public keys")
print(f"xpub base58: {xpub_base58} xpub bech32: {xpub_bech32}")

# Derive Nostr key path m/44'/1237'/0'/0/0
# path = "m/44/1237/0/0/1"
# m / purpose' / coin_type' / account' / change / address_index
privkey_path =  "m/44/1237/0/0/0'"
pubkey_path =   "M/44/1237/0/0/0'"
# privkey_path =  ""
# pubkey_path =   ""


print(f"root pubkey hex {master_pubkey_hex} npub: {pubkey_hex_to_npub(master_pubkey_hex)}")
print(f"derived using master private key using: {privkey_path}")
nostr_node = bip32_ctx.DerivePath(privkey_path)

priv_key = nostr_node.PrivateKey().Raw().ToBytes()
pub_key = nostr_node.PublicKey().RawCompressed().ToBytes()
pub_key_bech32 = pubkey_hex_to_npub(pub_key.hex())

print(f"nsec: {priv_key.hex()} / {privkey_hex_to_nsec(priv_key.hex())} ")
print(f"npub hex {pub_key.hex()} npub: {pub_key_bech32}")

print(f"derived from master public key using: {pubkey_path}")

child_pub_hex = derive_child_pub_from_xpub(xpub_base58, pubkey_path)
child_pub_bech32 = derive_child_pub_from_xpub_bech32(xpub_bech32,pubkey_path)



print(f"child npub hex: {child_pub_hex} {pubkey_hex_to_npub(child_pub_hex)}")
print(f"child npub hex from bech32: {child_pub_bech32} {child_pub_bech32}")
assert pub_key_bech32 == child_pub_bech32

"""

next_privkey_paths = generate_next_paths(base_path=privkey_path,count=1)
next_pubkey_paths = generate_next_paths(base_path=pubkey_path,count=1)

# print(next_pubkey_paths,next_privkey_paths)
master_privkey_nsec = privkey_hex_to_nsec(master_privkey_hex)
print(f"Master nsec: \n{master_privkey_nsec}\n")

print(f"now the private keys for {next_privkey_paths}:")
for each in next_privkey_paths:
   
    child_privkey_nsec = derive_child_privkey_from_rootpriv_bech32(privkey_bech32=master_privkey_nsec, path=each)
    
    nostr_keys = Keys(child_privkey_nsec)
    print(child_privkey_nsec, nostr_keys.public_key_bech32())

print(f"now the public keys for {next_pubkey_paths}:")
for each in next_pubkey_paths:
    
    child_pub_bech32 = derive_child_pub_from_xpub_bech32(xpub_bech32,each)
    print(child_pub_bech32)

"""