#!/usr/bin/env python3
import socket
import struct
import logging
from monstr.encrypt import Keys
import bech32
import asyncio

from nostrdns import npub_to_hex_pubkey, lookup_npub_records, lookup_npub_records_tuples

# ---- logging ----
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("dns")

# ---- monstr (for npub validation) ----


def is_valid_npub(label: str) -> bool:
    """
    Validate a string as a Nostr npub (bech32).
    Requires HRP 'npub' and a 32-byte decoded payload.
    """
    if not isinstance(label, str) or not label:
        return False
    try:
        hrp, data = bech32.bech32_decode(label)
        if hrp is None or data is None:
            return False
        if hrp.lower() != "npub":
            return False
        decoded = bech32.convertbits(data, 5, 8, False)  # returns a list of ints
        return decoded is not None and len(decoded) == 32
    except Exception:
        return False
# Zone SOA config
ZONE   = "supername.app."
MNAME  = "ns1.supername.app."           # primary nameserver
RNAME  = "hostmaster.supername.app."    # admin email with '.' instead of '@'
SERIAL = 2025092701                     # bump when you change zone data
REFRESH = 3600
RETRY   = 600
EXPIRE  = 604800
MINIMUM = 3600
SOA_TTL = 3600


# -------------------------------
# Local records
# -------------------------------
LOCAL_DATA = {
    "example.com.": [("A", "93.184.216.34", 300)],
    "local.test.":  [("TXT", "hello from local", 60)],
}

# -------------------------------
# Upstream forwarders
# -------------------------------
FORWARDERS = [
    ("1.1.1.1", 53),
    ("8.8.8.8", 53),
]
FORWARD_TIMEOUT = 2.0

# -------------------------------
# DNS wire helpers
# -------------------------------
def encode_name(name: str) -> bytes:
    if not name.endswith("."):
        name += "."
    out = b""
    for label in name[:-1].split("."):
        b = label.encode()
        out += struct.pack("B", len(b)) + b
    return out + b"\x00"

def parse_question(msg: bytes):
    i = 12
    labels = []
    while True:
        ln = msg[i]; i += 1
        if ln == 0: break
        labels.append(msg[i:i+ln].decode()); i += ln
    qtype, qclass = struct.unpack(">HH", msg[i:i+4]); i += 4
    qname = ".".join(labels)+"."
    return qname, qtype, qclass, i

def build_flags(req_flags, rcode=0, aa=False, ra=True):
    rf = struct.unpack(">H", req_flags)[0]
    rd = rf & 0x0100
    flags = 0x8000               # QR=1
    if aa: flags |= 0x0400       # AA
    flags |= rd                  # mirror RD
    if ra: flags |= 0x0080       # RA
    flags |= rcode
    return struct.pack(">H", flags)

def rr_header(name, rtype, ttl, rdata):
    return encode_name(name) + struct.pack(">HHI", rtype, 1, ttl) + struct.pack(">H", len(rdata)) + rdata

def rr_a(name, ip, ttl):    return rr_header(name, 1, ttl, socket.inet_aton(ip))
def rr_txt(name, text, ttl):
    b = text.encode(); b = b[:255]
    return rr_header(name, 16, ttl, struct.pack("B", len(b))+b)

def rr_soa(qname: str, mname: str, rname: str,
           serial: int, refresh: int, retry: int,
           expire: int, minimum: int, ttl: int = 3600) -> bytes:
    def _enc(name: str) -> bytes:
        parts = name.rstrip(".").split(".")
        return b"".join(bytes([len(p)]) + p.encode() for p in parts) + b"\x00"

    rdata = (
        _enc(mname) +
        _enc(rname) +
        struct.pack(">IIIII", serial, refresh, retry, expire, minimum)
    )
    return (
        _enc(qname) +
        struct.pack(">HHI", 6, 1, ttl) +            # TYPE=SOA, CLASS=IN, TTL
        struct.pack(">H", len(rdata)) + rdata
    )

# -------------------------------
# Forward to upstream
# -------------------------------
def forward_query(req: bytes) -> bytes | None:
    for host, port in FORWARDERS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(FORWARD_TIMEOUT)
                s.sendto(req, (host, port))
                resp, _ = s.recvfrom(4096)
                return resp
        except Exception as e:
            log.debug(f"forwarder {host}:{port} failed: {e}")
            continue
    return None
def rr_soa(qname: str, mname: str, rname: str,
           serial: int, refresh: int, retry: int,
           expire: int, minimum: int, ttl: int = 3600) -> bytes:
    """
    Build a DNS SOA record.
    
    qname: zone name (e.g., 'supername.app.')
    mname: primary master nameserver (e.g., 'ns1.supername.app.')
    rname: responsible party (e.g., 'hostmaster.supername.app.')
    """
    # Encode names
    def encode_name(name: str) -> bytes:
        parts = name.rstrip('.').split('.')
        out = b''.join(struct.pack("B", len(p)) + p.encode() for p in parts)
        return out + b'\x00'

    rdata = (
        encode_name(mname) +
        encode_name(rname) +
        struct.pack(">IIIII", serial, refresh, retry, expire, minimum)
    )

    return (
        encode_name(qname) +
        struct.pack(">HHI", 6, 1, ttl) +  # type=SOA (6), class=IN (1), ttl
        struct.pack(">H", len(rdata)) +
        rdata
    )



# -------------------------------
# Build response
# -------------------------------
def build_response(req: bytes) -> bytes:
    tid, req_flags = req[:2], req[2:4]
    qname, qtype, qclass, qend = parse_question(req)
    question = req[12:qend]

    # If not IN class, delegate immediately
    if qclass != 1:
        resp = forward_query(req)
        if resp:
            return resp
        flags = build_flags(req_flags, rcode=2, aa=False, ra=True)
        return tid + flags + struct.pack(">HHHH", 1, 0, 0, 0) + question

    # --- SOA at zone apex (authoritative answer) ---
    if qtype in (6, 255) and qname == ZONE:
        answer = rr_soa(
            qname=ZONE, mname=MNAME, rname=RNAME,
            serial=SERIAL, refresh=REFRESH, retry=RETRY,
            expire=EXPIRE, minimum=MINIMUM, ttl=SOA_TTL
        )
        flags = build_flags(req_flags, rcode=0, aa=True, ra=True)
        header = tid + flags + struct.pack(">HHHH", 1, 1, 0, 0)
        return header + question + answer
    # -----------------------------------------------

    # Check leftmost label for npub
    leftmost = qname.split(".", 1)[0]
    if is_valid_npub(leftmost):
        records = asyncio.run(lookup_npub_records_tuples(leftmost, qtype))
        print(f"we have the records {records}")

        if records:
            answers = b""
            for rtype, val, ttl in records:
                if rtype == "A":
                    answers += rr_a(qname, val, ttl)
                elif rtype == "TXT":
                    answers += rr_txt(qname, val, ttl)
            flags = build_flags(req_flags, rcode=0, aa=True, ra=True)
            ancount = count_rrs(answers)
            header = tid + flags + struct.pack(">HHHH", 1, ancount, 0, 0)
            return header + question + answers

        answers = b""
        if qtype in (1, 255):
            answers += rr_a(qname, "100.100.100.100", ttl=60)
        if qtype in (16, 255):
            answers += rr_txt(qname, leftmost, ttl=60)

        if answers:
            flags = build_flags(req_flags, rcode=0, aa=True, ra=True)
            ancount = count_rrs(answers)
            header = tid + flags + struct.pack(">HHHH", 1, ancount, 0, 0)
            return header + question + answers
        else:
            resp = forward_query(req)
            if resp:
                return resp
            flags = build_flags(req_flags, rcode=2, aa=False, ra=True)
            return tid + flags + struct.pack(">HHHH", 1, 0, 0, 0) + question

    # No valid npub -> delegate immediately
    resp = forward_query(req)
    if resp:
        return resp

    flags = build_flags(req_flags, rcode=2, aa=False, ra=True)
    return tid + flags + struct.pack(">HHHH", 1, 0, 0, 0) + question



def count_rrs(rr_blob: bytes) -> int:
    i = 0; cnt = 0
    while i < len(rr_blob):
        # NAME
        while True:
            if i >= len(rr_blob): return cnt
            ln = rr_blob[i]; i += 1
            if ln == 0: break
            i += ln
        if i + 10 > len(rr_blob): return cnt
        _, _, _, rdlen = struct.unpack(">HHIH", rr_blob[i:i+10])
        i += 10 + rdlen
        cnt += 1
    return cnt

# -------------------------------
# UDP server
# -------------------------------
def start_dns_server(host="0.0.0.0", port=53):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    log.info(f"[Local+Forward DNS] listening on {host}:{port}")
    while True:
        data, addr = sock.recvfrom(4096)
        try:
            resp = build_response(data)
        except Exception as e:
            log.error(f"error building response: {e}")
            resp = data[:2] + build_flags(data[2:4], rcode=1) + b"\x00\x00\x00\x00\x00\x00\x00\x00"
        sock.sendto(resp, addr)

if __name__ == "__main__":
    start_dns_server()  # runs on port 53 by default
