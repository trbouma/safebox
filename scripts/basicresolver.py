#!/usr/bin/env python3
import socket
import struct

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
    ("1.1.1.1", 53),   # Cloudflare
    ("8.8.8.8", 53),   # Google
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
    return ".".join(labels)+".", qtype, qclass, i

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
        except Exception:
            continue
    return None

# -------------------------------
# Build response
# -------------------------------
def build_response(req: bytes) -> bytes:
    tid, req_flags = req[:2], req[2:4]
    qname, qtype, qclass, qend = parse_question(req)
    question = req[12:qend]

    # If in local dataset and IN class
    if qclass == 1 and qname in LOCAL_DATA:
        answers = b""
        for rtype, val, ttl in LOCAL_DATA[qname]:
            if rtype == "A" and qtype in (1, 255):
                answers += rr_a(qname, val, ttl)
            elif rtype == "TXT" and qtype in (16, 255):
                answers += rr_txt(qname, val, ttl)
        if answers:
            ancount = answers.count(b"\x00", 1)  # naive: one RR => one root label
            flags = build_flags(req_flags, rcode=0, aa=True, ra=True)
            header = tid + flags + struct.pack(">HHHH", 1, ancount, 0, 0)
            return header + question + answers

    # Otherwise, forward
    resp = forward_query(req)
    if resp: return resp

    # Fallback: SERVFAIL
    flags = build_flags(req_flags, rcode=2, aa=False, ra=True)
    return tid + flags + struct.pack(">HHHH", 1, 0, 0, 0) + question

# -------------------------------
# UDP server
# -------------------------------
def start_dns_server(host="0.0.0.0", port=53):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    print(f"[Local+Forward DNS] listening on {host}:{port}")
    while True:
        data, addr = sock.recvfrom(4096)
        try:
            resp = build_response(data)
        except Exception:
            resp = data[:2] + build_flags(data[2:4], rcode=1) + b"\x00\x00\x00\x00\x00\x00\x00\x00"
        sock.sendto(resp, addr)

if __name__ == "__main__":
    start_dns_server()   # <-- runs on port 53 by default
