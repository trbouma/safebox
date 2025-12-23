#!/usr/bin/env python3
import socket
import struct
import time

# ---------- ZONE CONFIG ----------
ZONE = "safebox.dev."
MNAME = "ns1.safebox.dev."            # primary/master nameserver
RNAME = "hostmaster.safebox.dev."     # admin email with '.' instead of '@'

# Serial: yyyymmddNN (bump when you change records)
SERIAL = int(time.strftime("%Y%m%d")) * 100 + 1
REFRESH = 3600
RETRY   = 900
EXPIRE  = 1209600
MINIMUM = 300

# Host A records you want to serve (add more as needed)
A_RECORDS = {
    "ns1.safebox.dev.": "203.0.113.10",   # <-- replace with your server IP
    "ns2.safebox.dev.": "203.0.113.11",   # <-- ideally a 2nd server/IP
    "safebox.dev.":       "203.0.113.20", # apex A (optional)
    # "www.safebox.dev.": "203.0.113.21",
}

# NS records at the zone apex
NS_RECORDS = [
    "ns1.safebox.dev.",
    "ns2.safebox.dev.",
]

TTL_DEFAULT = 300
SOA_TTL = 300
NS_TTL = 300
A_TTL = 300
# ---------------------------------


def encode_name(name: str) -> bytes:
    """Encode a domain name like 'example.com.' into DNS wire format."""
    if not name.endswith("."):
        name += "."
    out = b""
    for label in name[:-1].split("."):
        if not label:
            continue
        b_label = label.encode("utf-8")
        out += struct.pack("B", len(b_label)) + b_label
    return out + b"\x00"


def parse_question(data):
    """
    Parse a single question. Return (qname, qtype, qclass, q_end)
    where q_end is the index just after QCLASS.
    """
    i = 12
    labels = []
    while True:
        if i >= len(data):
            raise ValueError("Malformed packet: QNAME overrun")
        ln = data[i]
        i += 1
        if ln == 0:
            break
        if i + ln > len(data):
            raise ValueError("Malformed packet: label overrun")
        labels.append(data[i:i+ln].decode("utf-8"))
        i += ln
    if i + 4 > len(data):
        raise ValueError("Malformed packet: missing QTYPE/QCLASS")
    qtype, qclass = struct.unpack(">HH", data[i:i+4])
    qname = ".".join(labels) + "."
    return qname, qtype, qclass, i + 4


def build_flags(req_flags, rcode=0):
    rf = struct.unpack(">H", req_flags)[0] if len(req_flags) == 2 else 0
    rd = rf & 0x0100  # mirror RD
    flags = 0x8000    # QR=1 response
    flags |= 0x0400   # AA=1 authoritative
    flags |= rd       # mirror RD from query
    flags |= (rcode & 0xF)
    return struct.pack(">H", flags)


def rr_header(name: str, rtype: int, rclass: int, ttl: int, rdlength: int) -> bytes:
    return (
        encode_name(name) +
        struct.pack(">HHI", rtype, rclass, ttl) +
        struct.pack(">H", rdlength)
    )


def rr_a(name: str, ip: str, ttl=A_TTL) -> bytes:
    rdata = socket.inet_aton(ip)
    return rr_header(name, 1, 1, ttl, len(rdata)) + rdata  # TYPE=A, CLASS=IN


def rr_ns(name: str, host: str, ttl=NS_TTL) -> bytes:
    rdata = encode_name(host)
    return rr_header(name, 2, 1, ttl, len(rdata)) + rdata  # TYPE=NS


def rr_soa(zone: str, mname: str, rname: str, ttl=SOA_TTL) -> bytes:
    rdata = (
        encode_name(mname) +
        encode_name(rname) +
        struct.pack(">IIIII", SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM)
    )
    return rr_header(zone, 6, 1, ttl, len(rdata)) + rdata  # TYPE=SOA


def in_zone(name: str) -> bool:
    return name.endswith(ZONE)


def build_positive(qname: str, qtype: int):
    """
    Return (answers, authorities, additionals) for known names.
    """
    answers = b""
    auth = b""
    addl = b""

    if qname == ZONE and qtype in (2, 255):  # NS or ANY at apex
        for ns in NS_RECORDS:
            answers += rr_ns(ZONE, ns)
        # Glue A for in-bailiwick NS names
        for ns in NS_RECORDS:
            if ns in A_RECORDS:
                addl += rr_a(ns, A_RECORDS[ns])
        return answers, auth, addl

    if qname == ZONE and qtype in (6, 255):  # SOA or ANY at apex
        answers += rr_soa(ZONE, MNAME, RNAME)
        # Helpful additional glue for MNAME if in-bailiwick
        if MNAME in A_RECORDS:
            addl += rr_a(MNAME, A_RECORDS[MNAME])
        return answers, auth, addl

    if qtype in (1, 255):  # A or ANY
        if qname in A_RECORDS:
            answers += rr_a(qname, A_RECORDS[qname])
            return answers, auth, addl

    # No direct answer, but if it's in-zone and exists as a delegation (not in this minimal server)
    return b"", b"", b""


def build_nxdomain():
    """Authority section with SOA for NXDOMAIN."""
    return rr_soa(ZONE, MNAME, RNAME), b""


def build_response(data):
    # Header
    if len(data) < 12:
        raise ValueError("Truncated header")
    tid = data[:2]
    req_flags = data[2:4]
    qdcount = struct.unpack(">H", data[4:6])[0]

    if qdcount != 1:
        # We only handle single-question queries
        flags = build_flags(req_flags, rcode=1)  # FORMERR
        return tid + flags + b"\x00\x00\x00\x00\x00\x00\x00\x00"

    qname, qtype, qclass, q_end = parse_question(data)
    question = data[12:q_end]

    answers = b""
    authorities = b""
    additionals = b""
    rcode = 0

    if qclass != 1:  # not IN class
        # Not implemented for other classes -> NOERROR, no answers
        pass
    else:
        ans, auth, addl = build_positive(qname, qtype)
        if ans:
            answers = ans
            authorities = auth
            additionals = addl
        else:
            # Unknown name (if in our zone) -> NXDOMAIN. If out of zone -> NOERROR/empty.
            if in_zone(qname):
                authorities, additionals = build_nxdomain()
                rcode = 3  # NXDOMAIN

    flags = build_flags(req_flags, rcode)

    header = (
        tid + flags +
        struct.pack(">H", 1) +                     # QDCOUNT
        struct.pack(">H", len(split_rrs(answers))) +     # ANCOUNT
        struct.pack(">H", len(split_rrs(authorities))) + # NSCOUNT
        struct.pack(">H", len(split_rrs(additionals)))   # ARCOUNT
    )
    return header + question + answers + authorities + additionals


def split_rrs(rr_blob: bytes):
    """
    Utility to count RRs in a blob by walking RDATA lengths.
    (We already build RRs atomically; here we only need counts for header.)
    We’ll parse minimally: walk the wire to count names + fixed headers.
    """
    # This function is intentionally simple: we stored RRs concatenated.
    # For counting, keep a running index; parse NAME (labels), then fixed 10 bytes, then RDLENGTH.
    i = 0
    count = 0
    while i < len(rr_blob):
        # NAME
        while True:
            if i >= len(rr_blob):
                return []  # malformed -> 0
            ln = rr_blob[i]
            i += 1
            if ln == 0:
                break
            i += ln
        # TYPE(2)+CLASS(2)+TTL(4)+RDLENGTH(2) = 10 bytes
        if i + 10 > len(rr_blob):
            return []
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", rr_blob[i:i+10])
        i += 10
        i += rdlen
        count += 1
    return [None] * count


def start_dns_server(host="0.0.0.0", port=53):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    print(f"[AUTH DNS] {ZONE} on {host}:{port}")
    while True:
        data, addr = sock.recvfrom(1500)
        try:
            resp = build_response(data)
        except Exception as e:
            # FORMERR best-effort
            tid = data[:2] if len(data) >= 2 else b"\x00\x00"
            flags = build_flags(data[2:4] if len(data) >= 4 else b"\x00\x00", rcode=1)
            # Try to echo question if parsable
            try:
                _, _, _, q_end = parse_question(data)
                question = data[12:q_end]
                resp = tid + flags + b"\x00\x01\x00\x00\x00\x00\x00\x00" + question
            except Exception:
                resp = tid + flags + b"\x00\x00\x00\x00\x00\x00\x00\x00"
        sock.sendto(resp, addr)


if __name__ == "__main__":
    start_dns_server()