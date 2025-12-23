#!/usr/bin/env python3
import socket, threading
import struct
import logging
from monstr.encrypt import Keys
import bech32
import asyncio

import signal
import sys

from nostrdns import npub_to_hex_pubkey, lookup_npub_records, lookup_npub_records_tuples, Settings, lookup_npub_a_first, _npub_a_first_with_timeout, _npub_fetch_all_with_timeout
import urllib.request





def get_public_ip() -> str:
    try:
        with urllib.request.urlopen("https://api.ipify.org") as resp:
            return resp.read().decode().strip()
    except Exception:
        return "127.0.0.1"  # fallback

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
ZONE   = "npub.openproof.org."
MNAME  = "ns1.npub.openproof.org."           # primary nameserver
RNAME  = "hostmaster.npub.openproof.org."    # admin email with '.' instead of '@'
SERIAL = 2025092701                     # bump when you change zone data
REFRESH = 3600
RETRY   = 600
EXPIRE  = 604800
MINIMUM = 3600
SOA_TTL = 3600


NS    = ["ns1.npub.openproof.org."]          # you can add ns2 later
GLUE = {"ns1.npub.openproof.org.": get_public_ip()}


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

# ---- multi-zone config ----
ZONES = {
    "openproof.org.": {
        "ns": ["ns1.openproof.org."],
        "glue_a": {"ns1.openproof.org.": "15.235.3.226"},
        "soa": {
            "mname": "ns1.openproof.org.",
            "rname": "hostmaster.openproof.org.",
            "serial": 2025092801,
            "refresh": 3600, "retry": 600, "expire": 604800, "minimum": 3600, "ttl": 3600
        },
    },
    "npub.openproof.org.": {
        "ns": ["ns1.openproof.org."],       # reuse same server
        "glue_a": {},                       # parent provides glue for ns1.openproof.org
        "soa": {
            "mname": "ns1.openproof.org.",
            "rname": "hostmaster.openproof.org.",
            "serial": 2025092801,
            "refresh": 3600, "retry": 600, "expire": 604800, "minimum": 3600, "ttl": 3600
        },
    },
}

def find_zone(qname: str) -> str | None:
    """Return the longest matching zone apex for qname."""
    q = qname.rstrip(".") + "."
    best = None
    for zone in ZONES.keys():
        if q.endswith(zone) and (best is None or len(zone) > len(best)):
            best = zone
    return best



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

def rr_ns(name: str, host: str, ttl: int = 3600) -> bytes:
    rdata = encode_name(host)
    return encode_name(name) + struct.pack(">HHI", 2, 1, ttl) + struct.pack(">H", len(rdata)) + rdata


def rr_header(name, rtype, ttl, rdata):
    return encode_name(name) + struct.pack(">HHI", rtype, 1, ttl) + struct.pack(">H", len(rdata)) + rdata

def rr_a(name, ip, ttl):    return rr_header(name, 1, ttl, socket.inet_aton(ip))

def rr_aaaa(name: str, ipv6: str, ttl: int) -> bytes:
    """
    Build a DNS AAAA resource record.

    Args:
        name (str): FQDN ending with a dot, e.g. "host.example.com."
        ipv6 (str): IPv6 address string, e.g. "2001:db8::1"
        ttl (int): TTL in seconds

    Returns:
        bytes: wire-format DNS AAAA RR
    """
    # compress address into 16 bytes
    try:
        ipv6_bytes = socket.inet_pton(socket.AF_INET6, ipv6)
    except OSError:
        raise ValueError(f"Invalid IPv6 address: {ipv6}")

    rtype = 28      # AAAA
    rclass = 1      # IN
    rdlength = len(ipv6_bytes)

    return (
        encode_name(name)
        + struct.pack(">HHI", rtype, rclass, ttl)
        + struct.pack(">H", rdlength)
        + ipv6_bytes
    )

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

OVERRIDES = {
    "npub1h9taws9gujwja2weyxzhawfahwqljcm3cs7wjv5vv70dvtx637wsl8rhx0.npub.openproof.org.": {
        "A": ("172.105.26.76", 300),   # <— your Nginx public IPv4
        # only add AAAA if your Nginx listens on 80 over IPv6:
        # "AAAA": ("2001:db8::1", 300),
    }
}

def normalize_name(name: str) -> str:
    n = (name or "").rstrip(".").lower()
    return n + "."

def rr_opt(udp_payload=1232) -> bytes:
    # NAME=root(0), TYPE=41, CLASS=udp_payload, TTL=0, RDLEN=0
    return b"\x00" + struct.pack(">H H I H", 41, udp_payload, 0, 0)

def negative_nodata(zone: str, req_flags: bytes, tid: bytes, question: bytes, add_opt=True, ra=False) -> bytes:
    """Return NOERROR with SOA in AUTHORITY (RFC 2308), 0 answers."""
    s = ZONES[zone]["soa"]
    auth = rr_soa(zone, s["mname"], s["rname"], s["serial"], s["refresh"],
                  s["retry"], s["expire"], s["minimum"], s["ttl"])
    flags = build_flags(req_flags, rcode=0, aa=True, ra=ra)
    ar = rr_opt() if add_opt else b""
    header = tid + flags + struct.pack(">HHHH", 1, 0, 1, 1 if ar else 0)
    return header + question + auth + ar

def positive_answer(tid, req_flags, question, *, answers=b"", authorities=b"", additionals=b"", aa=True, ra=False, add_opt=True):
    flags = build_flags(req_flags, rcode=0, aa=aa, ra=ra)
    ar = additionals + (rr_opt() if add_opt else b"")
    header = tid + flags + struct.pack(">HHHH", 1, count_rrs(answers), count_rrs(authorities), count_rrs(ar))
    return header + question + answers + authorities + ar

def nodata(zone: str, tid, req_flags, question, *, add_opt=True, ra=False):
    """NOERROR/NODATA with SOA in AUTHORITY (RFC 2308)"""
    s = ZONES[zone]["soa"]
    auth = rr_soa(zone, s["mname"], s["rname"], s["serial"], s["refresh"], s["retry"], s["expire"], s["minimum"], s["ttl"])
    flags = build_flags(req_flags, rcode=0, aa=True, ra=ra)
    ar = rr_opt() if add_opt else b""
    header = tid + flags + struct.pack(">HHHH", 1, 0, 1, 1 if ar else 0)
    return header + question + auth + ar

def zone_ns_authority(zone: str, ttl=3600) -> bytes:
    """Authoritative NS set for AUTHORITY section (helps some resolvers)."""
    return b"".join(rr_ns(zone, ns) for ns in ZONES[zone]["ns"])

# -------------------------------
# Build response
# -------------------------------
def build_response(req: bytes) -> bytes:
    tid, req_flags = req[:2], req[2:4]
    qname, qtype, qclass, qend = parse_question(req)
    question = req[12:qend]

    RA = False           # authoritative server: recursion not available
    add_opt = True       # always add EDNS0 OPT to be friendly with public resolvers
    fqdn = normalize_name(qname)

    # ---- Hard overrides (for issuance or special hosts) ----
    recs = OVERRIDES.get(fqdn)
    if recs:
        answers = b""

        # Add any overridden types we *do* have
        if qtype in (1, 255) and "A" in recs:
            answers += rr_a(fqdn, recs["A"][0], int(recs["A"][1]))
        if qtype in (28, 255) and "AAAA" in recs:
            answers += rr_aaaa(fqdn, recs["AAAA"][0], int(recs["AAAA"][1]))
        if qtype in (16, 255) and "TXT" in recs:
            answers += rr_txt(fqdn, str(recs["TXT"][0]), int(recs["TXT"][1]))

        # If AAAA was requested but not overridden -> clean NOERROR/NODATA
        if qtype == 28 and "AAAA" not in recs:
            zone = find_zone(fqdn)
            if zone:
                return negative_nodata(zone, req_flags, tid, question, add_opt, ra=RA)

        # If we actually built some answers from overrides, return them now
        if answers:
            return positive_answer(tid, req_flags, question, answers=answers, aa=True, ra=RA, add_opt=add_opt)

    # Otherwise: DO NOT return NODATA here.
    # Fall through to normal zone/npub handling so TXT (or other) can be resolved dynamically.

    # Only IN class
    if qclass != 1:
        flags = build_flags(req_flags, rcode=4, aa=True, ra=RA)  # NOTIMP for non-IN
        header = tid + flags + struct.pack(">HHHH", 1, 0, 0, 1 if add_opt else 0)
        return header + question + (rr_opt() if add_opt else b"")

    zone = find_zone(fqdn)
    if zone:
        z = ZONES[zone]

        # ---- Apex SOA ----
        if fqdn == zone and qtype in (6, 255):  # SOA or ANY
            s = z["soa"]
            ans = rr_soa(zone, s["mname"], s["rname"], s["serial"], s["refresh"], s["retry"], s["expire"], s["minimum"], s["ttl"])
            return positive_answer(tid, req_flags, question, answers=ans, aa=True, ra=RA, add_opt=add_opt)

        # ---- Apex NS (+ in-bailiwick glue A in ADDITIONAL) ----
        if fqdn == zone and qtype in (2, 255):  # NS or ANY
            answers = b"".join(rr_ns(zone, ns) for ns in z["ns"])
            glue_map = z.get("glue_a", {})
            additionals = b"".join(rr_a(h, ip, 3600) for h, ip in glue_map.items() if h in z["ns"])
            return positive_answer(tid, req_flags, question, answers=answers, additionals=additionals, aa=True, ra=RA, add_opt=add_opt)

        # ---- In-zone glue host A (e.g., ns1.<zone>.) ----
        if qtype in (1, 255) and fqdn in z.get("glue_a", {}):
            ans = rr_a(fqdn, z["glue_a"][fqdn], 3600)
            # include zone NS in AUTHORITY for non-apex positives
            auth = zone_ns_authority(zone)
            return positive_answer(tid, req_flags, question, answers=ans, authorities=auth, aa=True, ra=RA, add_opt=add_opt)

        # ---- npub leaf handling (no overrides needed) ----
        leftmost = fqdn.split(".", 1)[0]
        if is_valid_npub(leftmost):
            # A-first lookup (single relay walk, then filter by qtype)
            try:
                try:
                    a_recs, wanted_recs = asyncio.run(lookup_npub_a_first(leftmost, qtype))
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    try:
                        a_recs, wanted_recs = loop.run_until_complete(lookup_npub_a_first(leftmost, qtype))
                    finally:
                        loop.close()
            except Exception as e:
                print(f"[ERR] npub lookup: {e}")
                a_recs, wanted_recs = [], []

            answers = b""

            # Build only what was requested (but always tried to fetch A first)
            if qtype in (1, 255):    # A
                for rtype, val, ttl in a_recs:
                    if rtype == "A":
                        answers += rr_a(fqdn, str(val), int(ttl))
            if qtype in (16, 255):   # TXT
                for rtype, val, ttl in wanted_recs:
                    if rtype == "TXT":
                        answers += rr_txt(fqdn, str(val), int(ttl))
            if qtype in (28, 255):   # AAAA
                for rtype, val, ttl in wanted_recs:
                    if rtype == "AAAA":
                        answers += rr_aaaa(fqdn, str(val), int(ttl))

            if answers:
                # include zone NS in AUTHORITY for non-apex answers
                auth = zone_ns_authority(zone)
                return positive_answer(tid, req_flags, question, answers=answers, authorities=auth, aa=True, ra=RA, add_opt=add_opt)

            # Clean negatives (authoritative) — never SERVFAIL for in-zone names:
            # If AAAA was asked and none exists, or TXT/A missing → NOERROR/NODATA + SOA
            return nodata(zone, tid, req_flags, question, add_opt=add_opt, ra=RA)

        # ---- Non-npub name under our zone → authoritative NODATA ----
        return nodata(zone, tid, req_flags, question, add_opt=add_opt, ra=RA)

    # Outside our zones → REFUSED (pure authoritative; no forwarding)
    flags = build_flags(req_flags, rcode=5, aa=False, ra=RA)
    header = tid + flags + struct.pack(">HHHH", 1, 0, 0, 1 if add_opt else 0)
    return header + question + (rr_opt() if add_opt else b"")


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

def handle_tcp_client(conn, addr):
    try:
        # TCP DNS uses a 2-byte length prefix
        l = conn.recv(2)
        if len(l) < 2:
            return
        ln = int.from_bytes(l, "big")
        req = conn.recv(ln)
        resp = build_response(req)
        conn.send(len(resp).to_bytes(2, "big") + resp)
    finally:
        conn.close()

def start_dns_tcp(host="0.0.0.0", port=53):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(100)
    print(f"[DNS] listening on {host}:{port} (TCP)")
    try:
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_tcp_client, args=(conn, addr), daemon=True).start()
    finally:
        s.close()

# -------------------------------
# UDP server
# -------------------------------
def start_dns_server(host="0.0.0.0", port=53):
    settings = Settings()
    print(settings)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # allow quick restart
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except Exception:
        pass
    sock.bind((host, port))
    # allow loop to wake up and handle shutdown
    sock.settimeout(1.0)

    print(f"[DNS] listening on {host}:{port} (UDP)")

    # Make SIGTERM behave like Ctrl-C (useful for docker stop)
    def _term_handler(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, _term_handler)

    

    try:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue  # check again (and allows Ctrl-C to be processed)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                # ignore transient recv errors and keep serving
                # print(f"recv error: {e}")
                continue

            try:
                resp = build_response(data)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                # FORMERR fallback
                tid = data[:2] if len(data) >= 2 else b"\x00\x00"
                flags = build_flags(data[2:4] if len(data) >= 4 else b"\x00\x00", rcode=1, aa=False, ra=True)
                resp = tid + flags + b"\x00\x00\x00\x00\x00\x00\x00\x00"

            try:
                sock.sendto(resp, addr)
            except Exception:
                pass

    except KeyboardInterrupt:
        print("\n[DNS] shutting down...")
    finally:
        try:
            sock.close()
        except Exception:
            pass
        print("[DNS] socket closed")

if __name__ == "__main__":
    threading.Thread(target=start_dns_tcp, daemon=True).start()
    start_dns_server()  # your UDP loop
