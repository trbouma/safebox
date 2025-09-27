import socket
import struct

# Simple DNS records (hostname -> IPv4 address)
DNS_RECORDS = {
    "example.com.": "93.184.216.34",
    "test.local.": "127.0.0.1",
    "booga.joy.": "192.168.2.12",
}

def parse_question(data):
    """
    Returns (qname, qtype, qclass, q_end_index)
    q_end_index is the index just after QCLASS
    """
    i = 12  # start of QNAME
    labels = []
    while True:
        if i >= len(data):
            raise ValueError("Malformed DNS packet (QNAME overrun)")
        length = data[i]
        if length == 0:
            i += 1  # move past the zero-length label
            break
        i += 1
        if i + length > len(data):
            raise ValueError("Malformed DNS packet (label overrun)")
        labels.append(data[i:i+length].decode("utf-8"))
        i += length

    if i + 4 > len(data):
        raise ValueError("Malformed DNS packet (missing QTYPE/QCLASS)")

    qtype, qclass = struct.unpack(">HH", data[i:i+4])
    qname = ".".join(labels) + "."
    q_end = i + 4
    return qname, qtype, qclass, q_end

def build_flags(request_flags, rcode=0):
    """
    Build response flags:
    - QR = 1 (response)
    - AA = 1 (authoritative)
    - TC = 0
    - RD = mirror from request
    - RA = 0 (no recursion available)
    - RCODE as provided (default NOERROR=0)
    """
    # Request flags are 16-bit
    rf = struct.unpack(">H", request_flags)[0]
    rd = rf & 0x0100  # RD bit

    flags = 0x8000      # QR = 1 (response)
    flags |= 0x0400     # AA = 1
    flags |= rd         # mirror RD
    flags |= (rcode & 0xF)  # RCODE

    return struct.pack(">H", flags)

def build_response(data):
    # Header fields from request
    tid = data[:2]
    req_flags = data[2:4]
    qdcount = data[4:6]

    # Parse question exactly
    qname, qtype, qclass, q_end = parse_question(data)
    question = data[12:q_end]

    # Default counts
    ancount = 0
    nscount = 0
    arcount = 0

    # Prepare answer if we have an A record and class IN
    answers = b""
    if qtype == 1 and qclass == 1 and qname in DNS_RECORDS:
        ip_bytes = socket.inet_aton(DNS_RECORDS[qname])
        # Name as a pointer to the question name (offset 12 => 0xC00C)
        ans = b"\xc0\x0c"                             # NAME (pointer)
        ans += struct.pack(">HHI", 1, 1, 60)          # TYPE=A, CLASS=IN, TTL=60
        ans += struct.pack(">H", len(ip_bytes)) + ip_bytes  # RDLENGTH + RDATA
        answers += ans
        ancount = 1

    # Build flags (authoritative, no recursion available)
    flags = build_flags(req_flags, rcode=0)

    # Header: ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
    header = (
        tid
        + flags
        + qdcount
        + struct.pack(">H", ancount)
        + struct.pack(">H", nscount)
        + struct.pack(">H", arcount)
    )

    # Response is header + original (exact) Question + Answer(s)
    return header + question + answers

def start_dns_server(host="0.0.0.0", port=53):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    print(f"DNS server listening on {host}:{port}")

    while True:
        data, addr = sock.recvfrom(512)  # typical UDP DNS limit
        try:
            resp = build_response(data)
        except Exception as e:
            # On parse error, reply with FORMERR (RCODE=1)
            tid = data[:2] if len(data) >= 2 else b"\x00\x00"
            req_flags = data[2:4] if len(data) >= 4 else b"\x00\x00"
            flags = build_flags(req_flags, rcode=1)
            # QDCOUNT etc. zeroed
            header = tid + flags + b"\x00\x01" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"
            # Best-effort echo of minimal question if we can parse; otherwise none
            try:
                _, _, _, q_end = parse_question(data)
                question = data[12:q_end]
            except Exception:
                question = b""
            resp = header + question
        sock.sendto(resp, addr)

if __name__ == "__main__":
    start_dns_server()
