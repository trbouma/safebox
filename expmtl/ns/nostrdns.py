import asyncio
import json
import bech32  # for npub -> pubkey
from typing import List, Tuple, Optional
from pydantic_settings import BaseSettings

from monstr.client.client import Client, ClientPool
from monstr.event.event import Event


class Settings(BaseSettings):
    NOSTR_RELAYS: List = [
          "wss://relay.damus.io"

    ]
    KIND_DNS: int = 11111 # Custom event kind for “DNS record” (choose any free kind you prefer)


#       "wss://relay.damus.io"
#        "wss://nos.lol",
#        "wss://relay.primal.net",
#        "wss://relay.snort.social"



settings = Settings()

# ---------------------------
# Helpers
# ---------------------------
def npub_to_hex_pubkey(npub: str) -> Optional[str]:
    """
    Decode an npub (bech32) to 32-byte pubkey hex (lower-case).
    Returns None if invalid.
    """
    try:
        hrp, data = bech32.bech32_decode(npub)
        if hrp is None or hrp.lower() != "npub" or data is None:
            return None
        decoded = bech32.convertbits(data, 5, 8, False)
        if decoded is None or len(decoded) != 32:
            return None
        return bytes(decoded).hex()
    except Exception:
        return None

def _parse_dns_event(evt: Event, want_type: str, qname: Optional[str]) -> Optional[Tuple[str, str, int]]:
    """
    Try to parse a DNS record from a Nostr event.

    - want_type: "A", "TXT", etc.
    - qname: optional FQDN filter; if provided and event has a 'name', it must match.

    Returns (rtype, value, ttl) or None.
    """
    # First try JSON content
    print("we got events!")
    try:
        data = json.loads(evt.content or "{}")
        rtype = str(data.get("type", "")).upper()
        value = str(data.get("value", ""))
        ttl = int(data.get("ttl", 300))
        name = data.get("name")  # may be None or a fqdn

        if rtype and value and rtype == want_type:
            if qname and name and name.rstrip(".") + "." != qname:
                return None
            return (rtype, value, ttl)
    except Exception:
        pass

    # Fallback to tags
    try:
        tagmap = {}
        for t in evt.tags or []:
            if isinstance(t, list) and t:
                k = t[0]
                vs = t[1:]
                if k not in tagmap:
                    tagmap[k] = []
                tagmap[k].extend(vs)

        rtype = (tagmap.get("t", [""])[0] or "").upper()
        value = tagmap.get("v", [""])[0] if "v" in tagmap else ""
        ttl_s = tagmap.get("ttl", ["300"])[0] if "ttl" in tagmap else "300"
        name = tagmap.get("name", [None])[0] if "name" in tagmap else None

        if rtype and value and rtype == want_type:
            if qname and name and name.rstrip(".") + "." != qname:
                return None
            ttl = int(ttl_s)
            return (rtype, value, ttl)
    except Exception:
        pass

    return None

# Map wire qtype -> RR type string
_QTYPE_TO_STR = {
    1: "A",
    16: "TXT",
    28: "AAAA",
    255: "ANY",
}

_NPUB_LOOKUP_DEADLINE = 2.00  # seconds

async def _npub_a_first_with_timeout(npub: str, qtype: int):
    try:
        return await asyncio.wait_for(lookup_npub_a_first(npub, qtype), timeout=_NPUB_LOOKUP_DEADLINE)
    except Exception:
        return ([], [])


async def _npub_fetch_all_with_timeout(npub: str):
    """
    Get ALL tuples for an npub (using qtype=255/ANY) with a strict timeout.
    Returns a list of (rtype, value, ttl).
    """
    try:
        # Reuse your existing function but force ANY so we don’t miss data
        return await asyncio.wait_for(lookup_npub_records_tuples(npub, 255),
                                      timeout=_NPUB_LOOKUP_DEADLINE)
    except Exception as e:
        print(f"[NPUB] ANY fetch failed/timed out for {npub}: {e}")
        return []
    
async def lookup_npub_a_first(npub: str, want_qtype: int):
    """
    One-shot query to Nostr; parse all records; return:
        (a_recs, wanted_recs)
    where each is a list of (rtype, value, ttl).
    """
    print(f"[A-FIRST] npub={npub} want_qtype={want_qtype}")
    npub_hex = npub_to_hex_pubkey(npub)

    FILTER = [{
        'limit': 64,
        'authors': [npub_hex],
        'kinds': [settings.KIND_DNS]
    }]

    wanted_str = _QTYPE_TO_STR.get(want_qtype, None)

    a_recs: list[tuple[str, str, int]] = []
    wanted_recs: list[tuple[str, str, int]] = []

    try:
        async with ClientPool(settings.NOSTR_RELAYS) as c:
            events = await c.query(FILTER)
    except Exception as e:
        print(f"[ERR] Nostr query failed: {e}")
        events = []

    print(f"[A-FIRST] events retrieved: {len(events)}")

    # Parse all events once
    parsed: list[dict] = []
    for each in events:
        try:
            parsed.extend(parse_into_dns_records(each.tags) or [])
        except Exception as e:
            print(f"[ERR] parse tags: {e}")

    # Collect A first
    for rec in parsed:
        try:
            rtype = str(rec.get("type", "")).upper()
            val = rec.get("value")
            ttl = int(rec.get("ttl", 300))
            if not (rtype and val):
                continue
            if rtype == "A":
                a_recs.append((rtype, str(val), ttl))
        except Exception as e:
            print(f"[ERR] parse rec(A): {e}")

    # Then collect the specifically requested type (unless it's A)
    if want_qtype == 1:
        wanted_recs = list(a_recs)  # same list for convenience
    else:
        for rec in parsed:
            try:
                rtype = str(rec.get("type", "")).upper()
                val = rec.get("value")
                ttl = int(rec.get("ttl", 300))
                if not (rtype and val):
                    continue
                if wanted_str == "ANY":
                    wanted_recs.append((rtype, str(val), ttl))
                elif rtype == wanted_str:
                    wanted_recs.append((rtype, str(val), ttl))
            except Exception as e:
                print(f"[ERR] parse rec(wanted): {e}")

    # Optional defaults (so you can still answer deterministically)
    if not a_recs:
        # comment out if you want “pure” NODATA instead of a fallback A
        # a_recs = [("A", "100.100.100.101", 60)]
        pass

    if not wanted_recs and wanted_str in ("TXT", "ANY"):
        # small example TXT default; comment out if you prefer NODATA
        # wanted_recs = [("TXT", f"npub={npub}", 60)]
        pass

    return a_recs, wanted_recs

# ---------------------------
# Async fetch (one-shot)
# ---------------------------
async def _nostr_fetch_for_npub(
    npub_hex: str,
    want_type: str,
    qname: Optional[str],
    timeout: float = 1.5
) -> List[Tuple[str, str, int]]:
    """
    Connects to relays, subscribes to KIND_DNS events authored by npub_hex,
    gathers for `timeout` seconds, returns a list of (rtype, value, ttl).
    """
    results: List[Tuple[str, str, int]] = []

    print(f"fetch for {npub_hex} using {settings.KIND_DNS}")
    # Simple handler that collects matching events
    def handler(evt: Event, *_args, **_kwargs):
        print(f"evt {evt} {settings.KIND_DNS}")
        if evt.kind != settings.KIND_DNS:
            return
        # filter by author
        if getattr(evt, "pub_key", None) != npub_hex:
            return
        parsed = _parse_dns_event(evt, want_type=want_type, qname=qname)
        if parsed:
            results.append(parsed)

    # Create clients for each relay
    clients = [Client(url) for url in settings.NOSTR_RELAYS]
    run_tasks = []
    try:
        # Start all clients
        for c in clients:
            run_tasks.append(asyncio.create_task(c.run()))

        # Wait for connections briefly
        for c in clients:
            try:
                await c.wait_connect(timeout=timeout / 2)
            except Exception:
                # Non-fatal: some relays may be slow/offline
                pass

        # Subscribe: authors + kinds (NIP-01 filter)
        filters = {
            "authors": [npub_hex],
            "kinds": [settings.KIND_DNS],
            "limit": 64
        }
        for c in clients:
            c.subscribe(handlers=handler, filters=filters)

        # Allow some time for events to arrive
        await asyncio.sleep(timeout)

    finally:
        # Close all clients
        for c in clients:
            try:
                await c.end()
            except Exception:
                pass
        # Stop tasks
        for t in run_tasks:
            try:
                t.cancel()
            except Exception:
                pass

    return results

# ---------------------------
# Sync wrapper (drop-in)
# ---------------------------
def lookup_npub_record_via_monstr(npub: str, qtype: int, qname: Optional[str] = None, timeout: float = 1.5):
    """
    Look up DNS records for a detected npub via Nostr (monstr).
    - npub: bech32 npub (leftmost label you detected)
    - qtype: numeric DNS type (1=A, 16=TXT, 255=ANY)
    - qname: optional FQDN string to constrain results (e.g., "<npub>.example.com.")
    Returns: list of (rtype, value, ttl)
    """
    # Map qtype to text
    qtype_map = {1: "A", 16: "TXT", 255: "ANY"}
    want = qtype_map.get(qtype)
    if want is None:
        # For simplicity: only A/TXT/ANY in this stub; extend as desired.
        return []

    # Decode npub -> author pubkey hex
    pub_hex = npub_to_hex_pubkey(npub)
    if not pub_hex:
        return []

    # ANY: fetch both A and TXT
    wanted_types = ["A", "TXT"] if want == "ANY" else [want]

    out: List[Tuple[str, str, int]] = []
    for want_type in wanted_types:
        try:
            # If we're already inside an event loop, use it; else, create one
            try:
                loop = asyncio.get_running_loop()
                coro = _nostr_fetch_for_npub(pub_hex, want_type, qname, timeout)
                found = loop.run_until_complete(coro)  # will raise if loop is running
            except RuntimeError:
                # No running loop — create a new one
                found = asyncio.run(_nostr_fetch_for_npub(pub_hex, want_type, qname, timeout))
        except Exception:
            # Fallback: create a dedicated loop
            loop = asyncio.new_event_loop()
            try:
                found = loop.run_until_complete(_nostr_fetch_for_npub(pub_hex, want_type, qname, timeout))
            finally:
                loop.close()

        out.extend(found)

    return out

async def lookup_npub_records(npub: str, qtype: int):
    """
    Stub: lookup a DNS record for a given npub using a Nostr relay.

    Args:
        npub (str): The detected npub (leftmost label).
        qtype (int): DNS query type (1=A, 16=TXT, 255=ANY, etc.)

    Returns:
        list of (rtype, value, ttl) tuples, or empty list if not found.
    """

    """
        DNS Query: npub1abc.nostr (A record)
        ↓
        1. Parse domain → extract npub → convert to pubkey
    ↓
        2. Query Nostr relays for kind 11111 by pubkey
    ↓
        3. Parse record tags, filter by DNS type and name
    ↓
        4. If certificate records found, fetch kind 30003 for TLD
    ↓
        5. Validate and install certificate to trust store
    ↓
        6. Generate DNS response with proper records and TTL
    ↓
        7. Send DNS response
    """
    # --- for now, just stub behavior ---
    print(f"[STUB] Would query Nostr relay for npub={npub}, qtype={qtype}")
    npub_hex = npub_to_hex_pubkey(npub)
   

    FILTER = [{
                'limit': 64, 
                'authors'  :  [npub_hex],              
                'kinds': [settings.KIND_DNS]               
                
                }]
    
    print(f"npub hex {npub_hex} {settings.NOSTR_RELAYS} {FILTER}")

    async with ClientPool(settings.NOSTR_RELAYS) as c:  
            events = await c.query(FILTER)  

    print(f"records retrieved: {len(events)} ")
    for each in events:
        records = parse_into_dns_records(each.tags)
        return records


    # Example static behavior for testing:
    if qtype in (1, 255):  # A
        return [("A", "100.100.100.101", 60)]
    if qtype in (16, 255):  # TXT
        return [("TXT", f"npub={npub}", 60)]

    # return []

async def lookup_npub_records_tuples(npub: str, qtype: int):
    """
    Lookup a DNS record for a given npub using a Nostr relay.

    Args:
        npub (str): bech32 npub (leftmost label).
        qtype (int): DNS query type (1=A, 16=TXT, 255=ANY).

    Returns:
        list of (rtype, value, ttl) tuples of the requested type.
    """
    print(f"[STUB] Would query Nostr relay for npub={npub}, qtype={qtype}")
    npub_hex = npub_to_hex_pubkey(npub)

    FILTER = [{
        'limit': 64,
        'authors': [npub_hex],
        'kinds': [settings.KIND_DNS]
    }]
    print(f"npub hex {npub_hex} {settings.NOSTR_RELAYS} {FILTER}")

    tuples: list[tuple[str, str, int]] = []

    async with ClientPool(settings.NOSTR_RELAYS) as c:
        events = await c.query(FILTER)

    print(f"records retrieved: {len(events)} ")
    for each in events:
        dict_records = parse_into_dns_records(each.tags)
        for rec in dict_records:
            rtype = rec.get("type", "").upper()
            val = rec.get("value")
            ttl = int(rec.get("ttl", 300))
            if not (rtype and val):
                continue

            # Only include requested type
            if qtype == 1 and rtype == "A":
                tuples.append((rtype, val, ttl))
            elif qtype == 16 and rtype == "TXT":
                tuples.append((rtype, val, ttl))
            elif qtype == 255:  # ANY
                tuples.append((rtype, val, ttl))

    # If nothing found, you can fall back to static defaults
    if not tuples:
        if qtype in (1, 255):  # A
            return [("A", "100.100.100.101", 60)]
        if qtype in (16, 255):  # TXT
            return [("TXT", f"npub={npub}", 60)]

    return tuples




def parse_into_dns_records(raw_records):
    """
    Parse a list of flat DNS record lists into structured records.
    
    Each input row is expected to look like:
      ["record", TYPE, NAME, VALUE, ... , TTL]
    
    Returns:
        list of dicts with keys: type, name, value, ttl
    """
    records = []
    for row in raw_records:
        if not row or row[0] != "record":
            continue  # skip non-record rows

        rtype = row[1].upper()
        name = row[2]
        value = row[3]
        ttl = int(row[-1]) if row[-1].isdigit() else 300

        records.append({
            "type": rtype,
            "name": name,
            "value": value,
            "ttl": ttl
        })
    return records



