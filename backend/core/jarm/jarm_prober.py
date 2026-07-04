"""
Garudatva v3 — JARM Active Prober
Sends 10 crafted TLS ClientHello probes to fingerprint C2 server TLS config.
JARM identifies C2 infrastructure even when IP addresses rotate daily.
Runs on Workstation B only (requires outbound internet).

This is a faithful, byte-for-byte port of the official Salesforce JARM
v1.0 algorithm (github.com/salesforce/jarm, BSD-3-Clause, John Althouse /
Andrew Smart / RJ Nunaly / Mike Brady; Python port by Caleb Yu) — the exact
packet construction, cipher/extension tables, and fuzzy-hash assembly are
reproduced unmodified so the resulting 62-char fingerprint matches real
public JARM databases (e.g. known Cobalt Strike / Metasploit hashes).
Only the transport layer (asyncio sockets instead of blocking sockets) and
surrounding module structure were adapted to fit this codebase.
"""

from __future__ import annotations

import asyncio
import codecs
import hashlib
import os
import random
import struct
from typing import Dict, List, Optional, Tuple

from config import settings
from utils.logger import get_logger

logger = get_logger(__name__)

JARM_TIMEOUT = settings.JARM_TIMEOUT  # seconds per probe

# ── GREASE (RFC 8701) ────────────────────────────────────────────────────────
_GREASE_VALUES = [
    b"\x0a\x0a", b"\x1a\x1a", b"\x2a\x2a", b"\x3a\x3a", b"\x4a\x4a", b"\x5a\x5a",
    b"\x6a\x6a", b"\x7a\x7a", b"\x8a\x8a", b"\x9a\x9a", b"\xaa\xaa", b"\xba\xba",
    b"\xca\xca", b"\xda\xda", b"\xea\xea", b"\xfa\xfa",
]


def _choose_grease() -> bytes:
    return random.choice(_GREASE_VALUES)


# ── The 10 JARM probe definitions ────────────────────────────────────────────
# Each tuple: (version, cipher_list, cipher_order, grease, alpn_mode,
#              supported_versions_mode, extension_order)
def _probe_definitions() -> List[dict]:
    return [
        {"version": "TLS_1.2", "ciphers": "ALL",   "order": "FORWARD",     "grease": False, "alpn": "APLN",      "support": "1.2_SUPPORT", "ext_order": "REVERSE"},
        {"version": "TLS_1.2", "ciphers": "ALL",   "order": "REVERSE",     "grease": False, "alpn": "APLN",      "support": "1.2_SUPPORT", "ext_order": "FORWARD"},
        {"version": "TLS_1.2", "ciphers": "ALL",   "order": "TOP_HALF",    "grease": False, "alpn": "APLN",      "support": "NO_SUPPORT",  "ext_order": "FORWARD"},
        {"version": "TLS_1.2", "ciphers": "ALL",   "order": "BOTTOM_HALF", "grease": False, "alpn": "RARE_APLN", "support": "NO_SUPPORT",  "ext_order": "FORWARD"},
        {"version": "TLS_1.2", "ciphers": "ALL",   "order": "MIDDLE_OUT",  "grease": True,  "alpn": "RARE_APLN", "support": "NO_SUPPORT",  "ext_order": "REVERSE"},
        {"version": "TLS_1.1", "ciphers": "ALL",   "order": "FORWARD",     "grease": False, "alpn": "APLN",      "support": "NO_SUPPORT",  "ext_order": "FORWARD"},
        {"version": "TLS_1.3", "ciphers": "ALL",   "order": "FORWARD",     "grease": False, "alpn": "APLN",      "support": "1.3_SUPPORT", "ext_order": "REVERSE"},
        {"version": "TLS_1.3", "ciphers": "ALL",   "order": "REVERSE",     "grease": False, "alpn": "APLN",      "support": "1.3_SUPPORT", "ext_order": "FORWARD"},
        {"version": "TLS_1.3", "ciphers": "NO1.3", "order": "FORWARD",     "grease": False, "alpn": "APLN",      "support": "1.3_SUPPORT", "ext_order": "FORWARD"},
        {"version": "TLS_1.3", "ciphers": "ALL",   "order": "MIDDLE_OUT",  "grease": True,  "alpn": "APLN",      "support": "1.3_SUPPORT", "ext_order": "REVERSE"},
    ]


# ── Cipher ordering ───────────────────────────────────────────────────────────

def _cipher_mung(items: list, request: str) -> list:
    """Reorder a list per JARM's FORWARD/REVERSE/TOP_HALF/BOTTOM_HALF/MIDDLE_OUT."""
    output: list = []
    n = len(items)
    if request == "REVERSE":
        output = items[::-1]
    elif request == "BOTTOM_HALF":
        output = items[n // 2 + 1:] if n % 2 == 1 else items[n // 2:]
    elif request == "TOP_HALF":
        if n % 2 == 1:
            output.append(items[n // 2])
        output += _cipher_mung(_cipher_mung(items, "REVERSE"), "BOTTOM_HALF")
    elif request == "MIDDLE_OUT":
        middle = n // 2
        if n % 2 == 1:
            output.append(items[middle])
            for i in range(1, middle + 1):
                output.append(items[middle + i])
                output.append(items[middle - i])
        else:
            for i in range(1, middle + 1):
                output.append(items[middle - 1 + i])
                output.append(items[middle - i])
    return output


_CIPHER_LIST_ALL = [
    b"\x00\x16", b"\x00\x33", b"\x00\x67", b"\xc0\x9e", b"\xc0\xa2", b"\x00\x9e",
    b"\x00\x39", b"\x00\x6b", b"\xc0\x9f", b"\xc0\xa3", b"\x00\x9f", b"\x00\x45",
    b"\x00\xbe", b"\x00\x88", b"\x00\xc4", b"\x00\x9a", b"\xc0\x08", b"\xc0\x09",
    b"\xc0\x23", b"\xc0\xac", b"\xc0\xae", b"\xc0\x2b", b"\xc0\x0a", b"\xc0\x24",
    b"\xc0\xad", b"\xc0\xaf", b"\xc0\x2c", b"\xc0\x72", b"\xc0\x73", b"\xcc\xa9",
    b"\x13\x02", b"\x13\x01", b"\xcc\x14", b"\xc0\x07", b"\xc0\x12", b"\xc0\x13",
    b"\xc0\x27", b"\xc0\x2f", b"\xc0\x14", b"\xc0\x28", b"\xc0\x30", b"\xc0\x60",
    b"\xc0\x61", b"\xc0\x76", b"\xc0\x77", b"\xcc\xa8", b"\x13\x05", b"\x13\x04",
    b"\x13\x03", b"\xcc\x13", b"\xc0\x11", b"\x00\x0a", b"\x00\x2f", b"\x00\x3c",
    b"\xc0\x9c", b"\xc0\xa0", b"\x00\x9c", b"\x00\x35", b"\x00\x3d", b"\xc0\x9d",
    b"\xc0\xa1", b"\x00\x9d", b"\x00\x41", b"\x00\xba", b"\x00\x84", b"\x00\xc0",
    b"\x00\x07", b"\x00\x04", b"\x00\x05",
]
_CIPHER_LIST_NO13 = [
    b"\x00\x16", b"\x00\x33", b"\x00\x67", b"\xc0\x9e", b"\xc0\xa2", b"\x00\x9e",
    b"\x00\x39", b"\x00\x6b", b"\xc0\x9f", b"\xc0\xa3", b"\x00\x9f", b"\x00\x45",
    b"\x00\xbe", b"\x00\x88", b"\x00\xc4", b"\x00\x9a", b"\xc0\x08", b"\xc0\x09",
    b"\xc0\x23", b"\xc0\xac", b"\xc0\xae", b"\xc0\x2b", b"\xc0\x0a", b"\xc0\x24",
    b"\xc0\xad", b"\xc0\xaf", b"\xc0\x2c", b"\xc0\x72", b"\xc0\x73", b"\xcc\xa9",
    b"\xcc\x14", b"\xc0\x07", b"\xc0\x12", b"\xc0\x13", b"\xc0\x27", b"\xc0\x2f",
    b"\xc0\x14", b"\xc0\x28", b"\xc0\x30", b"\xc0\x60", b"\xc0\x61", b"\xc0\x76",
    b"\xc0\x77", b"\xcc\xa8", b"\xcc\x13", b"\xc0\x11", b"\x00\x0a", b"\x00\x2f",
    b"\x00\x3c", b"\xc0\x9c", b"\xc0\xa0", b"\x00\x9c", b"\x00\x35", b"\x00\x3d",
    b"\xc0\x9d", b"\xc0\xa1", b"\x00\x9d", b"\x00\x41", b"\x00\xba", b"\x00\x84",
    b"\x00\xc0", b"\x00\x07", b"\x00\x04", b"\x00\x05",
]


def _get_ciphers(probe: dict) -> bytes:
    cipher_list = list(_CIPHER_LIST_ALL if probe["ciphers"] == "ALL" else _CIPHER_LIST_NO13)
    if probe["order"] != "FORWARD":
        cipher_list = _cipher_mung(cipher_list, probe["order"])
    if probe["grease"]:
        cipher_list.insert(0, _choose_grease())
    return b"".join(cipher_list)


# ── Extensions ────────────────────────────────────────────────────────────────

def _extension_server_name(host: str) -> bytes:
    ext = b"\x00\x00"
    host_bytes = host.encode()
    ext += struct.pack(">H", len(host_bytes) + 5)
    ext += struct.pack(">H", len(host_bytes) + 3)
    ext += b"\x00"
    ext += struct.pack(">H", len(host_bytes))
    ext += host_bytes
    return ext


_ALPN_ALL = [
    b"\x08\x68\x74\x74\x70\x2f\x30\x2e\x39",  # http/0.9
    b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x30",  # http/1.0
    b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x31",  # http/1.1
    b"\x06\x73\x70\x64\x79\x2f\x31",          # spdy/1
    b"\x06\x73\x70\x64\x79\x2f\x32",          # spdy/2
    b"\x06\x73\x70\x64\x79\x2f\x33",          # spdy/3
    b"\x02\x68\x32",                          # h2
    b"\x03\x68\x32\x63",                      # h2c
    b"\x02\x68\x71",                          # hq
]
_ALPN_RARE = [
    b"\x08\x68\x74\x74\x70\x2f\x30\x2e\x39",
    b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x30",
    b"\x06\x73\x70\x64\x79\x2f\x31",
    b"\x06\x73\x70\x64\x79\x2f\x32",
    b"\x06\x73\x70\x64\x79\x2f\x33",
    b"\x03\x68\x32\x63",
    b"\x02\x68\x71",
]


def _app_layer_proto_negotiation(probe: dict) -> bytes:
    ext = b"\x00\x10"
    alpns = list(_ALPN_RARE if probe["alpn"] == "RARE_APLN" else _ALPN_ALL)
    if probe["ext_order"] != "FORWARD":
        alpns = _cipher_mung(alpns, probe["ext_order"])
    all_alpns = b"".join(alpns)
    ext += struct.pack(">H", len(all_alpns) + 2)
    ext += struct.pack(">H", len(all_alpns))
    ext += all_alpns
    return ext


def _key_share(grease: bool) -> bytes:
    ext = b"\x00\x33"
    share_ext = _choose_grease() + b"\x00\x01\x00" if grease else b""
    share_ext += b"\x00\x1d"          # group: x25519
    share_ext += b"\x00\x20"          # key_exchange length: 32
    share_ext += os.urandom(32)
    ext += struct.pack(">H", len(share_ext) + 2)
    ext += struct.pack(">H", len(share_ext))
    ext += share_ext
    return ext


def _supported_versions(probe: dict, grease: bool) -> bytes:
    if probe["support"] == "1.2_SUPPORT":
        tls = [b"\x03\x01", b"\x03\x02", b"\x03\x03"]
    else:
        tls = [b"\x03\x01", b"\x03\x02", b"\x03\x03", b"\x03\x04"]
    if probe["ext_order"] != "FORWARD":
        tls = _cipher_mung(tls, probe["ext_order"])
    ext = b"\x00\x2b"
    versions = _choose_grease() if grease else b""
    versions += b"".join(tls)
    ext += struct.pack(">H", len(versions) + 1)
    ext += struct.pack(">B", len(versions))
    ext += versions
    return ext


def _get_extensions(probe: dict, host: str) -> bytes:
    all_extensions = b""
    grease = probe["grease"]
    if grease:
        all_extensions += _choose_grease() + b"\x00\x00"
    all_extensions += _extension_server_name(host)
    all_extensions += b"\x00\x17\x00\x00"                          # extended_master_secret
    all_extensions += b"\x00\x01\x00\x01\x01"                      # max_fragment_length
    all_extensions += b"\xff\x01\x00\x01\x00"                      # renegotiation_info
    all_extensions += b"\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19"  # supported_groups
    all_extensions += b"\x00\x0b\x00\x02\x01\x00"                  # ec_point_formats
    all_extensions += b"\x00\x23\x00\x00"                          # session_ticket
    all_extensions += _app_layer_proto_negotiation(probe)
    all_extensions += b"\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01"  # signature_algorithms
    all_extensions += _key_share(grease)
    all_extensions += b"\x00\x2d\x00\x02\x01\x01"                  # psk_key_exchange_modes
    if probe["version"] == "TLS_1.3" or probe["support"] == "1.2_SUPPORT":
        all_extensions += _supported_versions(probe, grease)
    return struct.pack(">H", len(all_extensions)) + all_extensions


# ── Packet assembly ───────────────────────────────────────────────────────────

_RECORD_VERSION = {"TLS_1.3": b"\x03\x01", "SSLv3": b"\x03\x00", "TLS_1": b"\x03\x01",
                    "TLS_1.1": b"\x03\x02", "TLS_1.2": b"\x03\x03"}
_HELLO_VERSION = {"TLS_1.3": b"\x03\x03", "SSLv3": b"\x03\x00", "TLS_1": b"\x03\x01",
                  "TLS_1.1": b"\x03\x02", "TLS_1.2": b"\x03\x03"}


def build_client_hello(probe: dict, host: str) -> bytes:
    """Build one raw JARM TLS ClientHello probe packet."""
    payload = b"\x16" + _RECORD_VERSION[probe["version"]]

    client_hello = _HELLO_VERSION[probe["version"]]
    client_hello += os.urandom(32)                       # random
    session_id = os.urandom(32)
    client_hello += struct.pack(">B", len(session_id)) + session_id

    ciphers = _get_ciphers(probe)
    client_hello += struct.pack(">H", len(ciphers)) + ciphers
    client_hello += b"\x01"    # compression methods length
    client_hello += b"\x00"    # null compression

    client_hello += _get_extensions(probe, host)

    handshake = b"\x01" + struct.pack(">I", len(client_hello))[1:] + client_hello
    payload += struct.pack(">H", len(handshake)) + handshake
    return payload


# ── Server Hello parsing ──────────────────────────────────────────────────────

def _find_extension(ext_type: bytes, types: List[bytes], values: List[bytes]) -> str:
    for t, v in zip(types, values):
        if t == ext_type:
            if ext_type == b"\x00\x10":  # ALPN — return ASCII protocol name
                return v[3:].decode(errors="replace")
            return v.hex()
    return ""


def _extract_extension_info(data: bytearray, counter: int, server_hello_length: int) -> str:
    try:
        if data[counter + 47] == 11:
            return "|"
        if data[counter + 50:counter + 53] == b"\x0e\xac\x0b" or data[82:85] == b"\x0f\xf0\x0b":
            return "|"
        if counter + 42 >= server_hello_length:
            return "|"
        count = 49 + counter
        length = int(codecs.encode(bytes(data[counter + 47:counter + 49]), "hex"), 16)
        maximum = length + (count - 1)
        types: List[bytes] = []
        values: List[bytes] = []
        while count < maximum:
            types.append(bytes(data[count:count + 2]))
            ext_length = int(codecs.encode(bytes(data[count + 2:count + 4]), "hex"), 16)
            if ext_length == 0:
                count += 4
                values.append(b"")
            else:
                values.append(bytes(data[count + 4:count + 4 + ext_length]))
                count += ext_length + 4
        result = str(_find_extension(b"\x00\x10", types, values)) + "|"
        result += "-".join(codecs.encode(t, "hex").decode("ascii") for t in types)
        return result
    except IndexError:
        return "|"


def read_server_hello(data: Optional[bytearray]) -> str:
    """Parse a raw Server Hello. Returns 'cipher|version|alpn|ext_types' or '|||'."""
    try:
        if data is None or len(data) < 6:
            return "|||"
        if data[0] == 21:                              # TLS alert — refused
            return "|||"
        if data[0] == 22 and data[5] == 2:              # handshake, server_hello
            server_hello_length = int.from_bytes(data[3:5], "big")
            counter = data[43]
            selected_cipher = data[counter + 44:counter + 46]
            version = data[9:11]
            jarm = codecs.encode(bytes(selected_cipher), "hex").decode("ascii")
            jarm += "|"
            jarm += codecs.encode(bytes(version), "hex").decode("ascii")
            jarm += "|"
            jarm += _extract_extension_info(data, counter, server_hello_length)
            return jarm
        return "|||"
    except Exception as e:
        logger.debug(f"Server Hello parse error: {e}")
        return "|||"


# ── Fuzzy hash assembly ───────────────────────────────────────────────────────

_CIPHER_INDEX = [
    b"\x00\x04", b"\x00\x05", b"\x00\x07", b"\x00\x0a", b"\x00\x16", b"\x00\x2f",
    b"\x00\x33", b"\x00\x35", b"\x00\x39", b"\x00\x3c", b"\x00\x3d", b"\x00\x41",
    b"\x00\x45", b"\x00\x67", b"\x00\x6b", b"\x00\x84", b"\x00\x88", b"\x00\x9a",
    b"\x00\x9c", b"\x00\x9d", b"\x00\x9e", b"\x00\x9f", b"\x00\xba", b"\x00\xbe",
    b"\x00\xc0", b"\x00\xc4", b"\xc0\x07", b"\xc0\x08", b"\xc0\x09", b"\xc0\x0a",
    b"\xc0\x11", b"\xc0\x12", b"\xc0\x13", b"\xc0\x14", b"\xc0\x23", b"\xc0\x24",
    b"\xc0\x27", b"\xc0\x28", b"\xc0\x2b", b"\xc0\x2c", b"\xc0\x2f", b"\xc0\x30",
    b"\xc0\x60", b"\xc0\x61", b"\xc0\x72", b"\xc0\x73", b"\xc0\x76", b"\xc0\x77",
    b"\xc0\x9c", b"\xc0\x9d", b"\xc0\x9e", b"\xc0\x9f", b"\xc0\xa0", b"\xc0\xa1",
    b"\xc0\xa2", b"\xc0\xa3", b"\xc0\xac", b"\xc0\xad", b"\xc0\xae", b"\xc0\xaf",
    b"\xcc\x13", b"\xcc\x14", b"\xcc\xa8", b"\xcc\xa9", b"\x13\x01", b"\x13\x02",
    b"\x13\x03", b"\x13\x04", b"\x13\x05",
]


def _cipher_bytes(cipher_hex: str) -> str:
    if cipher_hex == "":
        return "00"
    for i, b in enumerate(_CIPHER_INDEX, start=1):
        if cipher_hex == codecs.encode(b, "hex").decode("ascii"):
            hexvalue = hex(i)[2:]
            return hexvalue if len(hexvalue) >= 2 else "0" + hexvalue
    return "00"


def _version_byte(version_hex: str) -> str:
    if version_hex == "":
        return "0"
    options = "abcdef"
    count = int(version_hex[3:4])
    return options[count]


def compute_jarm_hash(probe_responses: List[str]) -> str:
    """
    Assemble the 62-char JARM fingerprint from 10 raw probe response strings
    (each 'cipher|version|alpn|ext_types', or '|||' for a refused/failed probe).
    """
    joined = ",".join(probe_responses)
    if joined == ",".join(["|||"] * 10):
        return "0" * 62

    fuzzy_hash = ""
    alpns_and_ext = ""
    for handshake in probe_responses:
        components = handshake.split("|")
        while len(components) < 4:
            components.append("")
        fuzzy_hash += _cipher_bytes(components[0])
        fuzzy_hash += _version_byte(components[1])
        alpns_and_ext += components[2]
        alpns_and_ext += components[3]

    sha256 = hashlib.sha256(alpns_and_ext.encode()).hexdigest()
    fuzzy_hash += sha256[:32]
    return fuzzy_hash


# ── Network I/O ───────────────────────────────────────────────────────────────

async def probe_single(host: str, port: int, probe: dict) -> str:
    """Send one JARM probe to host:port. Returns the raw parsed response string."""
    writer = None
    try:
        packet = build_client_hello(probe, host)
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=JARM_TIMEOUT,
        )
        writer.write(packet)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1484), timeout=JARM_TIMEOUT)
        return read_server_hello(bytearray(data) if data else None)
    except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
        return "|||"
    except Exception as e:
        logger.debug(f"JARM probe error {host}:{port}: {e}")
        return "|||"
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass


async def probe_host(host: str, port: int = 443) -> Dict:
    """Run all 10 JARM probes against a single host, sequentially (per spec:
    probes are not directly comparable if interleaved), and hash the result."""
    logger.info(f"JARM probing: {host}:{port}")
    responses: List[str] = []
    for i, probe in enumerate(_probe_definitions()):
        resp = await probe_single(host, port, probe)
        responses.append(resp)
        logger.debug(f"  Probe {i + 1}/10: {'got response' if resp != '|||' else 'no response'}")

    jarm_hash = compute_jarm_hash(responses)
    logger.info(f"JARM result: {host} -> {jarm_hash}")
    return {
        "host": host,
        "port": port,
        "jarm_hash": jarm_hash,
        "probes_responded": sum(1 for r in responses if r != "|||"),
    }


async def probe_hosts(ips: List[str], port: int = 443) -> List[Dict]:
    """Run JARM probing against a list of IPs concurrently (different hosts
    in parallel; the 10 probes against any one host run sequentially)."""
    tasks = [probe_host(ip, port) for ip in ips]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if isinstance(r, dict)]
