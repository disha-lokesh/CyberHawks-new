"""
Garudatva v3 — Custom JA4 TLS Fingerprinting Engine
Written entirely from scratch — no external library dependency.
Parses raw TLS ClientHello binary frames from pcap.
Filters GREASE values per RFC 8701.
Format: TLSVer_SNI_CipherCount_ExtCount_CipherHash_ExtHash
"""

from __future__ import annotations

import asyncio
import hashlib
import struct
from pathlib import Path
from typing import List, Optional, Tuple

from models.ioc import NetworkArtifact
from utils.logger import get_logger

logger = get_logger(__name__)

# GREASE values to filter (RFC 8701)
GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
    0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

# TLS version byte → JA4 label
TLS_VERSIONS = {
    0x0301: "t10", 0x0302: "t11", 0x0303: "t12", 0x0304: "t13",
}


class TLSClientHello:
    def __init__(self):
        self.version: str = "t13"
        self.has_sni: bool = False
        self.sni: str = ""
        self.cipher_suites: List[int] = []
        self.extensions: List[int] = []
        self.alpn: List[str] = []
        self.signature_algorithms: List[int] = []


def compute_ja4(hello: TLSClientHello) -> str:
    """
    Compute JA4 fingerprint from a parsed TLSClientHello, per the FoxIO JA4
    spec (github.com/FoxIO-LLC/ja4).

    Part A (10 chars, unhashed): transport+version+sni+cipher_count+ext_count+alpn
    Part B (12 hex): truncated SHA256 of sorted, GREASE-filtered cipher suites
    Part C (12 hex): truncated SHA256 of sorted, GREASE-filtered extensions
                      (SNI/ALPN excluded — already captured in Part A) + "_" +
                      signature algorithms in original packet order

    Example: t13d1516h2_8daaf6152771_b186095e22b6
    """
    # GREASE-filtered, sorted-by-hex-value cipher suites (for count + Part B)
    ciphers = sorted(c for c in hello.cipher_suites if c not in GREASE_VALUES)
    # GREASE-filtered extensions, in original order, for the Part A count —
    # this includes SNI/ALPN (they count towards ext_count even though the
    # hash in Part C excludes them).
    exts_all = [e for e in hello.extensions if e not in GREASE_VALUES]

    version = hello.version
    sni_flag = "d" if hello.has_sni else "i"
    cipher_count = f"{min(len(ciphers), 99):02d}"
    ext_count = f"{min(len(exts_all), 99):02d}"

    # ALPN component: first + last char of the first ALPN value, else "00"
    if hello.alpn and hello.alpn[0]:
        proto = hello.alpn[0]
        alpn_code = proto[0] + proto[-1] if len(proto) > 1 else proto[0] * 2
    else:
        alpn_code = "00"

    part_a = f"{version}{sni_flag}{cipher_count}{ext_count}{alpn_code}"

    # Part B: cipher hash — never hash an empty string
    if ciphers:
        cipher_str = ",".join(f"{c:04x}" for c in ciphers)
        cipher_hash = hashlib.sha256(cipher_str.encode()).hexdigest()[:12]
    else:
        cipher_hash = "000000000000"

    # Part C: extension hash — sorted, GREASE removed, SNI(0x0000)/ALPN(0x0010)
    # excluded (already captured in Part A) + signature algorithms in the
    # order they appeared in the packet (not sorted).
    exts_for_hash = sorted(e for e in exts_all if e not in (0x0000, 0x0010))
    if exts_for_hash:
        ext_str = ",".join(f"{e:04x}" for e in exts_for_hash)
        if hello.signature_algorithms:
            sig_str = ",".join(f"{s:04x}" for s in hello.signature_algorithms)
            ext_str = f"{ext_str}_{sig_str}"
        ext_hash = hashlib.sha256(ext_str.encode()).hexdigest()[:12]
    else:
        ext_hash = "000000000000"

    return f"{part_a}_{cipher_hash}_{ext_hash}"


def parse_client_hello(data: bytes) -> Optional[TLSClientHello]:
    """
    Parse a raw TLS ClientHello record.
    data: raw bytes starting at the TLS record header.
    Returns None if not a valid ClientHello.
    """
    try:
        if len(data) < 5:
            return None

        # TLS Record header
        content_type = data[0]
        if content_type != 0x16:   # Handshake
            return None

        record_length = struct.unpack("!H", data[3:5])[0]
        if len(data) < 5 + record_length:
            return None

        handshake = data[5:5 + record_length]
        if not handshake or handshake[0] != 0x01:   # ClientHello
            return None

        # Handshake length (3 bytes)
        offset = 4
        if len(handshake) < offset + 2:
            return None

        hello = TLSClientHello()

        # Legacy version
        legacy_version = struct.unpack("!H", handshake[offset:offset + 2])[0]
        hello.version = TLS_VERSIONS.get(legacy_version, "t13")
        offset += 2

        # Random (32 bytes)
        offset += 32

        # Session ID
        if offset >= len(handshake):
            return None
        session_id_len = handshake[offset]
        offset += 1 + session_id_len

        # Cipher suites
        if offset + 2 > len(handshake):
            return None
        cs_len = struct.unpack("!H", handshake[offset:offset + 2])[0]
        offset += 2
        for i in range(0, cs_len, 2):
            if offset + 2 > len(handshake):
                break
            cs = struct.unpack("!H", handshake[offset:offset + 2])[0]
            if cs not in GREASE_VALUES:
                hello.cipher_suites.append(cs)
            offset += 2

        # Compression methods
        if offset >= len(handshake):
            return None
        comp_len = handshake[offset]
        offset += 1 + comp_len

        # Extensions
        if offset + 2 > len(handshake):
            return hello   # no extensions — still valid
        ext_total_len = struct.unpack("!H", handshake[offset:offset + 2])[0]
        offset += 2
        ext_end = offset + ext_total_len

        while offset + 4 <= ext_end and offset + 4 <= len(handshake):
            ext_type = struct.unpack("!H", handshake[offset:offset + 2])[0]
            ext_len = struct.unpack("!H", handshake[offset + 2:offset + 4])[0]
            offset += 4

            if ext_type not in GREASE_VALUES:
                hello.extensions.append(ext_type)

            # SNI (type 0x0000)
            if ext_type == 0x0000 and ext_len >= 5:
                try:
                    sni_list_len = struct.unpack("!H", handshake[offset:offset + 2])[0]
                    sni_type = handshake[offset + 2]
                    sni_name_len = struct.unpack("!H", handshake[offset + 3:offset + 5])[0]
                    sni_name = handshake[offset + 5:offset + 5 + sni_name_len].decode("ascii", errors="replace")
                    hello.sni = sni_name
                    hello.has_sni = True
                except Exception:
                    pass

            # ALPN (type 0x0010)
            elif ext_type == 0x0010 and ext_len >= 4:
                try:
                    alpn_list_len = struct.unpack("!H", handshake[offset:offset + 2])[0]
                    alpn_offset = offset + 2
                    alpn_end_inner = alpn_offset + alpn_list_len
                    while alpn_offset + 1 <= alpn_end_inner:
                        proto_len = handshake[alpn_offset]
                        alpn_offset += 1
                        proto = handshake[alpn_offset:alpn_offset + proto_len].decode("ascii", errors="replace")
                        hello.alpn.append(proto)
                        alpn_offset += proto_len
                except Exception:
                    pass

            # Signature algorithms (type 0x000d) — kept in packet order for Part C
            elif ext_type == 0x000d and ext_len >= 2:
                try:
                    sa_list_len = struct.unpack("!H", handshake[offset:offset + 2])[0]
                    sa_offset = offset + 2
                    sa_end = sa_offset + sa_list_len
                    while sa_offset + 2 <= sa_end and sa_offset + 2 <= len(handshake):
                        sa = struct.unpack("!H", handshake[sa_offset:sa_offset + 2])[0]
                        if sa not in GREASE_VALUES:
                            hello.signature_algorithms.append(sa)
                        sa_offset += 2
                except Exception:
                    pass

            # Supported versions (type 0x002b) — determines real TLS version
            elif ext_type == 0x002b:
                try:
                    sv_offset = offset
                    sv_len = handshake[sv_offset]
                    sv_offset += 1
                    best_version = 0
                    for _ in range(sv_len // 2):
                        v = struct.unpack("!H", handshake[sv_offset:sv_offset + 2])[0]
                        sv_offset += 2
                        if v not in GREASE_VALUES and v > best_version:
                            best_version = v
                    if best_version:
                        hello.version = TLS_VERSIONS.get(best_version, "t13")
                except Exception:
                    pass

            offset += ext_len

        return hello

    except Exception as e:
        logger.debug(f"ClientHello parse error: {e}")
        return None


def _reassemble_tcp_streams(pcap_path: str) -> List[Tuple[str, int, bytes]]:
    """
    Read a pcap with scapy and reassemble each TCP stream's payload bytes.
    scapy is used purely for packet/frame parsing (Ethernet/IP/TCP headers)
    — the TLS ClientHello itself is parsed by our own parse_client_hello(),
    not by a TLS-aware library. Returns (dst_ip, dst_port, payload) tuples,
    one per stream, concatenated in packet order.
    """
    from scapy.utils import PcapReader
    from scapy.layers.inet import IP, TCP

    streams: Dict[Tuple[str, int, int], bytearray] = {}
    order: List[Tuple[str, int, int]] = []

    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            if IP not in pkt or TCP not in pkt:
                continue
            tcp = pkt[TCP]
            payload = bytes(tcp.payload)
            if not payload:
                continue
            key = (pkt[IP].dst, tcp.dport, tcp.sport)
            if key not in streams:
                streams[key] = bytearray()
                order.append(key)
            streams[key].extend(payload)

    return [(key[0], key[1], bytes(streams[key])) for key in order]


async def parse_pcap(pcap_path: str) -> List[NetworkArtifact]:
    """
    Extract JA4 fingerprints from all TLS ClientHellos in a pcap.

    Uses scapy only to reassemble raw TCP stream bytes (frame/transport
    parsing) — the actual TLS ClientHello parsing and JA4 computation is
    done entirely by parse_client_hello()/compute_ja4() above, with no
    TLS-aware library involved, per the "no external dependency" design.
    """
    artifacts: List[NetworkArtifact] = []

    try:
        streams = await asyncio.to_thread(_reassemble_tcp_streams, pcap_path)
    except FileNotFoundError:
        logger.error(f"pcap not found: {pcap_path}")
        return artifacts
    except Exception as e:
        logger.error(f"pcap read error: {e}")
        return artifacts

    for dst_ip, dst_port, payload in streams:
        # A ClientHello is the first handshake message a client sends —
        # scan from the start of the stream for a TLS handshake record
        # whose first handshake byte is 0x01 (ClientHello).
        if len(payload) < 6 or payload[0] != 0x16 or payload[5] != 0x01:
            continue

        hello = parse_client_hello(payload)
        if hello is None:
            continue

        ja4 = compute_ja4(hello)
        artifacts.append(
            NetworkArtifact(
                url=f"tls://{hello.sni or dst_ip}:{dst_port}",
                host=hello.sni or dst_ip,
                ip=dst_ip,
                port=dst_port,
                protocol="TLS",
                ja4_hash=ja4,
                sni=hello.sni,
            )
        )
        logger.debug(f"JA4: {ja4} for {hello.sni or dst_ip}")

    logger.info(f"JA4 engine: {len(artifacts)} fingerprints extracted from {pcap_path}")
    return artifacts
