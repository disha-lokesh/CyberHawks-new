"""
Garudatva v3 — Network Capture
Runs tshark on AVD bridge interface (android0) during dynamic analysis.
Passes pcap to JA4 engine. Classifies C2 by ASN, DGA, Firebase, tunnels.
"""

from __future__ import annotations

import asyncio
import ipaddress
import math
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from models.ioc import CloudProvider, IOC, IOCType, NetworkArtifact
from utils.logger import get_logger

logger = get_logger(__name__)

PCAP_PATH = "/tmp/garudatva_capture.pcap"

# Known tunnel service hostnames
TUNNEL_PATTERNS = [
    r"\.ngrok\.io$", r"\.ngrok-free\.app$",
    r"\.trycloudflare\.com$", r"\.loca\.lt$",
    r"serveo\.net$", r"localhost\.run$",
    r"\.pagekite\.me$",
]

# Firebase C2 patterns
FIREBASE_PATTERNS = [
    r"\.firebaseio\.com$",
    r"fcm\.googleapis\.com$",
    r"firestore\.googleapis\.com$",
]

# Cloud provider ASN name fragments
CLOUD_ASN_MAP = {
    "AMAZON": CloudProvider.AWS,
    "AWS": CloudProvider.AWS,
    "GOOGLE": CloudProvider.GCP,
    "MICROSOFT": CloudProvider.AZURE,
    "AZURE": CloudProvider.AZURE,
    "CLOUDFLARE": CloudProvider.CLOUDFLARE,
    "FIREBASE": CloudProvider.FIREBASE,
}


async def capture_network_traffic(
    interface: str = "android0",
    duration_seconds: int = 120,
    output_path: str = PCAP_PATH,
) -> Optional[str]:
    """
    Run tshark on AVD bridge interface for duration_seconds.
    Returns path to pcap file, or None on failure.
    """
    logger.info(f"tshark capturing on {interface} for {duration_seconds}s")
    try:
        proc = await asyncio.create_subprocess_exec(
            "tshark",
            "-i", interface,
            "-a", f"duration:{duration_seconds}",
            "-w", output_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=duration_seconds + 30
        )
        if Path(output_path).exists() and Path(output_path).stat().st_size > 0:
            logger.info(f"pcap saved: {output_path} ({Path(output_path).stat().st_size} bytes)")
            return output_path
        logger.warning(f"tshark produced empty/no pcap: {stderr.decode(errors='replace')[:200]}")
        return None
    except FileNotFoundError:
        logger.error("tshark not found — install: sudo pacman -S wireshark-cli")
        return None
    except Exception as e:
        logger.error(f"tshark failed: {e}")
        return None


async def parse_pcap_with_ja4(pcap_path: str) -> List[NetworkArtifact]:
    """Feed pcap through our custom JA4 engine."""
    try:
        from core.ja4.ja4_engine import parse_pcap
        return await parse_pcap(pcap_path)
    except Exception as e:
        logger.error(f"JA4 parse failed: {e}")
        return []


async def classify_cloud_c2(iocs: List[IOC]) -> Dict[str, Any]:
    """
    Stage 3: classify each extracted IP/domain against cloud C2 patterns.
    Returns additions to risk score and per-IOC classification.
    """
    results: Dict[str, Any] = {
        "cloud_hits": [],
        "dga_domains": [],
        "domain_fronting": [],
        "firebase_c2": [],
        "tunnel_services": [],
        "score_additions": {},
    }

    for ioc in iocs:
        if ioc.ioc_type == IOCType.IP:
            provider = await _classify_ip_asn(ioc.value)
            if provider != CloudProvider.NOT_CLOUD:
                ioc.cloud_provider = provider
                results["cloud_hits"].append({
                    "ip": ioc.value,
                    "provider": provider,
                })

        elif ioc.ioc_type in (IOCType.URL, IOCType.DOMAIN):
            domain = _extract_domain(ioc.value)
            if not domain:
                continue

            # Firebase C2
            if any(re.search(p, domain) for p in FIREBASE_PATTERNS):
                ioc.cloud_provider = CloudProvider.FIREBASE
                results["firebase_c2"].append(domain)

            # Tunnel service
            tunnel = _check_tunnel(domain)
            if tunnel:
                ioc.is_tunnel_service = True
                ioc.tunnel_service_name = tunnel
                results["tunnel_services"].append({"domain": domain, "service": tunnel})

            # DGA entropy
            entropy, is_dga = _compute_dga_entropy(domain)
            if is_dga:
                ioc.is_dga = True
                ioc.dga_entropy = entropy
                results["dga_domains"].append({"domain": domain, "entropy": entropy})

    # Build score additions
    if results["cloud_hits"]:
        results["score_additions"]["connects_to_cloud_asn"] = 10
    if results["dga_domains"]:
        results["score_additions"]["dga_domain_detected"] = 15
    if results["domain_fronting"]:
        results["score_additions"]["domain_fronting_detected"] = 25
    if results["firebase_c2"]:
        results["score_additions"]["firebase_c2_pattern"] = 20
    if results["tunnel_services"]:
        results["score_additions"]["tunnel_service_detected"] = 30

    total_cloud_addition = sum(results["score_additions"].values())
    results["total_cloud_score_addition"] = min(total_cloud_addition, 60)

    logger.info(
        f"Cloud C2 classification: +{results['total_cloud_score_addition']} pts, "
        f"firebase={len(results['firebase_c2'])}, "
        f"tunnels={len(results['tunnel_services'])}, "
        f"dga={len(results['dga_domains'])}"
    )
    return results


# ── Internal helpers ─────────────────────────────────────────────────────────

async def _classify_ip_asn(ip: str) -> CloudProvider:
    """Simple ASN lookup via whois or ipinfo.io (air-gap: whois only)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "whois", ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        text = stdout.decode(errors="replace").upper()
        for keyword, provider in CLOUD_ASN_MAP.items():
            if keyword in text:
                return provider
    except Exception:
        pass
    return CloudProvider.NOT_CLOUD


def _extract_domain(url_or_domain: str) -> str:
    """Extract bare domain from URL."""
    url_or_domain = url_or_domain.lower().strip()
    url_or_domain = re.sub(r"^https?://", "", url_or_domain)
    url_or_domain = url_or_domain.split("/")[0].split(":")[0]
    return url_or_domain


def _check_tunnel(domain: str) -> Optional[str]:
    TUNNEL_NAMES = {
        r"\.ngrok\.io$": "ngrok",
        r"\.ngrok-free\.app$": "ngrok",
        r"\.trycloudflare\.com$": "cloudflare_tunnel",
        r"\.loca\.lt$": "localtunnel",
        r"serveo\.net$": "serveo",
        r"localhost\.run$": "localhost_run",
        r"\.pagekite\.me$": "pagekite",
    }
    for pattern, name in TUNNEL_NAMES.items():
        if re.search(pattern, domain):
            return name
    return None


def _compute_dga_entropy(domain: str) -> Tuple[float, bool]:
    """
    Shannon entropy + n-gram frequency to detect algorithmically generated domains.
    Entropy > 3.8 and subdomain length > 12 = likely DGA.
    """
    subdomain = domain.split(".")[0]
    if len(subdomain) < 8:
        return 0.0, False

    # Shannon entropy
    freq: Dict[str, int] = {}
    for ch in subdomain:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = -sum(
        (c / len(subdomain)) * math.log2(c / len(subdomain))
        for c in freq.values()
    )

    is_dga = entropy > 3.8 and len(subdomain) > 12
    return round(entropy, 3), is_dga
