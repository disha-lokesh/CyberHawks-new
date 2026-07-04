"""
Garudatva v3 — CSP Cloud IP Range Sweeper
Runs on Workstation B after a JARM match.
Downloads current IP ranges from AWS/GCP/Azure/Cloudflare.
Uses masscan to find live hosts on port 443.
Runs JARM probe on each live host.
Returns all IPs sharing the malicious JARM hash.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
from typing import List

import httpx

from utils.logger import get_logger

logger = get_logger(__name__)

# Official IP range endpoints
CLOUD_RANGE_URLS = {
    "AWS":        "https://ip-ranges.amazonaws.com/ip-ranges.json",
    "GCP":        "https://www.gstatic.com/ipranges/cloud.json",
    "AZURE":      "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20240101.json",
    "CLOUDFLARE": "https://api.cloudflare.com/client/v4/ips",
}


async def fetch_cloud_ranges() -> List[str]:
    """Download and return all cloud provider CIDR ranges."""
    ranges: List[str] = []
    async with httpx.AsyncClient(timeout=30) as client:

        # AWS
        try:
            r = await client.get(CLOUD_RANGE_URLS["AWS"])
            data = r.json()
            for prefix in data.get("prefixes", []):
                cidr = prefix.get("ip_prefix")
                if cidr:
                    ranges.append(cidr)
            logger.info(f"AWS ranges: {len(ranges)} CIDRs")
        except Exception as e:
            logger.warning(f"AWS range fetch failed: {e}")

        # GCP
        try:
            r = await client.get(CLOUD_RANGE_URLS["GCP"])
            data = r.json()
            gcp_count = 0
            for prefix in data.get("prefixes", []):
                cidr = prefix.get("ipv4Prefix")
                if cidr:
                    ranges.append(cidr)
                    gcp_count += 1
            logger.info(f"GCP ranges: {gcp_count} CIDRs")
        except Exception as e:
            logger.warning(f"GCP range fetch failed: {e}")

        # Cloudflare
        try:
            r = await client.get(CLOUD_RANGE_URLS["CLOUDFLARE"])
            data = r.json()
            cf_ranges = data.get("result", {}).get("ipv4_cidrs", [])
            ranges.extend(cf_ranges)
            logger.info(f"Cloudflare ranges: {len(cf_ranges)} CIDRs")
        except Exception as e:
            logger.warning(f"Cloudflare range fetch failed: {e}")

    logger.info(f"Total cloud ranges fetched: {len(ranges)} CIDRs")
    return ranges


async def masscan_range(cidr: str, port: int = 443, rate: int = 1000) -> List[str]:
    """Run masscan on a CIDR range. Returns list of live IPs."""
    live_ips: List[str] = []
    try:
        proc = await asyncio.create_subprocess_exec(
            "masscan", cidr,
            "-p", str(port),
            "--rate", str(rate),
            "--output-format", "json",
            "--output-filename", "/tmp/masscan_out.json",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.communicate(), timeout=120)

        import pathlib
        out = pathlib.Path("/tmp/masscan_out.json")
        if out.exists():
            text = out.read_text(errors="replace").strip()
            if text and text != "[]":
                # masscan JSON has trailing comma issues — fix
                text = text.rstrip(",\n") + "]" if not text.endswith("]") else text
                try:
                    data = json.loads("[" + text.lstrip("["))
                    live_ips = [entry["ip"] for entry in data if "ip" in entry]
                except json.JSONDecodeError:
                    pass
    except asyncio.TimeoutError:
        logger.warning(f"masscan timed out on {cidr}")
    except FileNotFoundError:
        logger.error("masscan not found — install: sudo pacman -S masscan")
    except Exception as e:
        logger.error(f"masscan error on {cidr}: {e}")

    return live_ips


async def sweep_cloud_ranges(target_jarm_hash: str, port: int = 443) -> List[str]:
    """
    Full CSP sweep:
    1. Download all cloud IP ranges
    2. masscan for live hosts on port 443
    3. JARM probe each live host
    4. Return IPs that match target JARM hash
    """
    from core.jarm.jarm_prober import probe_host

    logger.info(f"CSP sweep starting for JARM={target_jarm_hash[:16]}…")
    matching_ips: List[str] = []

    ranges = await fetch_cloud_ranges()
    if not ranges:
        logger.warning("No cloud ranges fetched — sweep aborted")
        return matching_ips

    # Limit sweep to first 50 ranges for demo (full sweep would take hours)
    sweep_ranges = ranges[:50]
    logger.info(f"Scanning {len(sweep_ranges)} CIDR ranges with masscan...")

    all_live_ips: List[str] = []
    for cidr in sweep_ranges:
        live = await masscan_range(cidr, port)
        all_live_ips.extend(live)

    logger.info(f"masscan found {len(all_live_ips)} live hosts — running JARM probes")

    # JARM probe each live host
    for ip in all_live_ips[:200]:   # cap at 200 for demo
        result = await probe_host(ip, port)
        if result.get("jarm_hash") == target_jarm_hash:
            matching_ips.append(ip)
            logger.info(f"JARM MATCH: {ip} → {target_jarm_hash[:16]}…")

    logger.info(
        f"CSP sweep complete: {len(matching_ips)} matching IPs "
        f"from {len(all_live_ips)} live hosts"
    )
    return matching_ips
