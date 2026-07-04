"""
Garudatva v3 — Indicator of Compromise models.
"""

from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class IOCType(str, Enum):
    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    CERTIFICATE_SHA1 = "CERTIFICATE_SHA1"
    PHONE_NUMBER = "PHONE_NUMBER"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    AES_KEY = "AES_KEY"
    DEVELOPER_CERT = "DEVELOPER_CERT"
    PACKAGE_NAME = "PACKAGE_NAME"
    JA4_HASH = "JA4_HASH"
    JARM_HASH = "JARM_HASH"


class CloudProvider(str, Enum):
    AWS = "AWS"
    GCP = "GCP"
    AZURE = "AZURE"
    CLOUDFLARE = "CLOUDFLARE"
    FIREBASE = "FIREBASE"
    UNKNOWN = "UNKNOWN"
    NOT_CLOUD = "NOT_CLOUD"


class IOC(BaseModel):
    ioc_type: IOCType
    value: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source: str = ""              # which analyzer found this
    context: str = ""             # human-readable context
    cloud_provider: Optional[CloudProvider] = None
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    is_dga: bool = False
    dga_entropy: Optional[float] = None
    is_domain_fronting: bool = False
    is_tunnel_service: bool = False
    tunnel_service_name: Optional[str] = None
    ja4_hash: Optional[str] = None
    jarm_hash: Optional[str] = None
    first_seen: Optional[datetime] = None


class CryptoArtifact(BaseModel):
    """Extracted AES key / IV pair with cipher object tracking."""
    cipher_id: int                # Java hashCode() of Cipher object
    algorithm: str                # e.g. "AES/CBC/PKCS5Padding"
    mode: int                     # 1=ENCRYPT, 2=DECRYPT
    key_hex: Optional[str] = None
    iv_hex: Optional[str] = None
    plaintext_hex: Optional[str] = None
    plaintext_preview: Optional[str] = None
    interceptor_class: Optional[str] = None   # OkHttp interceptor name
    timestamp: Optional[str] = None


class NetworkArtifact(BaseModel):
    """Captured network connection from dynamic analysis."""
    url: str
    method: str = "GET"
    host: str = ""
    ip: Optional[str] = None
    port: Optional[int] = None
    protocol: str = "HTTPS"
    ja4_hash: Optional[str] = None
    sni: Optional[str] = None
    host_header: Optional[str] = None
    domain_fronting: bool = False
    interceptor_class: Optional[str] = None
    request_body_preview: Optional[str] = None


class YARAMatch(BaseModel):
    rule_name: str
    rule_file: str
    category: str
    strings_matched: List[str] = Field(default_factory=list)
    meta: dict = Field(default_factory=dict)


class IndiaPatternMatch(BaseModel):
    pattern_id: str
    pattern_name: str
    category: str          # "UPI_FRAUD" | "FAKE_LOAN" | "AADHAAR" | etc.
    matched_strings: List[str] = Field(default_factory=list)
    severity: str = "HIGH"
