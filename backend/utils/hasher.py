"""
Garudatva v3 — Cryptographic hashing utilities.
SHA256 is the primary chain hash per BSA Sec 63.
"""

import hashlib
from pathlib import Path
from typing import Dict


CHUNK_SIZE = 65536  # 64KB chunks for large APK/video files


def sha256_file(path: Path) -> str:
    """
    Compute SHA256 of a file in streaming chunks.
    Used for APK, video evidence, and final PDF integrity.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """SHA256 of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_str(text: str) -> str:
    """SHA256 of a UTF-8 string. Used for canonical JSON hashing."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def multi_hash_file(path: Path) -> Dict[str, str]:
    """
    Compute MD5 + SHA1 + SHA256 + SHA512 in a single pass.
    Used in evidence locker manifest for completeness.
    MD5/SHA1 included for legacy tool compatibility only —
    SHA256 is the legally binding hash per BSA Sec 63.
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()

    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "sha512": sha512.hexdigest(),
    }


def verify_file_hash(path: Path, expected_sha256: str) -> bool:
    """
    Verify a file's SHA256 matches the expected value.
    Returns True if intact, False if tampered.
    """
    actual = sha256_file(path)
    return actual == expected_sha256


def ssdeep_hash(path: Path) -> str:
    """
    Fuzzy hash for similarity clustering (ssdeep).
    Used to cluster related malware samples in Neo4j.
    Requires ssdeep system package installed.
    """
    try:
        import ssdeep
        return ssdeep.hash_from_file(str(path))
    except ImportError:
        return "ssdeep_not_installed"
    except Exception as e:
        return f"ssdeep_error:{e}"
