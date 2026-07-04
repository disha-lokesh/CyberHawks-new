"""
Garudatva v3 — ML Feature Extractor
Extracts 99-feature vector from raw APK files for ML training.
Mirrors the feature extraction logic in core/static/triage.py
but runs in batch mode for dataset preparation.

Usage:
    python feature_extractor.py --input /path/to/apks/ --output ml/datasets/ --label 1
    python feature_extractor.py --input /path/to/benign/ --output ml/datasets/ --label 0
"""

from __future__ import annotations

import argparse
import zipfile
from pathlib import Path
from typing import List, Optional, Tuple
import numpy as np

# Feature count matches FEATURE_NAMES in ml_classifier.py
TOTAL_FEATURES = 99

# Dangerous permissions that matter for ML
DANGEROUS_PERMISSIONS = [
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.USE_BIOMETRIC",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.DISABLE_KEYGUARD",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.INTERNET",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.FOREGROUND_SERVICE",
]

# Suspicious DEX API calls
SUSPICIOUS_APIS = [
    "DexClassLoader", "PathClassLoader", "Class.forName",
    "invoke", "loadLibrary", "Runtime.exec",
    "getRuntime", "ProcessBuilder", "reflection",
    "SecretKeySpec", "Cipher", "IvParameterSpec",
    "Base64.decode", "XOR", "AES", "RC4",
]

# Suspicious native imports
SUSPICIOUS_NATIVE = [
    "socket", "connect", "exec", "ptrace",
    "dlopen", "mmap", "fork", "kill",
    "system", "popen",
]


def extract_features(apk_path: Path) -> Optional[List[float]]:
    """
    Extract 99 features from a single APK file.
    Returns None if APK is unreadable.

    Feature groups (99 total):
      - 23 permission features
      - 12 manifest features
      - 20 DEX string features
      - 8 certificate features
      - 10 native library features
      - 16 behavioral heuristics
      - 10 syscall features (zero at static time)
    """
    try:
        return _extract_safe(apk_path)
    except Exception as e:
        print(f"  SKIP {apk_path.name}: {e}")
        return None


def _extract_safe(apk_path: Path) -> List[float]:
    fv: List[float] = []

    # ── Open APK as ZIP ────────────────────────────────────────────────
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            names = zf.namelist()
            dex_files = [n for n in names if n.endswith(".dex")]
            so_files = [n for n in names if n.endswith(".so")]
            has_manifest = "AndroidManifest.xml" in names

            # Read first DEX for string extraction
            dex_bytes = b""
            if dex_files:
                try:
                    dex_bytes = zf.read(dex_files[0])
                except Exception:
                    pass

            # Manifest raw bytes
            manifest_bytes = b""
            if has_manifest:
                try:
                    manifest_bytes = zf.read("AndroidManifest.xml")
                except Exception:
                    pass

    except (zipfile.BadZipFile, Exception):
        # Return zero vector for unreadable APKs
        return [0.0] * TOTAL_FEATURES

    # ── Try androguard for deep analysis ──────────────────────────────
    permissions: List[str] = []
    activities: List[str] = []
    services: List[str] = []
    receivers: List[str] = []
    is_debuggable = False
    allows_cleartext = False
    allows_backup = False
    package_name = ""
    dex_strings: List[str] = []
    class_names: List[str] = []

    try:
        from androguard.misc import AnalyzeAPK
        a, d, dx = AnalyzeAPK(str(apk_path))
        permissions = list(a.get_permissions())
        activities = list(a.get_activities())
        services = list(a.get_services())
        receivers = list(a.get_receivers())
        is_debuggable = a.is_debuggable()
        allows_cleartext = a.get_attribute_value(
            "application", "usesCleartextTraffic"
        ) == "true"
        allows_backup = a.get_attribute_value(
            "application", "allowBackup"
        ) != "false"
        package_name = a.get_package()

        # Extract strings from DEX
        if d:
            for dex in (d if isinstance(d, list) else [d]):
                for s in dex.get_strings():
                    dex_strings.append(str(s))
        for cls in dx.get_classes():
            class_names.append(cls.name)

    except Exception:
        # Fallback: raw byte scanning
        dex_strings = _extract_strings_raw(dex_bytes)
        permissions = _scan_permissions_raw(manifest_bytes)

    perm_set = set(permissions)

    # ── GROUP 1: Permission features (23) ─────────────────────────────
    for perm in DANGEROUS_PERMISSIONS:
        fv.append(1.0 if perm in perm_set else 0.0)

    # ── GROUP 2: Manifest features (12) ───────────────────────────────
    fv.append(1.0 if is_debuggable else 0.0)
    fv.append(1.0 if allows_cleartext else 0.0)
    fv.append(1.0 if allows_backup else 0.0)
    fv.append(float(min(len(permissions), 50)))
    fv.append(float(min(len(activities), 30)))
    fv.append(float(min(len(services), 20)))
    fv.append(float(min(len(receivers), 20)))
    fv.append(_obfuscation_score(class_names, package_name))
    fv.append(float(len(dex_files)))
    fv.append(float(len(so_files)))
    fv.append(1.0 if len(so_files) > 0 else 0.0)
    fv.append(1.0 if _has_hidden_icon(manifest_bytes) else 0.0)

    # ── GROUP 3: DEX string features (20) ─────────────────────────────
    all_text = " ".join(dex_strings).lower()
    urls = [s for s in dex_strings if s.startswith(("http://", "https://"))]
    ips = [s for s in dex_strings if _looks_like_ip(s)]
    crypto_classes = [s for s in class_names if any(
        k in s.lower() for k in ["cipher", "aes", "crypto", "encrypt", "decrypt"]
    )]
    network_classes = [s for s in class_names if any(
        k in s.lower() for k in ["okhttp", "retrofit", "volley", "urlconnection", "socket"]
    )]
    susp_apis = [api for api in SUSPICIOUS_APIS if api.lower() in all_text]
    phone_nums = [s for s in dex_strings if _looks_like_phone(s)]
    encoded = [s for s in dex_strings if _looks_encoded(s)]

    fv.append(float(min(len(dex_strings), 10000)))
    fv.append(float(min(len(urls), 50)))
    fv.append(float(min(len(ips), 20)))
    fv.append(float(min(len(class_names), 5000)))
    fv.append(1.0 if "class.forname" in all_text or "reflection" in all_text else 0.0)
    fv.append(1.0 if "dexclassloader" in all_text or "pathclassloader" in all_text else 0.0)
    fv.append(_dex_obfuscation_level(class_names))
    fv.append(float(min(len(crypto_classes), 20)))
    fv.append(float(min(len(network_classes), 20)))
    fv.append(float(min(len(susp_apis), 20)))
    fv.append(float(min(len(phone_nums), 10)))
    fv.append(float(min(len(encoded), 10)))
    fv.append(1.0 if "firebaseio.com" in all_text else 0.0)
    fv.append(1.0 if any(t in all_text for t in ["ngrok", "serveo", "localxpose"]) else 0.0)
    fv.append(1.0 if "accessibility" in all_text else 0.0)
    fv.append(1.0 if "smsmanager" in all_text else 0.0)
    fv.append(1.0 if "clipboardmanager" in all_text else 0.0)
    fv.append(1.0 if "devicepolicymanger" in all_text else 0.0)
    fv.append(_shannon_entropy_score(dex_bytes[:4096]))
    fv.append(1.0 if "setcomponentenabledsetting" in all_text else 0.0)

    # ── GROUP 4: Certificate features (8) ─────────────────────────────
    cert_info = _extract_cert_info(apk_path)
    fv.append(float(cert_info.get("is_debug", 0)))
    fv.append(float(cert_info.get("is_expired", 0)))
    fv.append(float(cert_info.get("is_self_signed", 0)))
    fv.append(float(cert_info.get("anomaly_score", 0.0)))
    fv.append(float(min(cert_info.get("validity_years", 0), 50)))
    fv.append(float(cert_info.get("new_cert", 0)))
    fv.append(float(cert_info.get("weak_key", 0)))
    fv.append(float(cert_info.get("cert_country_risk", 0)))

    # ── GROUP 5: Native library features (10) ─────────────────────────
    native_strings = _extract_native_strings(apk_path, so_files[:3])
    native_text = " ".join(native_strings).lower()
    susp_imports = [s for s in SUSPICIOUS_NATIVE if s in native_text]
    susp_native_str = [
        s for s in native_strings
        if any(k in s.lower() for k in ["frida", "substrate", "xposed", "magisk"])
    ]
    fv.append(float(min(len(susp_imports), 20)))
    fv.append(float(min(len(susp_native_str), 20)))
    fv.append(1.0 if any(k in native_text for k in ["frida", "gum_script"]) else 0.0)
    fv.append(1.0 if any(k in native_text for k in ["su", "superuser", "magisk"]) else 0.0)
    fv.append(1.0 if any(k in native_text for k in ["emulator", "goldfish", "vbox"]) else 0.0)
    fv.append(float(min(len(so_files), 10)))
    fv.append(float(_native_risk_score(susp_imports, susp_native_str)))
    fv.append(_shannon_entropy_score(_read_so_sample(apk_path, so_files)))
    fv.append(1.0 if "ptrace" in native_text else 0.0)
    fv.append(1.0 if "execve" in native_text else 0.0)

    # ── GROUP 6: Behavioral heuristics (16) ───────────────────────────
    fv.append(1.0 if any(r in perm_set for r in [
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.BIND_DEVICE_ADMIN",
    ]) else 0.0)
    fv.append(1.0 if "upi" in all_text or "bhim" in all_text else 0.0)
    fv.append(1.0 if any(b in all_text for b in ["sbiinb", "icicib", "hdfcbk"]) else 0.0)
    fv.append(1.0 if "aadhaar" in all_text or "uidai" in all_text else 0.0)
    fv.append(1.0 if "pan card" in all_text or "pannumber" in all_text else 0.0)
    fv.append(1.0 if any(l in all_text for l in ["instant loan", "no cibil", "aadhaar loan"]) else 0.0)
    fv.append(1.0 if "overly" in all_text or "windowmanager" in all_text else 0.0)
    fv.append(1.0 if "type_view_text_changed" in all_text else 0.0)
    fv.append(float(len([u for u in urls if "firebase" in u.lower()])))
    fv.append(1.0 if len(activities) == 0 else 0.0)
    fv.append(1.0 if "receive_boot_completed" in all_text else 0.0)
    fv.append(1.0 if "getinstalledpackages" in all_text else 0.0)
    fv.append(1.0 if "camera" in all_text and "upload" in all_text else 0.0)
    fv.append(1.0 if "microphone" in all_text or "record_audio" in all_text else 0.0)
    fv.append(_toxic_permission_combo_score(perm_set))
    fv.append(float(min(len([s for s in services if s]), 10)))

    # ── GROUP 7: Syscall features (10) — zero at static time ──────────
    fv.extend([0.0] * 10)

    assert len(fv) == TOTAL_FEATURES, f"Feature count mismatch: {len(fv)} != {TOTAL_FEATURES}"
    return fv


# ── Helper functions ───────────────────────────────────────────────────────────

def _extract_strings_raw(data: bytes, min_len: int = 5) -> List[str]:
    """Extract printable ASCII strings from raw bytes."""
    strings = []
    current = []
    for byte in data:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                strings.append("".join(current))
            current = []
    return strings[:5000]


def _scan_permissions_raw(manifest_bytes: bytes) -> List[str]:
    """Scan manifest bytes for permission strings."""
    text = manifest_bytes.decode("utf-8", errors="ignore")
    import re
    return re.findall(r"android\.permission\.[A-Z_]+", text)


def _looks_like_ip(s: str) -> bool:
    import re
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", s))


def _looks_like_phone(s: str) -> bool:
    import re
    return bool(re.match(r"^(\+91|0)[6-9]\d{9}$", s))


def _looks_encoded(s: str) -> bool:
    """Detect Base64 or hex encoded strings."""
    import re
    if len(s) < 20:
        return False
    if re.match(r"^[A-Za-z0-9+/]{20,}={0,2}$", s):
        return True
    if re.match(r"^[0-9a-fA-F]{32,}$", s):
        return True
    return False


def _obfuscation_score(class_names: List[str], package_name: str) -> float:
    """Score 0-5 based on class name obfuscation indicators."""
    if not class_names:
        return 0.0
    short = sum(1 for c in class_names if len(c.split("/")[-1]) <= 2)
    ratio = short / max(len(class_names), 1)
    return float(min(ratio * 5, 5.0))


def _dex_obfuscation_level(class_names: List[str]) -> float:
    """0.0-1.0 obfuscation level."""
    if not class_names:
        return 0.0
    short = sum(1 for c in class_names if len(c.split("/")[-1].strip("L;")) <= 2)
    return float(min(short / max(len(class_names), 1), 1.0))


def _has_hidden_icon(manifest_bytes: bytes) -> bool:
    text = manifest_bytes.decode("utf-8", errors="ignore")
    return "LAUNCHER" not in text and len(manifest_bytes) > 0


def _shannon_entropy_score(data: bytes) -> float:
    """Compute normalized Shannon entropy (0-1)."""
    if not data:
        return 0.0
    import math
    freq: dict = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    total = len(data)
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return float(entropy / 8.0)  # Normalize to 0-1


def _extract_cert_info(apk_path: Path) -> dict:
    """Extract certificate metadata for feature vector."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        import zipfile
        import datetime

        with zipfile.ZipFile(apk_path, "r") as zf:
            cert_files = [n for n in zf.namelist() if n.startswith("META-INF/") and
                         n.endswith((".RSA", ".DSA", ".EC"))]
            if not cert_files:
                return {"anomaly_score": 1.0, "is_self_signed": 1}

            cert_data = zf.read(cert_files[0])

        # Parse PKCS#7 / DER cert
        from cryptography.hazmat.backends import default_backend
        try:
            from cryptography.hazmat.primitives.serialization.pkcs7 import (
                load_der_pkcs7_certificates,
            )
            certs = load_der_pkcs7_certificates(cert_data)
        except Exception:
            return {"anomaly_score": 0.5}

        if not certs:
            return {"anomaly_score": 1.0}

        cert = certs[0]
        now = datetime.datetime.now(datetime.timezone.utc)
        is_expired = cert.not_valid_after_utc < now if hasattr(cert, "not_valid_after_utc") else False
        validity_days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days if not is_expired else 0
        is_self_signed = cert.issuer == cert.subject
        is_debug = "Android Debug" in str(cert.subject)
        new_cert = (now - cert.not_valid_before_utc).days < 30
        anomaly = sum([
            2.0 if is_debug else 0.0,
            1.5 if is_self_signed else 0.0,
            1.0 if is_expired else 0.0,
            1.0 if new_cert else 0.0,
        ])

        return {
            "is_debug": int(is_debug),
            "is_expired": int(is_expired),
            "is_self_signed": int(is_self_signed),
            "anomaly_score": float(min(anomaly, 5.0)),
            "validity_years": float(validity_days / 365),
            "new_cert": int(new_cert),
            "weak_key": 0,
            "cert_country_risk": 0,
        }
    except Exception:
        return {"anomaly_score": 0.0}


def _extract_native_strings(apk_path: Path, so_names: List[str]) -> List[str]:
    """Extract printable strings from .so files inside APK."""
    strings = []
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for so_name in so_names[:2]:
                try:
                    data = zf.read(so_name)
                    strings.extend(_extract_strings_raw(data, min_len=5))
                except Exception:
                    pass
    except Exception:
        pass
    return strings[:2000]


def _read_so_sample(apk_path: Path, so_names: List[str]) -> bytes:
    """Read first 4KB of first .so for entropy calculation."""
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            if so_names:
                return zf.read(so_names[0])[:4096]
    except Exception:
        pass
    return b""


def _native_risk_score(susp_imports: list, susp_strings: list) -> float:
    """Score 0-10 based on native indicators."""
    score = len(susp_imports) * 0.5 + len(susp_strings) * 1.0
    return float(min(score, 10.0))


def _toxic_permission_combo_score(perm_set: set) -> float:
    """Score for dangerous permission combinations."""
    score = 0.0
    combos = [
        ({"android.permission.BIND_ACCESSIBILITY_SERVICE",
          "android.permission.READ_SMS",
          "android.permission.INTERNET"}, 2.0),
        ({"android.permission.RECORD_AUDIO",
          "android.permission.CAMERA",
          "android.permission.FOREGROUND_SERVICE"}, 1.5),
        ({"android.permission.READ_CONTACTS",
          "android.permission.READ_CALL_LOG",
          "android.permission.INTERNET"}, 1.5),
        ({"android.permission.READ_SMS",
          "android.permission.RECEIVE_SMS",
          "android.permission.INTERNET",
          "android.permission.RECEIVE_BOOT_COMPLETED"}, 3.0),
    ]
    for required_perms, weight in combos:
        if required_perms.issubset(perm_set):
            score += weight
    return float(min(score, 5.0))


def batch_extract(
    apk_dir: Path,
    label: int,
    output_prefix: str,
    output_dir: Path,
    max_samples: int = 50000,
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Extract features from all APKs in a directory.
    Saves features.npy and labels.npy to output_dir.

    Args:
        apk_dir: Directory containing .apk files
        label: 0=benign, 1=malware
        output_prefix: e.g. "amd", "cic", "drebin"
        output_dir: Where to save .npy files
        max_samples: Cap to avoid OOM
    """
    apks = list(apk_dir.glob("*.apk"))[:max_samples]
    print(f"Found {len(apks)} APKs in {apk_dir} (label={label})")

    features = []
    for i, apk in enumerate(apks):
        if i % 100 == 0:
            print(f"  Processing {i}/{len(apks)}: {apk.name}")
        fv = extract_features(apk)
        if fv is not None:
            features.append(fv)

    if not features:
        raise ValueError(f"No APKs successfully processed in {apk_dir}")

    X = np.array(features, dtype=np.float32)
    y = np.full(len(features), label, dtype=np.int32)

    output_dir.mkdir(parents=True, exist_ok=True)
    np.save(output_dir / f"{output_prefix}_features.npy", X)
    np.save(output_dir / f"{output_prefix}_labels.npy", y)
    print(f"  Saved: {output_prefix}_features.npy ({X.shape}), {output_prefix}_labels.npy")

    return X, y


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract ML features from APK files for Garudatva training"
    )
    parser.add_argument("--input", required=True, help="Directory of .apk files")
    parser.add_argument("--output", default="ml/datasets", help="Output directory for .npy files")
    parser.add_argument("--label", type=int, required=True, choices=[0, 1],
                        help="0=benign, 1=malware")
    parser.add_argument("--prefix", required=True,
                        help="Output file prefix e.g. 'amd', 'cic', 'drebin'")
    parser.add_argument("--max", type=int, default=50000,
                        help="Max samples to process (default 50000)")
    args = parser.parse_args()

    X, y = batch_extract(
        apk_dir=Path(args.input),
        label=args.label,
        output_prefix=args.prefix,
        output_dir=Path(args.output),
        max_samples=args.max,
    )
    print(f"Done. Shape: X={X.shape}, y={y.shape}")