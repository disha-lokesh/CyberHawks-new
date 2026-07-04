"""
Garudatva v3 — Native .so Analyzer
Uses r2pipe (radare2) to analyse native ELF libraries bundled in the APK.
Extracts suspicious imports, exports, and strings from native code.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

SUSPICIOUS_NATIVE_IMPORTS = {
    "ptrace", "fork", "execve", "system", "popen",
    "dlopen", "dlsym", "mmap", "mprotect",
    "getenv", "setenv", "socket", "connect", "send", "recv",
    "gethostbyname", "getaddrinfo",
    "inotify_init", "inotify_add_watch",
    "prctl",
}

SUSPICIOUS_NATIVE_STRINGS = [
    "/proc/self/maps", "/proc/net/tcp",
    "/dev/socket/qemud", "frida", "xposed",
    "su", "/system/xbin/su", "/system/bin/su",
    "libhide", "inject",
]


class NativeAnalysisResult:
    def __init__(self):
        self.so_files_analyzed: List[str] = []
        self.suspicious_imports: List[str] = []
        self.suspicious_exports: List[str] = []
        self.suspicious_strings: List[str] = []
        self.anti_debug_signals: List[str] = []
        self.frida_detection: bool = False
        self.root_detection: bool = False
        self.emulator_detection: bool = False
        self.native_risk_score: float = 0.0
        self.errors: List[str] = []


def analyze_native(so_files: List[Path]) -> NativeAnalysisResult:
    """Analyse native .so files using r2pipe."""
    result = NativeAnalysisResult()

    if not so_files:
        return result

    try:
        import r2pipe
    except ImportError:
        result.errors.append("r2pipe not installed — pip install r2pipe")
        logger.warning("r2pipe not available, falling back to nm/strings")
        return _fallback_analysis(so_files, result)

    for so_path in so_files[:10]:   # Cap at 10 .so files to avoid RAM blowout
        if so_path.stat().st_size > 50 * 1024 * 1024:   # Skip >50MB
            logger.warning(f"Skipping large .so: {so_path.name}")
            continue
        try:
            _analyze_single_so(so_path, result, r2pipe)
        except Exception as e:
            result.errors.append(f"{so_path.name}: {e}")
            logger.warning(f"r2pipe error on {so_path.name}: {e}")

    _score_native(result)
    return result


def _analyze_single_so(so_path: Path, result: NativeAnalysisResult, r2pipe) -> None:
    import r2pipe
    r2 = r2pipe.open(str(so_path), flags=["-2"])   # -2 = silent stderr
    try:
        r2.cmd("aaa")   # Analyse all

        # Imports
        imports_raw = r2.cmd("iij")
        if imports_raw:
            for imp in json.loads(imports_raw):
                name = imp.get("name", "")
                if any(s in name for s in SUSPICIOUS_NATIVE_IMPORTS):
                    result.suspicious_imports.append(name)

        # Strings
        strings_raw = r2.cmd("izzj")
        if strings_raw:
            for st in json.loads(strings_raw):
                val = st.get("string", "")
                for suspicious in SUSPICIOUS_NATIVE_STRINGS:
                    if suspicious in val.lower():
                        result.suspicious_strings.append(val)
                        break

        result.so_files_analyzed.append(so_path.name)
        logger.debug(f"r2pipe analysed: {so_path.name}")

    finally:
        r2.quit()


def _fallback_analysis(so_files: List[Path], result: NativeAnalysisResult) -> NativeAnalysisResult:
    """Use nm + strings as fallback when r2pipe unavailable."""
    for so_path in so_files[:10]:
        try:
            proc = subprocess.run(
                ["nm", "-D", str(so_path)],
                capture_output=True, text=True, timeout=15,
            )
            for line in proc.stdout.splitlines():
                for sus in SUSPICIOUS_NATIVE_IMPORTS:
                    if sus in line:
                        result.suspicious_imports.append(sus)

            proc2 = subprocess.run(
                ["strings", "-n", "6", str(so_path)],
                capture_output=True, text=True, timeout=15,
            )
            for line in proc2.stdout.splitlines():
                for sus in SUSPICIOUS_NATIVE_STRINGS:
                    if sus in line.lower():
                        result.suspicious_strings.append(line.strip())

            result.so_files_analyzed.append(so_path.name)
        except Exception as e:
            result.errors.append(f"fallback {so_path.name}: {e}")

    _score_native(result)
    return result


def _score_native(result: NativeAnalysisResult) -> None:
    """Derive boolean flags and risk score from native artifacts."""
    all_suspicious = (
        result.suspicious_imports
        + result.suspicious_strings
    )
    text = " ".join(all_suspicious).lower()

    result.frida_detection = "frida" in text or "gum_" in text
    result.root_detection = "su" in text or "/system/xbin" in text
    result.emulator_detection = "qemud" in text or "goldfish" in text or "ranchu" in text

    if result.frida_detection:
        result.anti_debug_signals.append("Frida detection code")
    if result.root_detection:
        result.anti_debug_signals.append("Root/SU detection code")
    if result.emulator_detection:
        result.anti_debug_signals.append("Emulator detection code")

    score = 0.0
    score += min(len(result.suspicious_imports), 5) * 0.5
    score += min(len(result.suspicious_strings), 5) * 0.4
    score += 1.5 if result.frida_detection else 0
    score += 1.5 if result.emulator_detection else 0
    score += 1.0 if result.root_detection else 0

    result.native_risk_score = min(score, 5.0)
    logger.info(
        f"Native: {len(result.so_files_analyzed)} .so analysed, "
        f"risk={result.native_risk_score:.1f}"
    )
