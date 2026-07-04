"""
Garudatva v3 — Configuration
All environment variables and path constants.
"""

from pathlib import Path
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── Server ─────────────────────────────────────────────
    ENV: str = "development"
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000"]

    # ── Air-gap ────────────────────────────────────────────
    AIR_GAP_MODE: bool = True          # Workstation A = no internet
    WORKSTATION_B_URL: str = ""        # Only set on Workstation B

    # ── Paths ──────────────────────────────────────────────
    BASE_DIR: Path = Path(__file__).parent
    UPLOAD_DIR: Path = BASE_DIR / "data" / "uploads"
    EVIDENCE_DIR: Path = BASE_DIR / "data" / "evidence"
    REPORT_DIR: Path = BASE_DIR / "data" / "reports"
    ARTIFACT_DIR: Path = BASE_DIR / "data" / "artifacts"
    ML_MODEL_PATH: Path = BASE_DIR / "ml" / "models" / "india_malware_rf.pkl"
    YARA_RULES_DIR: Path = BASE_DIR.parent / "yara-rules"
    SIGNATURES_DIR: Path = BASE_DIR.parent / "signatures"

    # ── Neo4j ──────────────────────────────────────────────
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "garudatva"

    # ── Redis / Celery ─────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"

    # ── Ollama LLM ─────────────────────────────────────────
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "qwen2.5:7b-instruct-q4_K_M"
    OLLAMA_FALLBACK_MODEL: str = "mistral:7b-instruct-v0.3-q4_K_M"
    OLLAMA_TIMEOUT: int = 300          # seconds

    # ── Android / AVD ──────────────────────────────────────
    AVD_NAME: str = "garudatva_sandbox"
    AVD_EMULATOR_PORT: int = 5554
    ADB_HOST: str = "localhost"
    ADB_PORT: int = 5037
    SANDBOX_TIMEOUT: int = 600         # 10 minutes max
    MONKEYRUNNER_DURATION: int = 120   # seconds of UI emulation
    STRACE_DURATION: int = 120         # seconds of syscall profiling

    # ── Risk thresholds ────────────────────────────────────
    RISK_BENIGN_MAX: int = 29
    RISK_SUSPICIOUS_MIN: int = 30
    RISK_HIGH_RISK_MIN: int = 65
    RISK_CRITICAL_MIN: int = 85

    # ── ML ─────────────────────────────────────────────────
    ML_FEATURE_COUNT: int = 87
    ML_N_ESTIMATORS: int = 100
    ML_RANDOM_STATE: int = 42

    # ── JARM ───────────────────────────────────────────────
    JARM_TIMEOUT: int = 10             # seconds per probe
    JARM_PROBES: int = 10              # TLS probes per target

    # ── Signing ────────────────────────────────────────────
    SIGNING_CERT_DIR: Path = BASE_DIR / "data" / "certs"
    SIGNING_REASON: str = "Forensic Analysis Report — IT Act Sec 79A"

    # ── RAM limits ─────────────────────────────────────────
    RAM_WARN_MB: int = 6000
    RAM_CRITICAL_MB: int = 7500

    # ── India patterns ─────────────────────────────────────
    INDIA_PATTERN_COUNT: int = 47

    # ── MobSF (optional automated scanner, local instance only) ────
    # Empty MOBSF_URL disables the integration — matches every other
    # optional external tool in this codebase (jadx, apktool, Ollama).
    MOBSF_URL: str = ""            # e.g. "http://localhost:8000"
    MOBSF_API_KEY: str = ""
    MOBSF_TIMEOUT: int = 180       # seconds — MobSF static scans are slow


settings = Settings()
