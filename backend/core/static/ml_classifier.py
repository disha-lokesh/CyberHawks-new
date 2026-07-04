"""
Garudatva v3 — ML Classifier
87-feature Random Forest with SHAP explainability.
Target AUC >= 0.972 (see ml/datasets/README.md); the actual measured AUC is
only known once ml/trainer.py has been run and is read from
models/training_metrics.json by get_model_metrics() below — never hardcode
a performance number here or in the report before that file exists.
Trained on AMD + CIC-AndMal2017 + Drebin.
"""

from __future__ import annotations

import json
import pickle
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

from models.risk_score import SHAPFeature
from utils.logger import get_logger

logger = get_logger(__name__)

_METRICS_PATH = Path(__file__).parent.parent.parent / "ml" / "models" / "training_metrics.json"
_metrics_cache: Optional[Dict] = None


def get_model_metrics() -> Optional[Dict]:
    """
    Return the real, measured training metrics (cv_auc_mean, train_auc, etc.)
    persisted by ml/trainer.py after an actual training run, or None if no
    model has been trained yet. Callers (e.g. the PDF report) must treat
    None as "heuristic scoring, no trained model" — never substitute a
    hardcoded/target number in its place.
    """
    global _metrics_cache
    if _metrics_cache is not None:
        return _metrics_cache
    if not _METRICS_PATH.exists():
        return None
    try:
        _metrics_cache = json.loads(_METRICS_PATH.read_text())
        return _metrics_cache
    except Exception as e:
        logger.warning(f"Failed to load training metrics: {e}")
        return None

# ── Feature names (ordered, matching training data) ──────────────────────────
# Top 87 features selected by Information Gain from 99 candidates.
FEATURE_NAMES = [
    # Permissions (15)
    "perm_READ_SMS", "perm_RECEIVE_SMS", "perm_SEND_SMS",
    "perm_READ_CONTACTS", "perm_READ_CALL_LOG",
    "perm_RECORD_AUDIO", "perm_CAMERA",
    "perm_SYSTEM_ALERT_WINDOW", "perm_BIND_ACCESSIBILITY_SERVICE",
    "perm_BIND_DEVICE_ADMIN", "perm_REQUEST_INSTALL_PACKAGES",
    "perm_ACCESS_FINE_LOCATION", "perm_ACCESS_BACKGROUND_LOCATION",
    "perm_USE_BIOMETRIC", "perm_PROCESS_OUTGOING_CALLS",
    # Manifest (8)
    "manifest_debuggable", "manifest_cleartext_traffic",
    "manifest_allow_backup", "manifest_permission_count",
    "manifest_activity_count", "manifest_service_count",
    "manifest_receiver_count", "manifest_obfuscation_score",
    # DEX (12)
    "dex_string_count", "dex_url_count", "dex_ip_count",
    "dex_class_count", "dex_reflection_used", "dex_dynamic_loading",
    "dex_obfuscation_level", "dex_crypto_class_count",
    "dex_network_class_count", "dex_suspicious_api_count",
    "dex_phone_number_count", "dex_encoded_payload_count",
    # Certificate (5)
    "cert_is_debug", "cert_is_expired", "cert_is_self_signed",
    "cert_anomaly_score", "cert_validity_years",
    # YARA (6)
    "yara_upi_fraud_hit", "yara_banking_trojan_hit",
    "yara_fake_loan_hit", "yara_aadhaar_hit",
    "yara_rat_hit", "yara_c2_hit",
    # India patterns (8)
    "india_upi_fraud_count", "india_fake_loan_count",
    "india_aadhaar_count", "india_banking_trojan_count",
    "india_rat_count", "india_social_fraud_count",
    "india_gov_fraud_count", "india_crypto_fraud_count",
    # Native .so (7)
    "native_suspicious_import_count", "native_suspicious_string_count",
    "native_frida_detection", "native_root_detection",
    "native_emulator_detection", "native_so_file_count",
    "native_risk_score",
    # Syscall (10) — from dynamic analysis (0 if static-only)
    "syscall_socket_freq", "syscall_connect_freq",
    "syscall_read_freq", "syscall_write_freq",
    "syscall_open_freq", "syscall_execve_freq",
    "syscall_ptrace_freq", "syscall_mmap_freq",
    "syscall_sendto_freq", "syscall_recvfrom_freq",
    # Network dynamic (6)
    "net_unique_hosts", "net_c2_hit_count",
    "net_dga_domain_count", "net_domain_fronting_detected",
    "net_firebase_c2", "net_tunnel_service",
    # Risk score (10)
    "risk_permission_score", "risk_india_pattern_score",
    "risk_yara_score", "risk_manifest_score",
    "risk_cert_score", "risk_native_score",
    "risk_cloud_c2_score", "risk_evasion_score",
    "risk_toxic_perm_count", "risk_dangerous_component_count",
]

assert len(FEATURE_NAMES) == 87, f"Expected 87 features, got {len(FEATURE_NAMES)}"


class MLClassifier:
    """Wraps the trained Random Forest for inference + SHAP explanation."""

    def __init__(self, model_path: Path):
        self.model_path = model_path
        self._model = None
        self._shap_explainer = None
        self._loaded = False

    def load(self) -> None:
        """Load model from disk. Called lazily."""
        if self._loaded:
            return
        if not self.model_path.exists():
            logger.warning(
                f"Model not found at {self.model_path}. "
                "Run ml/trainer.py to train first. "
                "Using fallback heuristic scoring."
            )
            return
        try:
            with open(self.model_path, "rb") as f:
                self._model = pickle.load(f)
            logger.info(f"RF model loaded from {self.model_path}")
            self._loaded = True
        except Exception as e:
            logger.error(f"Model load failed: {e}")

    def predict(
        self, feature_vector: List[float]
    ) -> Tuple[float, List[SHAPFeature]]:
        """
        Returns (malware_probability_0_to_1, top_shap_features).
        If model unavailable, returns heuristic estimate.
        """
        if not self._loaded or self._model is None:
            return self._heuristic_predict(feature_vector)

        X = np.array([feature_vector], dtype=np.float32)

        # RF probability
        proba = self._model.predict_proba(X)[0]
        # proba[1] = P(malware)
        mal_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])

        # SHAP
        shap_features = self._compute_shap(X, mal_prob)

        logger.info(f"RF prediction: P(malware)={mal_prob:.4f}")
        return mal_prob, shap_features

    def _compute_shap(
        self, X: np.ndarray, mal_prob: float
    ) -> List[SHAPFeature]:
        """Compute SHAP values for explainability."""
        try:
            import shap

            if self._shap_explainer is None:
                self._shap_explainer = shap.TreeExplainer(self._model)

            shap_values = self._shap_explainer.shap_values(X)
            # shap_values[1] = SHAP values for malware class
            sv = shap_values[1][0] if isinstance(shap_values, list) else shap_values[0]

            features = []
            for i, (name, val, shap_val) in enumerate(
                zip(FEATURE_NAMES, X[0], sv)
            ):
                features.append(
                    SHAPFeature(
                        feature_name=name,
                        shap_value=float(shap_val),
                        feature_value=float(val),
                        rank=0,   # Will be set after sorting
                    )
                )

            # Rank by absolute SHAP value
            features.sort(key=lambda f: abs(f.shap_value), reverse=True)
            for rank, f in enumerate(features, 1):
                f.rank = rank

            return features[:20]   # Top 20 for display

        except Exception as e:
            logger.warning(f"SHAP computation failed: {e}")
            return []

    def _heuristic_predict(
        self, feature_vector: List[float]
    ) -> Tuple[float, List[SHAPFeature]]:
        """
        Fallback when model is not trained yet.
        Simple weighted sum of key indicators.
        """
        fv = dict(zip(FEATURE_NAMES, feature_vector))
        score = 0.0
        score += fv.get("perm_BIND_ACCESSIBILITY_SERVICE", 0) * 0.3
        score += fv.get("perm_BIND_DEVICE_ADMIN", 0) * 0.25
        score += fv.get("dex_dynamic_loading", 0) * 0.2
        score += fv.get("dex_reflection_used", 0) * 0.1
        score += fv.get("yara_banking_trojan_hit", 0) * 0.35
        score += fv.get("yara_rat_hit", 0) * 0.3
        score += fv.get("native_frida_detection", 0) * 0.15
        score += fv.get("net_domain_fronting_detected", 0) * 0.2
        return min(score, 1.0), []
