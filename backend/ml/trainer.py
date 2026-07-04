"""
Garudatva v3 — ML Trainer
Information Gain feature selection → top 87 features.
Random Forest: 100 trees. Target AUC >= 0.972 (see ml/datasets/README.md) —
the actual achieved AUC is only known after a real training run and is
persisted to training_metrics.json alongside the model; nothing should
quote a specific AUC before that file exists.
Training data: AMD + CIC-AndMal2017 + Drebin.
"""

from __future__ import annotations

import json
import pickle
from pathlib import Path
from typing import Tuple

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import mutual_info_classif
from sklearn.metrics import roc_auc_score, classification_report
from sklearn.model_selection import cross_val_score, StratifiedKFold

from core.static.ml_classifier import FEATURE_NAMES
from utils.logger import get_logger

logger = get_logger(__name__)

MODEL_OUTPUT = Path(__file__).parent / "models" / "india_malware_rf.pkl"
FEATURE_INDEX_OUTPUT = Path(__file__).parent / "models" / "feature_indices.pkl"
METRICS_OUTPUT = Path(__file__).parent / "models" / "training_metrics.json"


def train(X: np.ndarray, y: np.ndarray, output_path: Path = MODEL_OUTPUT) -> dict:
    """
    Full training pipeline:
      1. Information Gain feature selection (top 87 of 99)
      2. Random Forest 100 trees
      3. Cross-validation AUC
      4. Save model + feature indices

    X: (n_samples, 99) raw feature matrix
    y: (n_samples,) binary labels (0=benign, 1=malware)
    """
    assert X.shape[1] >= 87, f"Need >=87 raw features, got {X.shape[1]}"
    logger.info(f"Training on {X.shape[0]} samples, {X.shape[1]} features")

    # ── Information Gain feature selection ────────────────────────────
    logger.info("Computing Information Gain scores...")
    ig_scores = mutual_info_classif(X, y, random_state=42)
    top_87_indices = ig_scores.argsort()[-87:][::-1]
    X_selected = X[:, top_87_indices]
    logger.info(
        f"Top feature (IG): index {top_87_indices[0]}, "
        f"score {ig_scores[top_87_indices[0]]:.4f}"
    )

    # ── Random Forest ─────────────────────────────────────────────────
    logger.info("Training Random Forest (100 trees)...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_features="sqrt",
        min_samples_split=2,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )

    # 5-fold stratified CV for AUC estimate
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_aucs = cross_val_score(
        clf, X_selected, y, cv=skf, scoring="roc_auc", n_jobs=-1
    )
    logger.info(
        f"CV AUC: {cv_aucs.mean():.4f} ± {cv_aucs.std():.4f}"
        f" (folds: {cv_aucs.tolist()})"
    )

    # Full fit
    clf.fit(X_selected, y)
    y_proba = clf.predict_proba(X_selected)[:, 1]
    train_auc = roc_auc_score(y, y_proba)
    logger.info(f"Train AUC: {train_auc:.4f}")

    # ── Save ──────────────────────────────────────────────────────────
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as f:
        pickle.dump(clf, f, protocol=5)
    logger.info(f"Model saved to {output_path}")

    with open(FEATURE_INDEX_OUTPUT, "wb") as f:
        pickle.dump(top_87_indices, f)
    logger.info(f"Feature indices saved to {FEATURE_INDEX_OUTPUT}")

    metrics = {
        "cv_auc_mean": float(cv_aucs.mean()),
        "cv_auc_std": float(cv_aucs.std()),
        "train_auc": float(train_auc),
        "n_samples": int(X.shape[0]),
        "n_malware": int(y.sum()),
        "n_benign": int(len(y) - y.sum()),
        "n_features_selected": 87,
        "n_estimators": 100,
        "top_feature_index": int(top_87_indices[0]),
        "top_feature_ig_score": float(ig_scores[top_87_indices[0]]),
    }

    # Persisted so the report/classifier can quote the *actual* measured AUC
    # instead of the pre-training target — never hardcode a metric that
    # hasn't been produced by a real training run.
    with open(METRICS_OUTPUT, "w") as f:
        json.dump(metrics, f, indent=2)
    logger.info(f"Training metrics saved to {METRICS_OUTPUT}")

    return metrics


def load_datasets(datasets_dir: Path) -> Tuple[np.ndarray, np.ndarray]:
    """
    Load and merge training datasets.
    Expected files in datasets_dir:
      - amd_features.npy + amd_labels.npy
      - cic_features.npy + cic_labels.npy
      - drebin_features.npy + drebin_labels.npy

    See datasets/README.md for preprocessing instructions.
    """
    import numpy as np

    Xs, ys = [], []
    sources = [
        ("amd_features.npy", "amd_labels.npy", "AMD"),
        ("cic_features.npy", "cic_labels.npy", "CIC-AndMal2017"),
        ("drebin_features.npy", "drebin_labels.npy", "Drebin"),
    ]

    for feat_file, label_file, name in sources:
        fp = datasets_dir / feat_file
        lp = datasets_dir / label_file
        if not fp.exists() or not lp.exists():
            logger.warning(f"Dataset {name} not found — skipping")
            continue
        X = np.load(fp)
        y = np.load(lp)
        Xs.append(X)
        ys.append(y)
        logger.info(f"Loaded {name}: {X.shape[0]} samples")

    if not Xs:
        raise FileNotFoundError(
            f"No datasets found in {datasets_dir}. "
            "See ml/datasets/README.md for preprocessing instructions."
        )

    return np.vstack(Xs), np.concatenate(ys)


if __name__ == "__main__":
    import sys
    datasets_dir = Path(__file__).parent / "datasets"
    logger.info("Loading training datasets...")
    X, y = load_datasets(datasets_dir)
    logger.info(f"Total: {X.shape[0]} samples ({y.sum():.0f} malware, {(1-y).sum():.0f} benign)")
    metrics = train(X, y)
    logger.info(f"Training complete: {metrics}")
