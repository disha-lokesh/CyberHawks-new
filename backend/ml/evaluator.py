"""
Garudatva v3 — ML Model Evaluator
Evaluates trained Random Forest on held-out test set.
Generates AUC, precision, recall, F1, confusion matrix.
Run after training to validate before deployment.

Usage:
    python evaluator.py --model ml/models/india_malware_rf.pkl \
                        --test-features ml/datasets/test_features.npy \
                        --test-labels ml/datasets/test_labels.npy
"""

from __future__ import annotations

import argparse
import pickle
from pathlib import Path
from typing import Dict

import numpy as np


def evaluate(
    model_path: Path,
    X_test: np.ndarray,
    y_test: np.ndarray,
    feature_indices_path: Path,
    class_names: list = None,
) -> Dict:
    """
    Evaluate trained model. Returns metrics dict.

    Args:
        model_path: Path to india_malware_rf.pkl
        X_test: Test features (n_samples, 99) — raw, unselected
        y_test: Test labels (n_samples,)
        feature_indices_path: Path to feature_indices.pkl (top 87 indices)
        class_names: Label names for report
    """
    from sklearn.metrics import (
        roc_auc_score, classification_report,
        confusion_matrix, precision_recall_curve,
    )

    if class_names is None:
        class_names = ["benign", "malware"]

    # Load model
    print(f"Loading model from {model_path}...")
    with open(model_path, "rb") as f:
        clf = pickle.load(f)

    # Load feature indices (same selection as training)
    print(f"Loading feature indices from {feature_indices_path}...")
    with open(feature_indices_path, "rb") as f:
        feature_indices = pickle.load(f)

    # Apply same feature selection as training
    X_selected = X_test[:, feature_indices]
    print(f"Test set: {X_selected.shape[0]} samples, {X_selected.shape[1]} selected features")

    # Predictions
    y_pred = clf.predict(X_selected)
    y_proba = clf.predict_proba(X_selected)[:, 1]

    # Metrics
    auc = roc_auc_score(y_test, y_proba)
    report = classification_report(y_test, y_pred, target_names=class_names, output_dict=True)
    cm = confusion_matrix(y_test, y_pred)

    # Threshold analysis
    precisions, recalls, thresholds = precision_recall_curve(y_test, y_proba)
    f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-8)
    best_threshold_idx = f1_scores.argmax()
    best_threshold = float(thresholds[best_threshold_idx]) if best_threshold_idx < len(thresholds) else 0.5

    metrics = {
        "auc": float(auc),
        "precision_malware": float(report.get("malware", {}).get("precision", 0)),
        "recall_malware": float(report.get("malware", {}).get("recall", 0)),
        "f1_malware": float(report.get("malware", {}).get("f1-score", 0)),
        "precision_benign": float(report.get("benign", {}).get("precision", 0)),
        "recall_benign": float(report.get("benign", {}).get("recall", 0)),
        "f1_benign": float(report.get("benign", {}).get("f1-score", 0)),
        "accuracy": float(report.get("accuracy", 0)),
        "false_positive_rate": float(cm[0][1] / (cm[0][0] + cm[0][1]) if cm[0].sum() > 0 else 0),
        "false_negative_rate": float(cm[1][0] / (cm[1][0] + cm[1][1]) if cm[1].sum() > 0 else 0),
        "confusion_matrix": cm.tolist(),
        "best_threshold": best_threshold,
        "n_test_samples": int(X_test.shape[0]),
        "n_features_selected": int(X_selected.shape[1]),
    }

    # Print summary
    print("\n" + "=" * 60)
    print("GARUDATVA ML EVALUATION REPORT")
    print("=" * 60)
    print(f"  AUC:              {metrics['auc']:.4f}  (target: ≥0.972)")
    print(f"  Precision:        {metrics['precision_malware']:.4f}")
    print(f"  Recall:           {metrics['recall_malware']:.4f}")
    print(f"  F1 Score:         {metrics['f1_malware']:.4f}")
    print(f"  Accuracy:         {metrics['accuracy']:.4f}")
    print(f"  False Positive:   {metrics['false_positive_rate']:.4f}  (target: ≤0.03)")
    print(f"  False Negative:   {metrics['false_negative_rate']:.4f}")
    print(f"  Best Threshold:   {metrics['best_threshold']:.4f}")
    print(f"  Confusion Matrix: TN={cm[0][0]} FP={cm[0][1]} FN={cm[1][0]} TP={cm[1][1]}")
    print("=" * 60)

    if metrics["auc"] >= 0.972:
        print("  ✓ AUC target MET — model ready for deployment")
    else:
        print(f"  ✗ AUC below 0.972 — retrain with more data")

    if metrics["false_positive_rate"] <= 0.03:
        print("  ✓ FPR target MET — acceptable for forensic use")
    else:
        print(f"  ✗ FPR above 0.03 — too many benign apps flagged")

    # SHAP feature importance
    try:
        import shap
        from core.static.ml_classifier import FEATURE_NAMES
        print("\nComputing SHAP feature importance (top 10)...")
        explainer = shap.TreeExplainer(clf)
        shap_values = explainer.shap_values(X_selected[:min(200, len(X_selected))])
        sv = shap_values[1] if isinstance(shap_values, list) else shap_values
        mean_abs_shap = np.abs(sv).mean(axis=0)

        selected_names = [FEATURE_NAMES[i] for i in feature_indices]
        ranked = sorted(
            zip(selected_names, mean_abs_shap),
            key=lambda x: x[1], reverse=True
        )
        print("\nTop 10 most important features (SHAP):")
        for rank, (name, importance) in enumerate(ranked[:10], 1):
            print(f"  {rank:2d}. {name:<45} {importance:.4f}")

        metrics["shap_top_features"] = [
            {"feature": name, "mean_abs_shap": float(imp)}
            for name, imp in ranked[:20]
        ]
    except Exception as e:
        print(f"  SHAP skipped: {e}")

    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Evaluate Garudatva ML model on test data"
    )
    parser.add_argument("--model", default="ml/models/india_malware_rf.pkl",
                        help="Path to trained model")
    parser.add_argument("--indices", default="ml/models/feature_indices.pkl",
                        help="Path to feature indices")
    parser.add_argument("--test-features", required=True,
                        help="Path to test_features.npy")
    parser.add_argument("--test-labels", required=True,
                        help="Path to test_labels.npy")
    args = parser.parse_args()

    X_test = np.load(args.test_features)
    y_test = np.load(args.test_labels)

    metrics = evaluate(
        model_path=Path(args.model),
        X_test=X_test,
        y_test=y_test,
        feature_indices_path=Path(args.indices),
    )

    # Save metrics JSON
    import json
    out = Path("ml/models/evaluation_report.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"\nMetrics saved to {out}")