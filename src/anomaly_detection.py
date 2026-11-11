"""
Anomaly Detection Module
========================
Implements unsupervised anomaly detection using Isolation Forest
to identify unknown or zero-day threats that supervised models might miss.

The Isolation Forest learns the "normal" behavior of the network 
and flags activities that deviate significantly from the baseline.
"""

import os
import sys
import json
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
import joblib

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROCESSED_DATA_DIR = os.path.join(BASE_DIR, 'data', 'processed')
MODELS_DIR = os.path.join(BASE_DIR, 'models', 'saved')


def load_data():
    """Load preprocessed data."""
    try:
        X_train = np.load(os.path.join(PROCESSED_DATA_DIR, 'X_train.npy'))
        X_test = np.load(os.path.join(PROCESSED_DATA_DIR, 'X_test.npy'))
        y_train = np.load(os.path.join(PROCESSED_DATA_DIR, 'y_train_binary.npy'))
        y_test = np.load(os.path.join(PROCESSED_DATA_DIR, 'y_test_binary.npy'))

        print(f"✅ Loaded data for anomaly detection")
        print(f"   X_train: {X_train.shape}, X_test: {X_test.shape}")
        return X_train, X_test, y_train, y_test

    except FileNotFoundError:
        print("❌ Prepared data not found. Run feature_engineering.py first!")
        sys.exit(1)


def train_isolation_forest(X_train, y_train):
    """
    Train Isolation Forest on NORMAL traffic only.
    The model learns the baseline of normal behavior, then anything
    deviating from this baseline is flagged as anomalous.
    
    Parameters:
        X_train: Training features
        y_train: Binary labels (0=Normal, 1=Attack)
    
    Returns:
        Trained IsolationForest model
    """
    print("\n🌲 Training Isolation Forest for Anomaly Detection...")

    # Train only on normal traffic to learn the baseline
    X_normal = X_train[y_train == 0]
    print(f"   Training on {len(X_normal)} normal traffic samples")
    print(f"   (Excluded {len(X_train) - len(X_normal)} attack samples)")

    # Contamination = expected proportion of anomalies in the dataset
    # Set slightly higher than 0 to be conservative
    iso_forest = IsolationForest(
        n_estimators=200,
        max_samples='auto',
        contamination=0.05,
        max_features=1.0,
        bootstrap=False,
        n_jobs=-1,
        random_state=42
    )

    iso_forest.fit(X_normal)
    print("✅ Isolation Forest trained successfully")

    return iso_forest


def compute_anomaly_scores(model, X_data):
    """
    Compute anomaly scores for each data point.
    
    Isolation Forest returns:
    - decision_function: The anomaly score (lower = more anomalous)
    - predict: 1 for normal, -1 for anomaly
    
    Parameters:
        model: Trained IsolationForest
        X_data: Feature matrix
    
    Returns:
        Tuple of (predictions, anomaly_scores)
    """
    # Get raw anomaly scores (lower = more anomalous)
    raw_scores = model.decision_function(X_data)

    # Normalize scores to 0-1 range (0 = normal, 1 = highly anomalous)
    # Invert so higher score = more suspicious
    min_score = raw_scores.min()
    max_score = raw_scores.max()
    normalized_scores = 1 - (raw_scores - min_score) / (max_score - min_score + 1e-10)

    # Get predictions (-1 = anomaly, 1 = normal)
    predictions = model.predict(X_data)
    # Convert to binary: 0 = normal, 1 = anomaly
    binary_predictions = (predictions == -1).astype(int)

    return binary_predictions, normalized_scores


def evaluate_anomaly_detection(y_true, y_pred, anomaly_scores):
    """
    Evaluate anomaly detection performance.
    
    Parameters:
        y_true: True binary labels (0=Normal, 1=Attack)
        y_pred: Predicted binary labels
        anomaly_scores: Normalized anomaly scores
    """
    print("\n" + "=" * 60)
    print("📊 ANOMALY DETECTION — Evaluation Results")
    print("=" * 60)

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    print(f"  Accuracy:           {accuracy:.4f} ({accuracy * 100:.2f}%)")
    print(f"  Precision:          {precision:.4f}")
    print(f"  Recall (TPR):       {recall:.4f}")
    print(f"  F1 Score:           {f1:.4f}")
    print(f"  False Positive Rate: {fpr:.4f} ({fpr * 100:.3f}%)")
    print(f"\n  Confusion Matrix:")
    print(f"    True Negatives:  {tn:,}")
    print(f"    False Positives: {fp:,}")
    print(f"    False Negatives: {fn:,}")
    print(f"    True Positives:  {tp:,}")

    # Score distribution
    normal_scores = anomaly_scores[y_true == 0]
    attack_scores = anomaly_scores[y_true == 1]

    print(f"\n  📊 Anomaly Score Distribution:")
    print(f"    Normal traffic:  mean={normal_scores.mean():.4f}, std={normal_scores.std():.4f}")
    print(f"    Attack traffic:  mean={attack_scores.mean():.4f}, std={attack_scores.std():.4f}")
    print(f"    Separation:      {abs(attack_scores.mean() - normal_scores.mean()):.4f}")
    print("=" * 60)

    metrics = {
        'accuracy': float(accuracy),
        'precision': float(precision),
        'recall': float(recall),
        'f1_score': float(f1),
        'false_positive_rate': float(fpr),
        'normal_score_mean': float(normal_scores.mean()),
        'attack_score_mean': float(attack_scores.mean()),
    }

    return metrics


def save_anomaly_model(model, metrics):
    """Save the trained Isolation Forest model and metrics."""
    os.makedirs(MODELS_DIR, exist_ok=True)

    joblib.dump(model, os.path.join(MODELS_DIR, 'isolation_forest.pkl'))
    print(f"💾 Saved: isolation_forest.pkl")

    # Update metrics file
    metrics_path = os.path.join(MODELS_DIR, 'metrics.json')
    if os.path.exists(metrics_path):
        with open(metrics_path, 'r') as f:
            all_metrics = json.load(f)
    else:
        all_metrics = {}

    all_metrics['isolation_forest'] = metrics

    with open(metrics_path, 'w') as f:
        json.dump(all_metrics, f, indent=2)

    print(f"💾 Updated: metrics.json")


if __name__ == '__main__':
    print("🛡️  AI-Based Cybersecurity Threat Detection")
    print("   Phase 2: Anomaly Detection")
    print("-" * 45)

    # Load data
    X_train, X_test, y_train, y_test = load_data()

    # Train Isolation Forest
    iso_forest = train_isolation_forest(X_train, y_train)

    # Compute anomaly scores
    print("\n🔍 Computing anomaly scores on test data...")
    y_pred, anomaly_scores = compute_anomaly_scores(iso_forest, X_test)

    # Evaluate
    metrics = evaluate_anomaly_detection(y_test, y_pred, anomaly_scores)

    # Save
    save_anomaly_model(iso_forest, metrics)

    print("\n🎉 Anomaly detection training complete!")
