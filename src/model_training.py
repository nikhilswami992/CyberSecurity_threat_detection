"""
Model Training Module
=====================
Trains and evaluates machine learning models for network intrusion detection.

Models:
1. Random Forest Classifier (baseline - fast, interpretable)
2. Deep Neural Network (TensorFlow/Keras - high accuracy)

Both models support binary classification (Normal vs Attack) 
and multi-class classification (Normal, DoS, Probe, R2L, U2R).
"""

import os
import sys
import json
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)
import joblib

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROCESSED_DATA_DIR = os.path.join(BASE_DIR, 'data', 'processed')
MODELS_DIR = os.path.join(BASE_DIR, 'models', 'saved')


def load_prepared_data():
    """Load the preprocessed feature-engineered data."""
    data = {}
    try:
        data['X_train'] = np.load(os.path.join(PROCESSED_DATA_DIR, 'X_train.npy'))
        data['X_test'] = np.load(os.path.join(PROCESSED_DATA_DIR, 'X_test.npy'))
        data['y_train_binary'] = np.load(os.path.join(PROCESSED_DATA_DIR, 'y_train_binary.npy'))
        data['y_test_binary'] = np.load(os.path.join(PROCESSED_DATA_DIR, 'y_test_binary.npy'))
        data['y_train_multi'] = np.load(os.path.join(PROCESSED_DATA_DIR, 'y_train_multi.npy'))
        data['y_test_multi'] = np.load(os.path.join(PROCESSED_DATA_DIR, 'y_test_multi.npy'))

        feature_names = pd.read_csv(
            os.path.join(PROCESSED_DATA_DIR, 'feature_names.csv')
        ).iloc[:, 0].tolist()
        data['feature_names'] = feature_names

        category_encoder = joblib.load(os.path.join(MODELS_DIR, 'category_encoder.pkl'))
        data['category_encoder'] = category_encoder

        print(f"✅ Loaded prepared data")
        print(f"   X_train: {data['X_train'].shape}")
        print(f"   X_test:  {data['X_test'].shape}")
        return data

    except FileNotFoundError as e:
        print(f"❌ Prepared data not found: {e}")
        print("   Run feature_engineering.py first!")
        sys.exit(1)


def evaluate_model(y_true, y_pred, y_prob=None, class_names=None, model_name="Model"):
    """
    Comprehensive model evaluation with multiple metrics.
    
    Parameters:
        y_true: True labels
        y_pred: Predicted labels
        y_prob: Prediction probabilities (optional, for AUC)
        class_names: Names for each class
        model_name: Name for display
    
    Returns:
        Dictionary of evaluation metrics
    """
    metrics = {
        'accuracy': float(accuracy_score(y_true, y_pred)),
        'precision': float(precision_score(y_true, y_pred, average='weighted', zero_division=0)),
        'recall': float(recall_score(y_true, y_pred, average='weighted', zero_division=0)),
        'f1_score': float(f1_score(y_true, y_pred, average='weighted', zero_division=0)),
    }

    # AUC for binary classification
    if y_prob is not None and len(np.unique(y_true)) == 2:
        try:
            if y_prob.ndim == 2:
                metrics['auc_roc'] = float(roc_auc_score(y_true, y_prob[:, 1]))
            else:
                metrics['auc_roc'] = float(roc_auc_score(y_true, y_prob))
        except ValueError:
            metrics['auc_roc'] = 0.0

    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred)

    # Calculate false positive rate for binary
    if len(np.unique(y_true)) == 2:
        tn, fp, fn, tp = cm.ravel()
        metrics['false_positive_rate'] = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        metrics['true_positive_rate'] = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0

    # Print results
    print(f"\n{'=' * 60}")
    print(f"📊 {model_name} — Evaluation Results")
    print(f"{'=' * 60}")
    print(f"  Accuracy:  {metrics['accuracy']:.4f} ({metrics['accuracy'] * 100:.2f}%)")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")
    print(f"  F1 Score:  {metrics['f1_score']:.4f}")

    if 'auc_roc' in metrics:
        print(f"  AUC-ROC:   {metrics['auc_roc']:.4f}")
    if 'false_positive_rate' in metrics:
        print(f"  FPR:       {metrics['false_positive_rate']:.4f} ({metrics['false_positive_rate'] * 100:.3f}%)")
        print(f"  TPR:       {metrics['true_positive_rate']:.4f}")

    if class_names is not None:
        print(f"\n📋 Classification Report:")
        print(classification_report(y_true, y_pred, target_names=class_names, zero_division=0))

    print(f"\n📊 Confusion Matrix:")
    print(cm)
    print(f"{'=' * 60}")

    return metrics


def train_random_forest(X_train, y_train, X_test, y_test,
                        class_names=None, task_name="binary"):
    """
    Train a Random Forest Classifier.
    
    Parameters:
        X_train, y_train: Training data
        X_test, y_test: Test data
        class_names: Class label names
        task_name: 'binary' or 'multi' (for naming)
    
    Returns:
        Tuple of (trained model, metrics dict)
    """
    print(f"\n🌲 Training Random Forest ({task_name} classification)...")

    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        max_features='sqrt',
        n_jobs=-1,
        random_state=42,
        class_weight='balanced'
    )

    rf.fit(X_train, y_train)

    # Predictions
    y_pred = rf.predict(X_test)
    y_prob = rf.predict_proba(X_test)

    # Evaluate
    metrics = evaluate_model(
        y_test, y_pred, y_prob, class_names,
        model_name=f"Random Forest ({task_name})"
    )

    # Feature importance
    if hasattr(rf, 'feature_importances_'):
        feature_names = pd.read_csv(
            os.path.join(PROCESSED_DATA_DIR, 'feature_names.csv')
        ).iloc[:, 0].tolist()

        if len(feature_names) == len(rf.feature_importances_):
            importance_df = pd.DataFrame({
                'feature': feature_names,
                'importance': rf.feature_importances_
            }).sort_values('importance', ascending=False)

            print(f"\n🔑 Top 10 Most Important Features:")
            for _, row in importance_df.head(10).iterrows():
                bar = '█' * int(row['importance'] * 100)
                print(f"  {row['feature']:35s} {row['importance']:.4f} {bar}")

    return rf, metrics


def train_neural_network(X_train, y_train, X_test, y_test,
                         class_names=None, task_name="binary"):
    """
    Train a Deep Neural Network using TensorFlow/Keras (or Scikit-Learn MLP fallback).
    
    Parameters:
        X_train, y_train: Training data
        X_test, y_test: Test data
        class_names: Class label names
        task_name: 'binary' or 'multi'
    
    Returns:
        Tuple of (trained model, metrics dict, training history)
    """
    # Import TensorFlow here to avoid slow import at module level
    try:
        os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
        import tensorflow as tf
        from tensorflow import keras
        from tensorflow.keras import layers, callbacks
    except ImportError:
        print(f"⚠️  TensorFlow not installed — training Deep MLP Neural Network (128 → 64 → 32) via Scikit-Learn ({task_name})...")
        from sklearn.neural_network import MLPClassifier
        mlp = MLPClassifier(
            hidden_layer_sizes=(128, 64, 32),
            activation='relu',
            solver='adam',
            batch_size=512,
            max_iter=15,
            random_state=42
        )
        mlp.fit(X_train, y_train)
        y_pred = mlp.predict(X_test)
        y_prob = mlp.predict_proba(X_test)
        eval_metrics = evaluate_model(
            y_test, y_pred, y_prob, class_names,
            model_name=f"Deep Neural Network ({task_name})"
        )
        return mlp, eval_metrics, None

    print(f"\n🧠 Training Neural Network ({task_name} classification)...")

    n_features = X_train.shape[1]
    n_classes = len(np.unique(y_train))

    # Build model architecture
    model = keras.Sequential([
        layers.Input(shape=(n_features,)),
        layers.Dense(256, activation='relu'),
        layers.BatchNormalization(),
        layers.Dropout(0.3),
        layers.Dense(128, activation='relu'),
        layers.BatchNormalization(),
        layers.Dropout(0.3),
        layers.Dense(64, activation='relu'),
        layers.BatchNormalization(),
        layers.Dropout(0.2),
        layers.Dense(32, activation='relu'),
    ])

    # Output layer depends on task
    if task_name == 'binary':
        model.add(layers.Dense(1, activation='sigmoid'))
        loss = 'binary_crossentropy'
        metrics_list = ['accuracy']
    else:
        model.add(layers.Dense(n_classes, activation='softmax'))
        loss = 'sparse_categorical_crossentropy'
        metrics_list = ['accuracy']

    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=0.001),
        loss=loss,
        metrics=metrics_list
    )

    # Callbacks
    early_stop = callbacks.EarlyStopping(
        monitor='val_loss', patience=5, restore_best_weights=True
    )
    reduce_lr = callbacks.ReduceLROnPlateau(
        monitor='val_loss', factor=0.5, patience=3, min_lr=1e-6
    )

    print(f"   Architecture: {n_features} → 256 → 128 → 64 → 32 → {1 if task_name == 'binary' else n_classes}")
    model.summary()

    # Train
    history = model.fit(
        X_train, y_train,
        epochs=50,
        batch_size=256,
        validation_split=0.15,
        callbacks=[early_stop, reduce_lr],
        verbose=1
    )

    # Predict
    if task_name == 'binary':
        y_prob = model.predict(X_test, verbose=0).flatten()
        y_pred = (y_prob > 0.5).astype(int)
    else:
        y_prob = model.predict(X_test, verbose=0)
        y_pred = np.argmax(y_prob, axis=1)

    # Evaluate
    eval_metrics = evaluate_model(
        y_test, y_pred, y_prob, class_names,
        model_name=f"Neural Network ({task_name})"
    )

    return model, eval_metrics, history


def save_models(rf_binary, rf_multi, nn_binary, nn_multi, metrics_all):
    """Save all trained models and their metrics."""
    os.makedirs(MODELS_DIR, exist_ok=True)

    # Save Random Forest models
    if rf_binary is not None:
        joblib.dump(rf_binary, os.path.join(MODELS_DIR, 'rf_binary.pkl'))
        print("💾 Saved: rf_binary.pkl")

    if rf_multi is not None:
        joblib.dump(rf_multi, os.path.join(MODELS_DIR, 'rf_multi.pkl'))
        print("💾 Saved: rf_multi.pkl")

    # Save Neural Network models
    if nn_binary is not None:
        if hasattr(nn_binary, 'save'):
            nn_binary.save(os.path.join(MODELS_DIR, 'nn_binary.keras'))
            print("💾 Saved: nn_binary.keras")
        else:
            joblib.dump(nn_binary, os.path.join(MODELS_DIR, 'nn_binary.pkl'))
            print("💾 Saved: nn_binary.pkl")

    if nn_multi is not None:
        if hasattr(nn_multi, 'save'):
            nn_multi.save(os.path.join(MODELS_DIR, 'nn_multi.keras'))
            print("💾 Saved: nn_multi.keras")
        else:
            joblib.dump(nn_multi, os.path.join(MODELS_DIR, 'nn_multi.pkl'))
            print("💾 Saved: nn_multi.pkl")

    # Save metrics
    with open(os.path.join(MODELS_DIR, 'metrics.json'), 'w') as f:
        json.dump(metrics_all, f, indent=2)
    print("💾 Saved: metrics.json")


if __name__ == '__main__':
    print("🛡️  AI-Based Cybersecurity Threat Detection")
    print("   Phase 2: Model Training")
    print("-" * 45)

    # Load data
    data = load_prepared_data()

    metrics_all = {}

    # ─── Binary Classification (Normal vs Attack) ───
    print("\n" + "🔴" * 20)
    print("  BINARY CLASSIFICATION: Normal vs Attack")
    print("🔴" * 20)

    # Random Forest — Binary
    rf_binary, rf_binary_metrics = train_random_forest(
        data['X_train'], data['y_train_binary'],
        data['X_test'], data['y_test_binary'],
        class_names=['Normal', 'Attack'],
        task_name='binary'
    )
    metrics_all['rf_binary'] = rf_binary_metrics

    # Neural Network — Binary
    nn_binary, nn_binary_metrics, nn_binary_hist = train_neural_network(
        data['X_train'], data['y_train_binary'],
        data['X_test'], data['y_test_binary'],
        class_names=['Normal', 'Attack'],
        task_name='binary'
    )
    if nn_binary_metrics:
        metrics_all['nn_binary'] = nn_binary_metrics

    # ─── Multi-class Classification ───
    print("\n" + "🟠" * 20)
    print("  MULTI-CLASS CLASSIFICATION: Attack Categories")
    print("🟠" * 20)

    class_names = list(data['category_encoder'].classes_)
    print(f"  Classes: {class_names}")

    # Random Forest — Multi
    rf_multi, rf_multi_metrics = train_random_forest(
        data['X_train'], data['y_train_multi'],
        data['X_test'], data['y_test_multi'],
        class_names=class_names,
        task_name='multi'
    )
    metrics_all['rf_multi'] = rf_multi_metrics

    # Neural Network — Multi
    nn_multi, nn_multi_metrics, nn_multi_hist = train_neural_network(
        data['X_train'], data['y_train_multi'],
        data['X_test'], data['y_test_multi'],
        class_names=class_names,
        task_name='multi'
    )
    if nn_multi_metrics:
        metrics_all['nn_multi'] = nn_multi_metrics

    # ─── Save All Models ───
    save_models(rf_binary, rf_multi, nn_binary, nn_multi, metrics_all)

    # ─── Summary ───
    print("\n" + "=" * 60)
    print("📊 MODEL COMPARISON SUMMARY")
    print("=" * 60)
    for model_name, metrics in metrics_all.items():
        print(f"\n  {model_name}:")
        print(f"    Accuracy:  {metrics['accuracy']:.4f}")
        print(f"    F1 Score:  {metrics['f1_score']:.4f}")
        if 'false_positive_rate' in metrics:
            print(f"    FPR:       {metrics['false_positive_rate']:.4f}")
    print("=" * 60)

    print("\n🎉 Model training complete!")
