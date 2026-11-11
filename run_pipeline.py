"""
Pipeline Runner — Complete, Refine & Debug Implementation
=========================================================
Runs the complete ML pipeline end-to-end:
  1. Data Ingestion   — Download & load NSL-KDD dataset
  2. Feature Engineering — Encode, derive, normalize features
  3. Model Training   — Random Forest & Deep Neural Network (binary + multi-class)
  4. Anomaly Detection — Isolation Forest
  5. API Launch       — Flask server + SecOps dashboard

Usage:
    python3 run_pipeline.py           # Run full pipeline + launch API
    python3 run_pipeline.py --train   # Run training only (no API)
    python3 run_pipeline.py --api     # Launch API only (assumes trained models)
    python3 run_pipeline.py --verify  # Run automated integration & debug verification suite
"""

import os
import sys
import time
import argparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)


def print_banner():
    print("\n" + "=" * 60)
    print("🛡️  AI-Based Cybersecurity Threat Detection")
    print("   Complete, Refined & Verified Implementation")
    print("=" * 60)


def step_1_data_ingestion():
    """Download and load the NSL-KDD dataset."""
    print("\n" + "━" * 60)
    print("📦 STEP 1: Data Ingestion")
    print("━" * 60)

    from src.data_ingestion import download_dataset, load_dataset, get_data_summary
    from src.data_ingestion import PROCESSED_DATA_DIR

    os.makedirs(PROCESSED_DATA_DIR, exist_ok=True)

    success = download_dataset()
    if not success:
        print("❌ Data download failed. Exiting.")
        sys.exit(1)

    train_df = load_dataset('train')
    get_data_summary(train_df)

    test_df = load_dataset('test')
    get_data_summary(test_df)

    # Save as CSV
    train_df.to_csv(os.path.join(PROCESSED_DATA_DIR, 'train_raw.csv'), index=False)
    test_df.to_csv(os.path.join(PROCESSED_DATA_DIR, 'test_raw.csv'), index=False)
    print(f"\n✅ Raw datasets saved to: {PROCESSED_DATA_DIR}")

    return train_df, test_df


def step_2_feature_engineering():
    """Run the feature engineering pipeline."""
    print("\n" + "━" * 60)
    print("⚙️  STEP 2: Feature Engineering")
    print("━" * 60)

    from src.feature_engineering import load_processed_data, prepare_features, save_prepared_data

    train_df, test_df = load_processed_data()
    data_dict = prepare_features(train_df, test_df)
    save_prepared_data(data_dict)

    print("\n✅ Feature engineering complete!")
    return data_dict


def step_3_model_training():
    """Train Random Forest & Deep Neural Network models."""
    print("\n" + "━" * 60)
    print("🧠 STEP 3: Model Training (Random Forest + Deep Neural Network)")
    print("━" * 60)

    from src.model_training import (
        load_prepared_data, train_random_forest, train_neural_network, save_models
    )

    data = load_prepared_data()
    metrics_all = {}

    # ─── Binary Classification ───
    print("\n🔴 Binary Classification: Normal vs Attack")
    rf_binary, rf_binary_metrics = train_random_forest(
        data['X_train'], data['y_train_binary'],
        data['X_test'], data['y_test_binary'],
        class_names=['Normal', 'Attack'],
        task_name='binary'
    )
    metrics_all['rf_binary'] = rf_binary_metrics

    nn_binary, nn_binary_metrics, _ = train_neural_network(
        data['X_train'], data['y_train_binary'],
        data['X_test'], data['y_test_binary'],
        class_names=['Normal', 'Attack'],
        task_name='binary'
    )
    if nn_binary_metrics:
        metrics_all['nn_binary'] = nn_binary_metrics

    # ─── Multi-class Classification ───
    print("\n🟠 Multi-class Classification: Attack Categories")
    class_names = list(data['category_encoder'].classes_)
    print(f"  Classes: {class_names}")

    rf_multi, rf_multi_metrics = train_random_forest(
        data['X_train'], data['y_train_multi'],
        data['X_test'], data['y_test_multi'],
        class_names=class_names,
        task_name='multi'
    )
    metrics_all['rf_multi'] = rf_multi_metrics

    nn_multi, nn_multi_metrics, _ = train_neural_network(
        data['X_train'], data['y_train_multi'],
        data['X_test'], data['y_test_multi'],
        class_names=class_names,
        task_name='multi'
    )
    if nn_multi_metrics:
        metrics_all['nn_multi'] = nn_multi_metrics

    # Save all models
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

    return metrics_all


def step_4_anomaly_detection():
    """Train Isolation Forest for anomaly detection."""
    print("\n" + "━" * 60)
    print("🌲 STEP 4: Anomaly Detection (Isolation Forest)")
    print("━" * 60)

    from src.anomaly_detection import (
        load_data, train_isolation_forest,
        compute_anomaly_scores, evaluate_anomaly_detection,
        save_anomaly_model
    )

    X_train, X_test, y_train, y_test = load_data()
    iso_forest = train_isolation_forest(X_train, y_train)

    print("\n🔍 Computing anomaly scores on test data...")
    y_pred, anomaly_scores = compute_anomaly_scores(iso_forest, X_test)

    metrics = evaluate_anomaly_detection(y_test, y_pred, anomaly_scores)
    save_anomaly_model(iso_forest, metrics)

    print("\n✅ Anomaly detection training complete!")
    return metrics


def step_5_launch_api():
    """Launch the Flask API and dashboard."""
    print("\n" + "━" * 60)
    print("🌐 STEP 5: Launching API Server & Dashboard")
    print("━" * 60)

    from src.api import app

    port = int(os.environ.get('PORT', 5050))
    print(f"\n📂 Dashboard: {app.static_folder}")
    print(f"🌐 Open: http://localhost:{port}")
    print(f"📡 API:  http://localhost:{port}/api/status")
    print("━" * 60)

    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)


def step_6_verify():
    """Run the automated integration & debug verification suite."""
    print("\n" + "━" * 60)
    print("🧪 STEP 6: Running Automated Verification & Debug Suite")
    print("━" * 60)
    import unittest
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.join(BASE_DIR, 'tests'))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if not result.wasSuccessful():
        sys.exit(1)
    print("\n✅ All system verification & debug checks passed!")


def main():
    parser = argparse.ArgumentParser(
        description='AI Cybersecurity Threat Detection — Pipeline Runner'
    )
    parser.add_argument('--train', action='store_true',
                        help='Run training pipeline only (no API)')
    parser.add_argument('--api', action='store_true',
                        help='Launch API only (assumes models exist)')
    parser.add_argument('--verify', action='store_true',
                        help='Run automated system verification & debug suite')
    args = parser.parse_args()

    print_banner()

    start_time = time.time()

    if args.verify:
        step_6_verify()
    elif args.api:
        # API only mode
        step_5_launch_api()
    else:
        # Full pipeline
        step_1_data_ingestion()
        step_2_feature_engineering()
        step_3_model_training()
        step_4_anomaly_detection()
        step_6_verify()

        elapsed = time.time() - start_time
        print(f"\n🎉 Full pipeline completed in {elapsed:.1f} seconds!")

        if not args.train:
            print("\nLaunching API server...\n")
            step_5_launch_api()
        else:
            print("\n✅ Training complete. Run with --api to start the server.")


if __name__ == '__main__':
    main()
