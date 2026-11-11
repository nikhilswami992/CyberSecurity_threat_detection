"""
Threat Classifier Module
========================
Unified threat classification interface that combines supervised models
(Random Forest, Neural Network) with unsupervised anomaly detection
(Isolation Forest) for comprehensive threat assessment.

Provides:
- Multi-model threat scoring
- Threat severity levels (Critical, High, Medium, Low, Info)
- Confidence-weighted ensemble predictions
- Automated response recommendations
"""

import os
import sys
import json
import numpy as np
import pandas as pd
import joblib

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, 'models', 'saved')

# Threat severity mapping
SEVERITY_MAP = {
    'DoS': 'Critical',
    'U2R': 'Critical',
    'R2L': 'High',
    'Probe': 'Medium',
    'Normal': 'Info',
    'Unknown': 'High',
}

# Automated response recommendations
RESPONSE_MAP = {
    'Critical': {
        'action': 'BLOCK_IMMEDIATELY',
        'description': 'Block source IP, isolate affected hosts, alert SOC team',
        'auto_block': True,
    },
    'High': {
        'action': 'INVESTIGATE_URGENT',
        'description': 'Flag for immediate investigation, increase monitoring',
        'auto_block': False,
    },
    'Medium': {
        'action': 'MONITOR_CLOSELY',
        'description': 'Add to watchlist, increase logging, schedule review',
        'auto_block': False,
    },
    'Low': {
        'action': 'LOG_AND_WATCH',
        'description': 'Log the event, continue passive monitoring',
        'auto_block': False,
    },
    'Info': {
        'action': 'NONE',
        'description': 'Normal traffic — no action required',
        'auto_block': False,
    },
}


class ThreatClassifier:
    """
    Unified threat classifier combining multiple models.
    
    Attributes:
        rf_binary: Random Forest for binary classification
        rf_multi: Random Forest for multi-class classification
        iso_forest: Isolation Forest for anomaly detection
        scaler: Feature scaler
        encoders: Categorical encoders
        category_encoder: Label encoder for attack categories
    """

    def __init__(self):
        self.rf_binary = None
        self.rf_multi = None
        self.nn_binary = None
        self.nn_multi = None
        self.iso_forest = None
        self.scaler = None
        self.encoders = None
        self.category_encoder = None
        self.feature_names = None
        self.metrics = None
        self.loaded = False

    def load_models(self):
        """Load all trained models from disk."""
        print("📂 Loading trained models...")

        try:
            # Load Random Forest models
            rf_binary_path = os.path.join(MODELS_DIR, 'rf_binary.pkl')
            if os.path.exists(rf_binary_path):
                self.rf_binary = joblib.load(rf_binary_path)
                print("  ✅ Random Forest (binary)")

            rf_multi_path = os.path.join(MODELS_DIR, 'rf_multi.pkl')
            if os.path.exists(rf_multi_path):
                self.rf_multi = joblib.load(rf_multi_path)
                print("  ✅ Random Forest (multi-class)")

            # Load Deep Neural Network models (.pkl MLP or .keras)
            nn_bin_pkl = os.path.join(MODELS_DIR, 'nn_binary.pkl')
            nn_mul_pkl = os.path.join(MODELS_DIR, 'nn_multi.pkl')
            if os.path.exists(nn_bin_pkl):
                self.nn_binary = joblib.load(nn_bin_pkl)
                print("  ✅ Deep Neural Network (binary)")
            if os.path.exists(nn_mul_pkl):
                self.nn_multi = joblib.load(nn_mul_pkl)
                print("  ✅ Deep Neural Network (multi-class)")

            if self.nn_binary is None:
                try:
                    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
                    import tensorflow as tf
                    nn_binary_path = os.path.join(MODELS_DIR, 'nn_binary.keras')
                    if os.path.exists(nn_binary_path):
                        self.nn_binary = tf.keras.models.load_model(nn_binary_path)
                        print("  ✅ Neural Network (binary)")

                    nn_multi_path = os.path.join(MODELS_DIR, 'nn_multi.keras')
                    if os.path.exists(nn_multi_path):
                        self.nn_multi = tf.keras.models.load_model(nn_multi_path)
                        print("  ✅ Neural Network (multi-class)")
                except Exception:
                    print("  ⚠️  TensorFlow runtime unavailable — using MLP DNN artifacts")

            # Load Isolation Forest
            iso_path = os.path.join(MODELS_DIR, 'isolation_forest.pkl')
            if os.path.exists(iso_path):
                self.iso_forest = joblib.load(iso_path)
                print("  ✅ Isolation Forest (anomaly)")

            # Load transformers
            self.scaler = joblib.load(os.path.join(MODELS_DIR, 'scaler.pkl'))
            self.encoders = joblib.load(os.path.join(MODELS_DIR, 'encoders.pkl'))
            self.category_encoder = joblib.load(os.path.join(MODELS_DIR, 'category_encoder.pkl'))
            print("  ✅ Scaler & Encoders")

            # Load feature names
            fn_path = os.path.join(BASE_DIR, 'data', 'processed', 'feature_names.csv')
            if os.path.exists(fn_path):
                self.feature_names = pd.read_csv(fn_path).iloc[:, 0].tolist()
                print("  ✅ Feature Names")

            # Load metrics
            metrics_path = os.path.join(MODELS_DIR, 'metrics.json')
            if os.path.exists(metrics_path):
                with open(metrics_path, 'r') as f:
                    self.metrics = json.load(f)

            self.loaded = True
            print("✅ All models loaded successfully!")

        except FileNotFoundError as e:
            print(f"❌ Model not found: {e}")
            print("   Run model_training.py and anomaly_detection.py first!")

    def classify_threat(self, features):
        """
        Classify a single network connection using ensemble of models.
        
        Parameters:
            features: numpy array of preprocessed features (1D or 2D)
        
        Returns:
            Dictionary with classification results including:
            - is_attack: Boolean
            - attack_category: String (Normal, DoS, Probe, R2L, U2R)
            - severity: String (Critical, High, Medium, Low, Info)
            - confidence: Float (0-1)
            - anomaly_score: Float (0-1)
            - response: Recommended response action
            - model_votes: Individual model predictions
        """
        if not self.loaded:
            self.load_models()

        if features.ndim == 1:
            features = features.reshape(1, -1)

        result = {
            'model_votes': {},
            'confidence': 0.0,
        }

        # ─── Random Forest Binary ───
        if self.rf_binary is not None:
            rf_bin_pred = self.rf_binary.predict(features)[0]
            rf_bin_prob = self.rf_binary.predict_proba(features)[0]
            result['model_votes']['rf_binary'] = {
                'prediction': int(rf_bin_pred),
                'confidence': float(max(rf_bin_prob)),
            }

        # ─── Random Forest Multi-class ───
        if self.rf_multi is not None:
            rf_multi_pred = self.rf_multi.predict(features)[0]
            rf_multi_prob = self.rf_multi.predict_proba(features)[0]
            category = self.category_encoder.inverse_transform([rf_multi_pred])[0]
            result['model_votes']['rf_multi'] = {
                'prediction': category,
                'confidence': float(max(rf_multi_prob)),
            }

        # ─── Neural Network Binary ───
        if self.nn_binary is not None:
            if hasattr(self.nn_binary, 'predict_proba'):
                nn_bin_pred = int(self.nn_binary.predict(features)[0])
                nn_bin_prob = float(max(self.nn_binary.predict_proba(features)[0]))
                result['model_votes']['nn_binary'] = {
                    'prediction': nn_bin_pred,
                    'confidence': nn_bin_prob,
                }
            else:
                nn_bin_prob = self.nn_binary.predict(features, verbose=0)[0][0]
                result['model_votes']['nn_binary'] = {
                    'prediction': int(nn_bin_prob > 0.5),
                    'confidence': float(max(nn_bin_prob, 1 - nn_bin_prob)),
                }

        # ─── Neural Network Multi-class ───
        if self.nn_multi is not None:
            if hasattr(self.nn_multi, 'predict_proba'):
                nn_multi_pred = self.nn_multi.predict(features)[0]
                nn_multi_prob = self.nn_multi.predict_proba(features)[0]
                category_nn = self.category_encoder.inverse_transform([nn_multi_pred])[0]
                result['model_votes']['nn_multi'] = {
                    'prediction': category_nn,
                    'confidence': float(max(nn_multi_prob)),
                }
            else:
                nn_multi_prob = self.nn_multi.predict(features, verbose=0)[0]
                nn_multi_pred = np.argmax(nn_multi_prob)
                category_nn = self.category_encoder.inverse_transform([nn_multi_pred])[0]
                result['model_votes']['nn_multi'] = {
                    'prediction': category_nn,
                    'confidence': float(max(nn_multi_prob)),
                }

        # ─── Isolation Forest Anomaly ───
        if self.iso_forest is not None:
            raw_score = self.iso_forest.decision_function(features)[0]
            iso_pred = self.iso_forest.predict(features)[0]
            # Normalize: lower decision_function = more anomalous
            anomaly_score = max(0, min(1, 0.5 - raw_score))
            result['anomaly_score'] = float(anomaly_score)
            result['model_votes']['isolation_forest'] = {
                'prediction': 'Anomaly' if iso_pred == -1 else 'Normal',
                'anomaly_score': float(anomaly_score),
            }
        else:
            result['anomaly_score'] = 0.0

        # ─── Ensemble Decision ───
        result = self._ensemble_decision(result)

        return result

    def _ensemble_decision(self, result):
        """Combine model votes into final decision with weighted confidence."""
        votes = result['model_votes']

        # Binary attack votes
        binary_attack_votes = []
        binary_confidences = []

        for key in ['rf_binary', 'nn_binary']:
            if key in votes:
                binary_attack_votes.append(votes[key]['prediction'])
                binary_confidences.append(votes[key]['confidence'])

        # Consider anomaly detection
        if 'isolation_forest' in votes:
            iso_vote = 1 if votes['isolation_forest']['prediction'] == 'Anomaly' else 0
            binary_attack_votes.append(iso_vote)
            binary_confidences.append(votes['isolation_forest'].get('anomaly_score', 0.5))

        # Multi-class category detection
        multi_is_attack = False
        multi_category = 'Normal'
        if 'rf_multi' in votes:
            multi_category = votes['rf_multi']['prediction']
            multi_is_attack = (multi_category != 'Normal')
        elif 'nn_multi' in votes:
            multi_category = votes['nn_multi']['prediction']
            multi_is_attack = (multi_category != 'Normal')

        # Majority vote for binary combined with multi-class prediction
        if binary_attack_votes:
            attack_ratio = sum(binary_attack_votes) / len(binary_attack_votes)
            result['is_attack'] = bool(multi_is_attack or attack_ratio >= 0.5)
            result['confidence'] = float(np.mean(binary_confidences))
        else:
            result['is_attack'] = bool(multi_is_attack)
            result['confidence'] = 0.0

        if result['is_attack']:
            result['attack_category'] = multi_category if multi_is_attack else 'Attack'
        else:
            result['attack_category'] = 'Normal'

        # Severity & Response
        result['severity'] = SEVERITY_MAP.get(result['attack_category'], 'Medium')
        result['response'] = RESPONSE_MAP.get(result['severity'], RESPONSE_MAP['Medium'])

        return result

    def classify_batch(self, X):
        """
        Classify a batch of network connections.
        
        Parameters:
            X: 2D numpy array of features
        
        Returns:
            List of classification result dictionaries
        """
        results = []
        for i in range(len(X)):
            result = self.classify_threat(X[i])
            results.append(result)
        return results

    def classify_raw_connection(self, raw_conn):
        """
        Classify a raw network connection dictionary with arbitrary fields.
        Fills missing fields with standard defaults, computes derived features,
        encodes categorical attributes, scales features, and runs multi-model inference.

        Parameters:
            raw_conn: Dictionary containing network connection attributes

        Returns:
            Dictionary with classification, anomaly scores, model votes, and explainability indicators
        """
        if not self.loaded:
            self.load_models()

        defaults = {
            'duration': 0.0, 'protocol_type': 'tcp', 'service': 'http', 'flag': 'SF',
            'src_bytes': 0.0, 'dst_bytes': 0.0, 'land': 0.0, 'wrong_fragment': 0.0,
            'urgent': 0.0, 'hot': 0.0, 'num_failed_logins': 0.0, 'logged_in': 0.0,
            'num_compromised': 0.0, 'root_shell': 0.0, 'su_attempted': 0.0, 'num_root': 0.0,
            'num_file_creations': 0.0, 'num_shells': 0.0, 'num_access_files': 0.0,
            'num_outbound_cmds': 0.0, 'is_host_login': 0.0, 'is_guest_login': 0.0,
            'count': 1.0, 'srv_count': 1.0, 'serror_rate': 0.0, 'srv_serror_rate': 0.0,
            'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 1.0,
            'dst_host_srv_count': 1.0, 'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0
        }

        # Override defaults with provided raw connection values
        for k, v in raw_conn.items():
            if k in defaults:
                if isinstance(defaults[k], float) or isinstance(defaults[k], int):
                    try:
                        defaults[k] = float(v)
                    except (ValueError, TypeError):
                        pass
                else:
                    defaults[k] = str(v)

        # Smart heuristic correlations when partial form attributes are provided
        if 'flag' in raw_conn and raw_conn.get('flag') == 'S0':
            if 'serror_rate' not in raw_conn:
                defaults['serror_rate'] = 1.0
            if 'srv_serror_rate' not in raw_conn:
                defaults['srv_serror_rate'] = 1.0
            if 'dst_host_serror_rate' not in raw_conn:
                defaults['dst_host_serror_rate'] = 1.0
            if 'dst_host_srv_serror_rate' not in raw_conn:
                defaults['dst_host_srv_serror_rate'] = 1.0
            if 'dst_host_count' not in raw_conn and defaults['count'] > 50:
                defaults['dst_host_count'] = 255.0
                defaults['dst_host_srv_count'] = min(25.0, defaults['srv_count'])
                defaults['same_srv_rate'] = 0.06
                defaults['diff_srv_rate'] = 0.06
                defaults['dst_host_same_srv_rate'] = 0.06
                defaults['dst_host_diff_srv_rate'] = 0.07

        if 'flag' in raw_conn and raw_conn.get('flag') in ('REJ', 'RSTO'):
            if 'rerror_rate' not in raw_conn:
                defaults['rerror_rate'] = 1.0
            if 'srv_rerror_rate' not in raw_conn:
                defaults['srv_rerror_rate'] = 1.0
            if 'dst_host_rerror_rate' not in raw_conn:
                defaults['dst_host_rerror_rate'] = 1.0
            if 'dst_host_srv_rerror_rate' not in raw_conn:
                defaults['dst_host_srv_rerror_rate'] = 1.0
            if raw_conn.get('flag') == 'REJ' and defaults['count'] > 20:
                if 'diff_srv_rate' not in raw_conn:
                    defaults['diff_srv_rate'] = 0.85
                if 'dst_host_count' not in raw_conn:
                    defaults['dst_host_count'] = 255.0
                if 'dst_host_diff_srv_rate' not in raw_conn:
                    defaults['dst_host_diff_srv_rate'] = 0.75

        if defaults['num_failed_logins'] > 0:
            if 'hot' not in raw_conn:
                defaults['hot'] = max(1.0, defaults['num_failed_logins'])
            if 'dst_host_count' not in raw_conn:
                defaults['dst_host_count'] = 4.0
            if 'dst_host_srv_count' not in raw_conn:
                defaults['dst_host_srv_count'] = 4.0
            if defaults['flag'] in ('RSTO', 'REJ'):
                defaults['rerror_rate'] = 1.0
                defaults['srv_rerror_rate'] = 1.0
                defaults['dst_host_rerror_rate'] = 1.0
                defaults['dst_host_srv_rerror_rate'] = 1.0

        if defaults['root_shell'] > 0:
            if 'logged_in' not in raw_conn:
                defaults['logged_in'] = 1.0
            if 'num_root' not in raw_conn:
                defaults['num_root'] = 14.0
            if 'num_compromised' not in raw_conn:
                defaults['num_compromised'] = 5.0
            if 'num_file_creations' not in raw_conn:
                defaults['num_file_creations'] = 1.0
            if 'hot' not in raw_conn:
                defaults['hot'] = 2.0
            if 'dst_host_count' not in raw_conn:
                defaults['dst_host_count'] = 255.0
            if 'dst_host_srv_count' not in raw_conn:
                defaults['dst_host_srv_count'] = 4.0

        df = pd.DataFrame([defaults])

        # Compute derived features
        df['bytes_ratio'] = np.where(df['dst_bytes'] > 0, df['src_bytes'] / (df['dst_bytes'] + 1), df['src_bytes'])
        df['traffic_intensity'] = (df['src_bytes'] + df['dst_bytes']) / (df['duration'] + 1)
        df['srv_diversity'] = np.where(df['count'] > 0, df['srv_count'] / (df['count'] + 1), 0)
        df['total_error_rate'] = df['serror_rate'] + df['rerror_rate']
        df['host_srv_concentration'] = np.where(df['dst_host_count'] > 0, df['dst_host_srv_count'] / (df['dst_host_count'] + 1), 0)
        df['is_error_flag'] = df['flag'].isin(['S0', 'REJ', 'RSTO', 'RSTOS0', 'S1', 'S2', 'S3']).astype(int)
        df['suspicious_activity'] = (
            df['hot'] + df['num_failed_logins'] + df['num_compromised'] +
            df['root_shell'] + df['su_attempted'] + df['num_root']
        )

        # Categorical encoding
        for col in ['protocol_type', 'service', 'flag']:
            if self.encoders and col in self.encoders:
                le = self.encoders[col]
                val = str(df[col].iloc[0])
                df[col + '_encoded'] = le.transform([val])[0] if val in le.classes_ else 0
            else:
                df[col + '_encoded'] = 0

        # Scale features
        if self.feature_names and self.scaler:
            feat_df = df[self.feature_names]
            scaled_vals = self.scaler.transform(feat_df)
        else:
            scaled_vals = np.zeros((1, 48))

        # Run multi-model classification
        result = self.classify_threat(scaled_vals)

        # Explainability key indicators
        indicators = []
        if defaults['count'] > 100:
            indicators.append(f"High connection burst ({int(defaults['count'])} pkts/window)")
        if df['total_error_rate'].iloc[0] > 0.4:
            indicators.append(f"Elevated SYN/REJ error rate ({(df['total_error_rate'].iloc[0]*100):.1f}%)")
        if df['is_error_flag'].iloc[0] == 1:
            indicators.append(f"Abnormal TCP connection status flag '{defaults['flag']}'")
        if defaults['num_failed_logins'] > 0:
            indicators.append(f"Failed authentication attempts ({int(defaults['num_failed_logins'])})")
        if defaults['root_shell'] > 0 or defaults['num_root'] > 0:
            indicators.append("Privileged execution / root access attempt")
        if defaults['duration'] == 0 and defaults['src_bytes'] == 0:
            indicators.append("Zero-byte payload / stealth port scan signature")
        if df['bytes_ratio'].iloc[0] > 50:
            indicators.append("High egress data ratio (potential exfiltration)")
        if not indicators:
            indicators.append("Traffic pattern conforms to baseline operational behavior")

        result['key_indicators'] = indicators
        result['raw_features'] = {
            'protocol': defaults['protocol_type'],
            'service': defaults['service'],
            'flag': defaults['flag'],
            'duration': defaults['duration'],
            'src_bytes': defaults['src_bytes'],
            'dst_bytes': defaults['dst_bytes'],
            'count': defaults['count'],
        }

        return result

    def get_model_summary(self):
        """Return a summary of loaded models and their metrics."""
        summary = {
            'models_loaded': {
                'rf_binary': self.rf_binary is not None,
                'rf_multi': self.rf_multi is not None,
                'nn_binary': self.nn_binary is not None,
                'nn_multi': self.nn_multi is not None,
                'isolation_forest': self.iso_forest is not None,
            },
            'metrics': self.metrics or {},
        }
        return summary


if __name__ == '__main__':
    print("🛡️  AI-Based Cybersecurity Threat Detection")
    print("   Threat Classifier — Test Run")
    print("-" * 45)

    classifier = ThreatClassifier()
    classifier.load_models()

    # Load test data for demo
    from src.data_ingestion import PROCESSED_DATA_DIR as DATA_DIR
    X_test = np.load(os.path.join(DATA_DIR, 'X_test.npy'))
    y_test = np.load(os.path.join(DATA_DIR, 'y_test_binary.npy'))

    # Classify a few samples
    print("\n📋 Sample Classifications:")
    for i in range(min(10, len(X_test))):
        result = classifier.classify_threat(X_test[i])
        actual = "Attack" if y_test[i] == 1 else "Normal"
        predicted = result['attack_category']
        severity = result['severity']
        confidence = result['confidence']
        anomaly = result['anomaly_score']

        status = "✅" if (result['is_attack'] == (y_test[i] == 1)) else "❌"
        print(f"  {status} Sample {i+1}: Actual={actual:7s} → "
              f"Predicted={predicted:8s} | Severity={severity:8s} | "
              f"Confidence={confidence:.2f} | Anomaly={anomaly:.2f}")

    print(f"\n📊 Model Summary:")
    summary = classifier.get_model_summary()
    for model, loaded in summary['models_loaded'].items():
        print(f"  {'✅' if loaded else '❌'} {model}")
