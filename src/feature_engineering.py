"""
Feature Engineering Module
==========================
Extracts, transforms, and prepares features from the NSL-KDD dataset 
for machine learning model training.

Features include:
- Encoding categorical variables (protocol_type, service, flag)
- Normalizing numerical features  
- Creating derived features (traffic ratios, connection patterns)
- Splitting data into train/test sets
"""

import os
import sys
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
import joblib

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROCESSED_DATA_DIR = os.path.join(BASE_DIR, 'data', 'processed')
MODELS_DIR = os.path.join(BASE_DIR, 'models', 'saved')

# Categorical columns in NSL-KDD
CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']

# Numerical columns (all except categorical, label, and metadata columns)
METADATA_COLS = ['label', 'difficulty_level', 'attack_category', 'is_attack']

# Key numerical features for analysis
KEY_NUMERICAL_FEATURES = [
    'duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count',
    'serror_rate', 'rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_serror_rate', 'dst_host_rerror_rate'
]


def load_processed_data():
    """Load the raw processed datasets."""
    train_path = os.path.join(PROCESSED_DATA_DIR, 'train_raw.csv')
    test_path = os.path.join(PROCESSED_DATA_DIR, 'test_raw.csv')

    if not os.path.exists(train_path) or not os.path.exists(test_path):
        print("⚠️  Raw processed data not found. Running data ingestion first...")
        from src.data_ingestion import download_dataset, load_dataset
        download_dataset()
        train_df = load_dataset('train')
        test_df = load_dataset('test')
        train_df.to_csv(train_path, index=False)
        test_df.to_csv(test_path, index=False)
    else:
        train_df = pd.read_csv(train_path)
        test_df = pd.read_csv(test_path)

    print(f"✅ Loaded training data: {train_df.shape}")
    print(f"✅ Loaded test data: {test_df.shape}")
    return train_df, test_df


def create_derived_features(df):
    """
    Create additional derived features that capture network behavior patterns.
    
    Parameters:
        df: Input DataFrame
    
    Returns:
        DataFrame with additional derived features
    """
    df = df.copy()

    # Traffic volume ratio (bytes sent vs received)
    df['bytes_ratio'] = np.where(
        df['dst_bytes'] > 0,
        df['src_bytes'] / (df['dst_bytes'] + 1),
        df['src_bytes']
    )

    # Connection intensity (total bytes per unit time)
    df['traffic_intensity'] = (df['src_bytes'] + df['dst_bytes']) / (df['duration'] + 1)

    # Service diversity ratio
    df['srv_diversity'] = np.where(
        df['count'] > 0,
        df['srv_count'] / (df['count'] + 1),
        0
    )

    # Error rate combination (total error indicators)
    df['total_error_rate'] = df['serror_rate'] + df['rerror_rate']

    # Host service concentration
    df['host_srv_concentration'] = np.where(
        df['dst_host_count'] > 0,
        df['dst_host_srv_count'] / (df['dst_host_count'] + 1),
        0
    )

    # Flag-based features
    df['is_error_flag'] = df['flag'].isin(['S0', 'REJ', 'RSTO', 'RSTOS0', 'S1', 'S2', 'S3']).astype(int)

    # Hot indicator (composite of suspicious activities)
    df['suspicious_activity'] = (
        df['hot'] + df['num_failed_logins'] + df['num_compromised'] +
        df['root_shell'] + df['su_attempted'] + df['num_root']
    )

    print(f"✅ Created {7} derived features")
    return df


def encode_categorical_features(train_df, test_df):
    """
    Encode categorical features using Label Encoding.
    Fits encoders on training data and transforms both train and test.
    
    Parameters:
        train_df: Training DataFrame
        test_df: Test DataFrame
    
    Returns:
        Tuple of (encoded_train_df, encoded_test_df, encoders_dict)
    """
    encoders = {}
    train_df = train_df.copy()
    test_df = test_df.copy()

    for col in CATEGORICAL_COLS:
        le = LabelEncoder()

        # Fit on combined unique values to handle unseen categories in test
        combined_values = pd.concat([train_df[col], test_df[col]]).unique()
        le.fit(combined_values)

        train_df[col + '_encoded'] = le.transform(train_df[col])
        test_df[col + '_encoded'] = le.transform(test_df[col])

        encoders[col] = le
        print(f"  📊 Encoded '{col}': {len(le.classes_)} unique values")

    print(f"✅ Categorical encoding complete")
    return train_df, test_df, encoders


def normalize_features(train_df, test_df, feature_columns):
    """
    Normalize numerical features using Min-Max scaling.
    Fits scaler on training data and transforms both sets.
    
    Parameters:
        train_df: Training DataFrame
        test_df: Test DataFrame
        feature_columns: List of columns to normalize
    
    Returns:
        Tuple of (normalized_train, normalized_test, scaler)
    """
    scaler = MinMaxScaler()

    train_df = train_df.copy()
    test_df = test_df.copy()

    train_df[feature_columns] = scaler.fit_transform(train_df[feature_columns])
    test_df[feature_columns] = scaler.transform(test_df[feature_columns])

    print(f"✅ Normalized {len(feature_columns)} features using MinMaxScaler")
    return train_df, test_df, scaler


def prepare_features(train_df, test_df):
    """
    Complete feature preparation pipeline.
    
    Steps:
    1. Create derived features
    2. Encode categorical variables
    3. Normalize all numerical features
    4. Split into X (features) and y (labels)
    
    Parameters:
        train_df: Raw training DataFrame
        test_df: Raw test DataFrame
    
    Returns:
        Dictionary with X_train, X_test, y_train_binary, y_test_binary,
        y_train_multi, y_test_multi, feature_names, scaler, encoders
    """
    print("\n" + "=" * 60)
    print("⚙️  FEATURE ENGINEERING PIPELINE")
    print("=" * 60)

    # Step 1: Create derived features
    print("\n📐 Step 1: Creating derived features...")
    train_df = create_derived_features(train_df)
    test_df = create_derived_features(test_df)

    # Step 2: Encode categorical features
    print("\n🔤 Step 2: Encoding categorical features...")
    train_df, test_df, encoders = encode_categorical_features(train_df, test_df)

    # Step 3: Define feature columns
    # Get all numerical columns (excluding metadata and original categorical)
    exclude_cols = set(METADATA_COLS + CATEGORICAL_COLS)
    feature_columns = [col for col in train_df.columns if col not in exclude_cols]

    print(f"\n📊 Total features for model: {len(feature_columns)}")

    # Step 4: Normalize features
    print("\n📏 Step 3: Normalizing features...")
    train_df, test_df, scaler = normalize_features(train_df, test_df, feature_columns)

    # Step 5: Prepare X and y arrays
    X_train = train_df[feature_columns].values
    X_test = test_df[feature_columns].values

    # Binary labels (Normal vs Attack)
    y_train_binary = train_df['is_attack'].values
    y_test_binary = test_df['is_attack'].values

    # Multi-class labels (attack categories)
    category_encoder = LabelEncoder()
    y_train_multi = category_encoder.fit_transform(train_df['attack_category'])
    y_test_multi = category_encoder.transform(test_df['attack_category'])

    print(f"\n✅ Feature preparation complete!")
    print(f"   X_train shape: {X_train.shape}")
    print(f"   X_test shape:  {X_test.shape}")
    print(f"   Binary classes: {np.unique(y_train_binary)}")
    print(f"   Multi classes:  {category_encoder.classes_}")
    print("=" * 60)

    return {
        'X_train': X_train,
        'X_test': X_test,
        'y_train_binary': y_train_binary,
        'y_test_binary': y_test_binary,
        'y_train_multi': y_train_multi,
        'y_test_multi': y_test_multi,
        'feature_names': feature_columns,
        'scaler': scaler,
        'encoders': encoders,
        'category_encoder': category_encoder,
        'train_df': train_df,
        'test_df': test_df,
    }


def save_prepared_data(data_dict):
    """Save all prepared data and transformers to disk."""
    os.makedirs(MODELS_DIR, exist_ok=True)

    # Save numpy arrays
    np.save(os.path.join(PROCESSED_DATA_DIR, 'X_train.npy'), data_dict['X_train'])
    np.save(os.path.join(PROCESSED_DATA_DIR, 'X_test.npy'), data_dict['X_test'])
    np.save(os.path.join(PROCESSED_DATA_DIR, 'y_train_binary.npy'), data_dict['y_train_binary'])
    np.save(os.path.join(PROCESSED_DATA_DIR, 'y_test_binary.npy'), data_dict['y_test_binary'])
    np.save(os.path.join(PROCESSED_DATA_DIR, 'y_train_multi.npy'), data_dict['y_train_multi'])
    np.save(os.path.join(PROCESSED_DATA_DIR, 'y_test_multi.npy'), data_dict['y_test_multi'])

    # Save feature names
    pd.Series(data_dict['feature_names']).to_csv(
        os.path.join(PROCESSED_DATA_DIR, 'feature_names.csv'), index=False
    )

    # Save scaler and encoders
    joblib.dump(data_dict['scaler'], os.path.join(MODELS_DIR, 'scaler.pkl'))
    joblib.dump(data_dict['encoders'], os.path.join(MODELS_DIR, 'encoders.pkl'))
    joblib.dump(data_dict['category_encoder'], os.path.join(MODELS_DIR, 'category_encoder.pkl'))

    print(f"\n💾 Saved prepared data to: {PROCESSED_DATA_DIR}")
    print(f"💾 Saved transformers to: {MODELS_DIR}")


if __name__ == '__main__':
    print("🛡️  AI-Based Cybersecurity Threat Detection")
    print("   Phase 1: Feature Engineering")
    print("-" * 45)

    # Load raw data
    train_df, test_df = load_processed_data()

    # Run feature engineering pipeline
    data_dict = prepare_features(train_df, test_df)

    # Save everything
    save_prepared_data(data_dict)

    print("\n🎉 Feature engineering complete! Ready for model training.")
