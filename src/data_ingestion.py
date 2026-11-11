"""
Data Ingestion Module
=====================
Downloads and loads the NSL-KDD dataset for network intrusion detection.
The NSL-KDD dataset contains 41 features per network connection and
classifies traffic into Normal, DoS, Probe, R2L, and U2R categories.
"""

import os
import warnings
warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL")
import pandas as pd
import requests
import sys

# Column names for the NSL-KDD dataset (41 features + class + difficulty)
COLUMN_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate', 'label', 'difficulty_level'
]

# NSL-KDD download URLs (from the Canadian Institute for Cybersecurity)
DATASET_URLS = {
    'train': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt',
    'test': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt',
}

# Attack type to category mapping
ATTACK_CATEGORY_MAP = {
    # Normal
    'normal': 'Normal',
    # DoS attacks
    'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS', 'pod': 'DoS',
    'smurf': 'DoS', 'teardrop': 'DoS', 'apache2': 'DoS', 'udpstorm': 'DoS',
    'processtable': 'DoS', 'mailbomb': 'DoS',
    # Probe attacks
    'satan': 'Probe', 'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe',
    'mscan': 'Probe', 'saint': 'Probe',
    # R2L attacks (Remote to Local)
    'guess_passwd': 'R2L', 'ftp_write': 'R2L', 'imap': 'R2L', 'phf': 'R2L',
    'multihop': 'R2L', 'warezmaster': 'R2L', 'warezclient': 'R2L', 'spy': 'R2L',
    'xlock': 'R2L', 'xsnoop': 'R2L', 'snmpguess': 'R2L', 'snmpgetattack': 'R2L',
    'httptunnel': 'R2L', 'sendmail': 'R2L', 'named': 'R2L', 'worm': 'R2L',
    # U2R attacks (User to Root)
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'rootkit': 'U2R',
    'perl': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R', 'ps': 'U2R',
    'httptunnel': 'R2L',
}

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DATA_DIR = os.path.join(BASE_DIR, 'data', 'raw')
PROCESSED_DATA_DIR = os.path.join(BASE_DIR, 'data', 'processed')


def ensure_directories():
    """Create necessary data directories if they don't exist."""
    os.makedirs(RAW_DATA_DIR, exist_ok=True)
    os.makedirs(PROCESSED_DATA_DIR, exist_ok=True)
    print(f"✅ Data directories ready: {RAW_DATA_DIR}")


def download_dataset():
    """Download the NSL-KDD dataset files."""
    ensure_directories()

    for name, url in DATASET_URLS.items():
        filepath = os.path.join(RAW_DATA_DIR, f'KDD{name.capitalize()}+.txt')

        if os.path.exists(filepath):
            print(f"📁 {name} dataset already exists at: {filepath}")
            continue

        print(f"⬇️  Downloading {name} dataset from: {url}")
        try:
            response = requests.get(url, timeout=60)
            response.raise_for_status()

            with open(filepath, 'w') as f:
                f.write(response.text)

            print(f"✅ {name} dataset saved to: {filepath}")
        except requests.exceptions.RequestException as e:
            print(f"❌ Failed to download {name} dataset: {e}")
            print(f"   Please manually download from: {url}")
            print(f"   And place it at: {filepath}")
            return False

    return True


def load_dataset(dataset_type='train'):
    """
    Load the NSL-KDD dataset into a pandas DataFrame.
    
    Parameters:
        dataset_type: 'train' or 'test'
    
    Returns:
        pd.DataFrame with the loaded dataset
    """
    filename = f'KDD{dataset_type.capitalize()}+.txt'
    filepath = os.path.join(RAW_DATA_DIR, filename)

    if not os.path.exists(filepath):
        print(f"⚠️  Dataset not found at {filepath}. Attempting to download...")
        if not download_dataset():
            raise FileNotFoundError(f"Cannot load dataset: {filepath}")

    print(f"📂 Loading {dataset_type} dataset from: {filepath}")

    df = pd.read_csv(filepath, names=COLUMN_NAMES, header=None)

    # Map specific attack labels to categories
    df['attack_category'] = df['label'].str.strip().str.lower().map(ATTACK_CATEGORY_MAP)

    # Handle unknown attack types — classify as 'Unknown'
    df['attack_category'] = df['attack_category'].fillna('Unknown')

    # Create binary label: 0 = Normal, 1 = Attack
    df['is_attack'] = (df['attack_category'] != 'Normal').astype(int)

    print(f"✅ Loaded {len(df)} records with {len(df.columns)} columns")
    print(f"\n📊 Class distribution:")
    print(df['attack_category'].value_counts().to_string())

    return df


def get_data_summary(df):
    """
    Print a summary of the loaded dataset.
    
    Parameters:
        df: pandas DataFrame with the loaded dataset
    """
    print("\n" + "=" * 60)
    print("📋 DATASET SUMMARY")
    print("=" * 60)
    print(f"Total records:    {len(df):,}")
    print(f"Total features:   {len(df.columns)}")
    print(f"Normal traffic:   {len(df[df['is_attack'] == 0]):,} ({len(df[df['is_attack'] == 0]) / len(df) * 100:.1f}%)")
    print(f"Attack traffic:   {len(df[df['is_attack'] == 1]):,} ({len(df[df['is_attack'] == 1]) / len(df) * 100:.1f}%)")
    print(f"\n📊 Attack Categories:")
    for category, count in df['attack_category'].value_counts().items():
        pct = count / len(df) * 100
        print(f"  {category:10s}: {count:6,} ({pct:5.1f}%)")

    print(f"\n📊 Protocol Types:")
    print(df['protocol_type'].value_counts().to_string())
    print(f"\n📊 Top 10 Services:")
    print(df['service'].value_counts().head(10).to_string())
    print("=" * 60)


if __name__ == '__main__':
    print("🛡️  AI-Based Cybersecurity Threat Detection")
    print("   Phase 1: Data Ingestion")
    print("-" * 45)

    # Download dataset
    success = download_dataset()
    if not success:
        sys.exit(1)

    # Load training data
    train_df = load_dataset('train')
    get_data_summary(train_df)

    # Load test data
    test_df = load_dataset('test')
    get_data_summary(test_df)

    # Save as CSV for easier access
    train_df.to_csv(os.path.join(PROCESSED_DATA_DIR, 'train_raw.csv'), index=False)
    test_df.to_csv(os.path.join(PROCESSED_DATA_DIR, 'test_raw.csv'), index=False)
    print(f"\n✅ Raw datasets saved to: {PROCESSED_DATA_DIR}")
