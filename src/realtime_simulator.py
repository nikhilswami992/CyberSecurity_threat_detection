"""
Real-Time Traffic Simulator
============================
Simulates a live network traffic feed by sampling from the NSL-KDD test dataset.
Generates realistic-looking network connection events with timestamps,
source/destination IPs, and threat classifications.

Used by the API to provide a simulated real-time threat feed to the dashboard.
"""

import os
import time
import random
import threading
import numpy as np
import pandas as pd
from datetime import datetime

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROCESSED_DATA_DIR = os.path.join(BASE_DIR, 'data', 'processed')

# Simulated IP ranges
INTERNAL_IPS = [
    '10.0.1.', '10.0.2.', '10.0.3.', '10.0.4.',
    '192.168.1.', '192.168.2.', '172.16.0.', '172.16.1.'
]

EXTERNAL_IPS = [
    '203.0.113.', '198.51.100.', '185.220.101.', '45.33.32.',
    '91.189.92.', '104.244.42.', '34.107.221.', '52.84.150.',
    '13.107.42.', '23.215.0.', '151.101.1.', '140.82.121.',
]

# Known malicious IPs (for simulation)
MALICIOUS_IPS = [
    '185.220.101.42', '45.33.32.156', '91.189.92.77',
    '203.0.113.200', '198.51.100.99', '185.220.101.11',
]

# Service to port mapping
SERVICE_PORT_MAP = {
    'http': 80, 'https': 443, 'ftp': 21, 'ssh': 22,
    'smtp': 25, 'dns': 53, 'telnet': 23, 'pop3': 110,
    'imap': 143, 'mysql': 3306, 'rdp': 3389, 'snmp': 161,
    'ntp': 123, 'ldap': 389, 'other': 0,
}

# Device names for internal network
DEVICE_NAMES = [
    'web-server-01', 'web-server-02', 'db-server-01', 'db-server-02',
    'mail-server', 'dns-server', 'file-server', 'app-server-01',
    'workstation-101', 'workstation-102', 'workstation-103', 'workstation-104',
    'firewall-gw', 'proxy-server', 'vpn-gateway', 'backup-server',
]


class TrafficSimulator:
    """
    Simulates real-time network traffic for the dashboard feed.
    
    Uses actual NSL-KDD test data to generate realistic traffic events
    with added metadata (IPs, timestamps, device names).
    """

    def __init__(self):
        self._lock = threading.RLock()
        self.test_data = None
        self.current_index = 0
        self.event_counter = 0
        self.blocked_ips = set()
        self.alert_history = []
        self.stats = {
            'total_connections': 0,
            'normal_count': 0,
            'attack_count': 0,
            'blocked_count': 0,
            'categories': {'Normal': 0, 'DoS': 0, 'Probe': 0, 'R2L': 0, 'U2R': 0},
        }

    def load_test_data(self):
        """Load test dataset for simulation."""
        test_path = os.path.join(PROCESSED_DATA_DIR, 'test_raw.csv')

        if os.path.exists(test_path):
            self.test_data = pd.read_csv(test_path)
            # Shuffle for more realistic simulation
            self.test_data = self.test_data.sample(frac=1, random_state=42).reset_index(drop=True)
            print(f"✅ Loaded {len(self.test_data)} test records for simulation")
        else:
            print("⚠️  Test data not found. Using synthetic data.")
            self.test_data = None

    def generate_event(self):
        """
        Generate a single simulated network traffic event.
        
        Returns:
            Dictionary representing a network connection event
        """
        self.event_counter += 1
        self.stats['total_connections'] += 1

        # Use real data if available
        if self.test_data is not None:
            row = self.test_data.iloc[self.current_index % len(self.test_data)]
            self.current_index += 1

            is_attack = bool(row.get('is_attack', 0) == 1)
            category = str(row.get('attack_category', 'Normal'))
            protocol = str(row.get('protocol_type', 'tcp'))
            service = str(row.get('service', 'http'))
            flag = str(row.get('flag', 'SF'))
            duration = int(row.get('duration', 0))
            src_bytes = int(row.get('src_bytes', 0))
            dst_bytes = int(row.get('dst_bytes', 0))
        else:
            # Synthetic generation
            is_attack = random.random() < 0.3
            category = random.choice(['DoS', 'Probe', 'R2L', 'U2R']) if is_attack else 'Normal'
            protocol = random.choice(['tcp', 'udp', 'icmp'])
            service = random.choice(list(SERVICE_PORT_MAP.keys()))
            flag = random.choice(['SF', 'S0', 'REJ', 'RSTO', 'S1'])
            duration = random.randint(0, 5000)
            src_bytes = random.randint(0, 50000)
            dst_bytes = random.randint(0, 50000)

        # Generate realistic IPs
        if is_attack:
            src_ip = random.choice(MALICIOUS_IPS) if random.random() < 0.6 else \
                random.choice(EXTERNAL_IPS) + str(random.randint(1, 254))
        else:
            src_ip = random.choice(INTERNAL_IPS + EXTERNAL_IPS) + str(random.randint(1, 254))

        dst_ip = random.choice(INTERNAL_IPS) + str(random.randint(1, 254))
        dst_port = SERVICE_PORT_MAP.get(service, random.randint(1024, 65535))
        src_port = random.randint(1024, 65535)

        # Check if IP is blocked
        is_blocked = src_ip in self.blocked_ips

        # Update stats
        if is_attack:
            self.stats['attack_count'] += 1
            self.stats['categories'][category] = self.stats['categories'].get(category, 0) + 1
        else:
            self.stats['normal_count'] += 1
            self.stats['categories']['Normal'] += 1

        if is_blocked:
            self.stats['blocked_count'] += 1

        # Severity based on category
        severity_map = {
            'DoS': 'critical', 'U2R': 'critical',
            'R2L': 'high', 'Probe': 'medium',
            'Normal': 'info',
        }
        severity = severity_map.get(category, 'medium')

        # Anomaly score simulation
        if is_attack:
            anomaly_score = random.uniform(0.6, 0.99)
        else:
            anomaly_score = random.uniform(0.01, 0.3)

        # Confidence
        confidence = random.uniform(0.85, 0.99) if is_attack else random.uniform(0.90, 0.99)

        event = {
            'id': f'EVT-{self.event_counter:06d}',
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'service': service,
            'flag': flag,
            'duration': duration,
            'src_bytes': src_bytes,
            'dst_bytes': dst_bytes,
            'is_attack': bool(is_attack),
            'attack_category': str(category),
            'severity': str(severity),
            'anomaly_score': float(round(anomaly_score, 4)),
            'confidence': float(round(confidence, 4)),
            'is_blocked': bool(is_blocked),
            'device': random.choice(DEVICE_NAMES),
            'response': 'BLOCKED' if is_blocked else (
                'ALERT' if severity in ['critical', 'high'] else 'MONITOR'
            ),
        }

        # Enrich with Kafka stream metadata, Zeek/Suricata/Wireshark signatures & OSINT Threat Intel
        from src.siem_db import enrich_event_with_pipeline_metadata, log_event_to_sql
        event = enrich_event_with_pipeline_metadata(event, self.event_counter)
        log_event_to_sql(event)

        # Track alerts
        if is_attack:
            self.alert_history.append(event)
            # Keep only recent alerts
            if len(self.alert_history) > 500:
                self.alert_history = self.alert_history[-500:]

        return event

    def generate_batch(self, count=10):
        """Generate a batch of events."""
        return [self.generate_event() for _ in range(count)]

    def block_ip(self, ip):
        """Add an IP to the blocklist."""
        with self._lock:
            self.blocked_ips.add(ip)
            self.stats['blocked_count'] = len(self.blocked_ips)
        return {'status': 'blocked', 'ip': ip, 'timestamp': datetime.now().isoformat()}

    def unblock_ip(self, ip):
        """Remove an IP from the blocklist."""
        with self._lock:
            self.blocked_ips.discard(ip)
            self.stats['blocked_count'] = len(self.blocked_ips)
        return {'status': 'unblocked', 'ip': ip, 'timestamp': datetime.now().isoformat()}

    def get_stats(self):
        """Get current traffic statistics."""
        with self._lock:
            total = self.stats['total_connections']
            blocked_total = len(self.blocked_ips)
            self.stats['blocked_count'] = blocked_total
            stats = {
                **self.stats,
                'categories': dict(self.stats['categories']),
                'attack_rate': (self.stats['attack_count'] / total * 100) if total > 0 else 0,
                'block_rate': (blocked_total / total * 100) if total > 0 else 0,
                'blocked_ips': sorted(self.blocked_ips),
                'active_alerts': len([a for a in self.alert_history
                                      if a['severity'] in ['critical', 'high']]),
            }
            return stats

    def get_recent_alerts(self, count=50):
        """Get the most recent alerts."""
        with self._lock:
            return list(self.alert_history[-count:])


# Global simulator instance
_simulator = None


def get_simulator():
    """Get or create the global simulator instance."""
    global _simulator
    if _simulator is None:
        _simulator = TrafficSimulator()
        _simulator.load_test_data()
        # Seed initial events into SIEM SQL DB for immediate querying
        _simulator.generate_batch(25)
    return _simulator
