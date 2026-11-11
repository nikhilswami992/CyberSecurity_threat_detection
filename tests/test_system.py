"""
Automated Verification, Refinement & Debugging Suite
====================================================
Tests every subsystem of the AI-Based Cybersecurity Threat Detection platform:
1. Dataset & Feature Engineering integrity (48 normalized features)
2. 5-Model AI Ensemble loading & inference (RF Binary, RF Multi, DNN Binary, DNN Multi, Isolation Forest)
3. All 6 Threat Sandbox Presets (DoS, Probe, U2R, R2L, Normal HTTPS, Normal DNS)
4. REST API Endpoints (/api/status, /api/stats, /api/events, /api/alerts, /api/metrics, /api/presets, /api/predict)
5. Automated SOAR IP Quarantine & Firewall Rule Compiler (iptables, UFW, pf.conf)
6. SQLite SIEM SQL Query Engine, Security Guardrails & OSINT Threat Feeds
7. Network Security Log Formatters (Zeek conn.log, Suricata eve.json, Wireshark dissections)

Run with:
    python3 -m unittest discover -s tests -v
"""

import os
import sys
import json
import unittest
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from src.api import app, PRESETS, get_classifier
from src.siem_db import execute_readonly_sql, OSINT_THREAT_FEEDS


class TestCybersecurityThreatDetectionSuite(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()
        cls.classifier = get_classifier()

    def test_01_model_artifacts_and_metrics_loaded(self):
        """Verify all 5 trained ML models and benchmark metrics are loaded."""
        summary = self.classifier.get_model_summary()
        models = summary['models_loaded']
        self.assertTrue(models['rf_binary'], "rf_binary should be loaded")
        self.assertTrue(models['rf_multi'], "rf_multi should be loaded")
        self.assertTrue(models['nn_binary'], "nn_binary should be loaded")
        self.assertTrue(models['nn_multi'], "nn_multi should be loaded")
        self.assertTrue(models['isolation_forest'], "isolation_forest should be loaded")

        metrics = summary['metrics']
        for key in ['rf_binary', 'rf_multi', 'nn_binary', 'nn_multi', 'isolation_forest']:
            self.assertIn(key, metrics, f"Metrics missing for {key}")
            self.assertGreater(metrics[key]['accuracy'], 0.70)

    def test_02_feature_engineering_dimensions(self):
        """Verify feature names and processed dataset shapes match 48 dimensions."""
        self.assertEqual(len(self.classifier.feature_names), 48)
        x_test_path = os.path.join(BASE_DIR, 'data', 'processed', 'X_test.npy')
        self.assertTrue(os.path.exists(x_test_path))
        X_test = np.load(x_test_path, mmap_mode='r')
        self.assertEqual(X_test.shape[1], 48)

    def test_03_all_sandbox_presets_classification(self):
        """Verify all 6 Threat Sandbox presets classify into their exact expected category."""
        for preset in PRESETS:
            expected_cat = preset['category']
            res = self.classifier.classify_raw_connection(preset['features'])
            self.assertEqual(
                res['attack_category'],
                expected_cat,
                f"Preset '{preset['id']}' expected {expected_cat} but got {res['attack_category']}"
            )
            if expected_cat == 'Normal':
                self.assertFalse(res['is_attack'])
                self.assertEqual(res['severity'], 'Info')
            else:
                self.assertTrue(res['is_attack'])
                self.assertIn(res['severity'], ['Critical', 'High', 'Medium'])

    def test_04_api_status_and_metrics_endpoints(self):
        """Verify /api/status and /api/metrics return valid operational JSON."""
        res_status = self.client.get('/api/status')
        self.assertEqual(res_status.status_code, 200)
        data_status = res_status.get_json()
        self.assertEqual(data_status['status'], 'operational')
        self.assertTrue(all(data_status['models'].values()))

        res_metrics = self.client.get('/api/metrics')
        self.assertEqual(res_metrics.status_code, 200)
        data_metrics = res_metrics.get_json()
        self.assertIn('rf_binary', data_metrics['metrics'])
        self.assertIn('isolation_forest', data_metrics['metrics'])

    def test_05_api_predict_and_auto_soar_quarantine(self):
        """Verify POST /api/predict classifies threats and auto-quarantines Critical IPs."""
        test_ip = '198.51.100.250'
        # Unblock first to ensure clean state
        self.client.post('/api/unblock', json={'ip': test_ip})

        syn_preset = next(p for p in PRESETS if p['id'] == 'syn_flood')
        payload = {**syn_preset['features'], 'src_ip': test_ip, 'dst_ip': '10.0.1.15'}

        res = self.client.post('/api/predict', json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['is_attack'])
        self.assertEqual(data['attack_category'], 'DoS')
        self.assertEqual(data['severity'], 'Critical')
        self.assertTrue(data['auto_blocked'])

        # Clean up test IP
        self.client.post('/api/unblock', json={'ip': test_ip})

    def test_06_firewall_export_formats(self):
        """Verify iptables, UFW, and pf.conf firewall rule exports."""
        test_ip = '203.0.113.199'
        self.client.post('/api/block', json={'ip': test_ip})

        for fmt, expected_token in [
            ('iptables', f'iptables -A INPUT -s {test_ip} -j DROP'),
            ('ufw', f'ufw deny from {test_ip} to any'),
            ('pf', 'table <blocked_threats> persist'),
        ]:
            res = self.client.get(f'/api/export/firewall?format={fmt}')
            self.assertEqual(res.status_code, 200)
            text = res.get_data(as_text=True)
            self.assertIn(expected_token, text)

        self.client.post('/api/unblock', json={'ip': test_ip})

    def test_07_siem_sql_console_and_security_guardrails(self):
        """Verify SIEM read-only SQL queries and mutating query blocking."""
        # Valid SELECT query
        res = self.client.post('/api/siem/query', json={
            'query': 'SELECT id, src_ip, attack_category, severity FROM siem_events LIMIT 5'
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertNotIn('error', data)
        self.assertGreater(len(data['rows']), 0)

        # Mutating SQL query should be blocked
        res_bad = self.client.post('/api/siem/query', json={
            'query': 'DROP TABLE siem_events'
        })
        data_bad = res_bad.get_json()
        self.assertIn('error', data_bad)

    def test_08_zeek_suricata_wireshark_and_osint_feeds(self):
        """Verify Zeek conn.log, Suricata eve.json, Wireshark logs, and OSINT feeds."""
        for fmt, marker in [
            ('zeek', '#fields\tts\tuid'),
            ('suricata', '"event_type":'),
            ('wireshark', 'Wireshark / tshark Live Packet Dissector'),
        ]:
            res = self.client.get(f'/api/siem/logs?format={fmt}')
            self.assertEqual(res.status_code, 200)
            self.assertIn(marker, res.get_data(as_text=True))

        res_osint = self.client.get('/api/threat-intel')
        self.assertEqual(res_osint.status_code, 200)
        osint_data = res_osint.get_json()
        self.assertEqual(osint_data['count'], len(OSINT_THREAT_FEEDS))

    def test_09_live_wireshark_engine_and_watch_only_guardrails(self):
        """Verify Live Wireshark endpoints, FlowTracker feature builder, and watch-only guardrails."""
        res_live = self.client.get('/api/live/status')
        self.assertEqual(res_live.status_code, 200)
        live_status = res_live.get_json()
        self.assertFalse(live_status['auto_block'])

        res_ifaces = self.client.get('/api/live/interfaces')
        self.assertEqual(res_ifaces.status_code, 200)
        self.assertIn('interfaces', res_ifaces.get_json())

        # Verify multi-statement SQL injection is blocked
        res_multi = execute_readonly_sql('SELECT 1; DROP TABLE siem_events')
        self.assertIn('error', res_multi)

        # Verify /api/predict respects auto_block=False when user disables auto-blocking
        test_ip = '198.51.100.251'
        self.client.post('/api/unblock', json={'ip': test_ip})
        syn_preset = next(p for p in PRESETS if p['id'] == 'syn_flood')
        res_pred = self.client.post('/api/predict', json={
            **syn_preset['features'],
            'src_ip': test_ip,
            'auto_block': False,
        })
        self.assertEqual(res_pred.status_code, 200)
        self.assertFalse(res_pred.get_json()['auto_blocked'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
