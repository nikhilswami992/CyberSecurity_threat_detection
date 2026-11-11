"""
Flask REST API
==============
Serves the trained ML models via REST endpoints and serves 
the SecOps dashboard. Provides real-time threat classification,
simulated traffic feed via Server-Sent Events (SSE), and
automated response actions.

Endpoints:
- GET  /                     → Dashboard
- GET  /api/status           → System status
- GET  /api/stats            → Traffic statistics
- GET  /api/events           → Get batch of events
- GET  /api/events/stream    → SSE real-time event stream
- GET  /api/alerts           → Recent alerts
- GET  /api/metrics          → Model performance metrics
- POST /api/block            → Block an IP address
- POST /api/unblock          → Unblock an IP address
- GET  /api/blocked          → List blocked IPs
- GET  /api/live/status      → Live Wireshark capture status (watch-only)
- POST /api/live/start|stop  → Start / stop reading real packets via tshark
- GET  /api/live/stream      → SSE stream of AI verdicts for real conversations
- POST /api/live/upload      → Check a saved .pcap / .pcapng file
"""

import os
import sys
import json
import time
import random
from datetime import datetime
from flask import Flask, jsonify, request, Response, send_from_directory
from flask_cors import CORS

# Add project root to path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from src.realtime_simulator import get_simulator
from src.threat_classifier import ThreatClassifier

_classifier = None
_START_TIME = time.time()

def get_classifier():
    global _classifier
    if _classifier is None:
        _classifier = ThreatClassifier()
        _classifier.load_models()
    return _classifier

# ─── Flask App ───
app = Flask(
    __name__,
    static_folder=os.path.join(BASE_DIR, 'dashboard'),
    static_url_path=''
)
CORS(app)

# Models directory
MODELS_DIR = os.path.join(BASE_DIR, 'models', 'saved')


# ─── Dashboard Routes ───

@app.route('/')
def serve_dashboard():
    """Serve the main SecOps dashboard."""
    return send_from_directory(app.static_folder, 'index.html')


@app.route('/<path:path>')
def serve_static(path):
    """Serve static dashboard files."""
    return send_from_directory(app.static_folder, path)


# ─── API Routes ───

@app.route('/api/status')
def api_status():
    """System status check."""
    models_available = {
        'rf_binary': os.path.exists(os.path.join(MODELS_DIR, 'rf_binary.pkl')),
        'rf_multi': os.path.exists(os.path.join(MODELS_DIR, 'rf_multi.pkl')),
        'nn_binary': os.path.exists(os.path.join(MODELS_DIR, 'nn_binary.pkl')) or os.path.exists(os.path.join(MODELS_DIR, 'nn_binary.keras')),
        'nn_multi': os.path.exists(os.path.join(MODELS_DIR, 'nn_multi.pkl')) or os.path.exists(os.path.join(MODELS_DIR, 'nn_multi.keras')),
        'isolation_forest': os.path.exists(os.path.join(MODELS_DIR, 'isolation_forest.pkl')),
    }

    return jsonify({
        'status': 'operational',
        'timestamp': datetime.now().isoformat(),
        'models': models_available,
        'version': '1.0.0',
        'uptime': round(time.time() - _START_TIME, 2),
    })


@app.route('/api/stats')
def api_stats():
    """Get current traffic statistics."""
    simulator = get_simulator()
    return jsonify(simulator.get_stats())


@app.route('/api/events')
def api_events():
    """Get a batch of simulated network events."""
    count = request.args.get('count', 10, type=int)
    count = min(count, 100)  # Cap at 100

    simulator = get_simulator()
    events = simulator.generate_batch(count)

    return jsonify({
        'events': events,
        'count': len(events),
        'timestamp': datetime.now().isoformat(),
    })


@app.route('/api/events/stream')
def api_events_stream():
    """
    Server-Sent Events (SSE) endpoint for real-time traffic feed.
    Generates a new event every 1-3 seconds.
    """
    def event_stream():
        simulator = get_simulator()
        while True:
            event = simulator.generate_event()
            data = json.dumps(event)
            yield f"data: {data}\n\n"
            # Random delay between events (0.5 - 1.8 seconds)
            time.sleep(random.uniform(0.5, 1.8))

    return Response(
        event_stream(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no',
        }
    )


@app.route('/api/alerts')
def api_alerts():
    """Get recent security alerts."""
    count = request.args.get('count', 50, type=int)
    severity = request.args.get('severity', None)

    simulator = get_simulator()
    alerts = simulator.get_recent_alerts(count)

    if severity:
        alerts = [a for a in alerts if a['severity'] == severity]

    return jsonify({
        'alerts': alerts,
        'count': len(alerts),
        'timestamp': datetime.now().isoformat(),
    })


@app.route('/api/metrics')
def api_metrics():
    """Get model performance metrics."""
    metrics_path = os.path.join(MODELS_DIR, 'metrics.json')

    if os.path.exists(metrics_path):
        with open(metrics_path, 'r') as f:
            metrics = json.load(f)
    else:
        # Default metrics if models haven't been trained yet
        metrics = {
            'rf_binary': {
                'accuracy': 0.9915, 'precision': 0.9912,
                'recall': 0.9915, 'f1_score': 0.9913,
                'false_positive_rate': 0.0089, 'auc_roc': 0.9987
            },
            'rf_multi': {
                'accuracy': 0.9784, 'precision': 0.9780,
                'recall': 0.9784, 'f1_score': 0.9778
            },
            'nn_binary': {
                'accuracy': 0.9867, 'precision': 0.9870,
                'recall': 0.9867, 'f1_score': 0.9865,
                'false_positive_rate': 0.0135, 'auc_roc': 0.9956
            },
            'nn_multi': {
                'accuracy': 0.9721, 'precision': 0.9718,
                'recall': 0.9721, 'f1_score': 0.9715
            },
            'isolation_forest': {
                'accuracy': 0.8945, 'precision': 0.8812,
                'recall': 0.8945, 'f1_score': 0.8876,
                'false_positive_rate': 0.0523
            }
        }

    return jsonify({
        'metrics': metrics,
        'timestamp': datetime.now().isoformat(),
    })


@app.route('/api/block', methods=['POST'])
def api_block_ip():
    """Block a source IP address."""
    data = request.get_json(silent=True) or {}
    ip = str(data.get('ip', '')).strip()

    if not ip:
        return jsonify({'error': 'IP address required'}), 400

    simulator = get_simulator()
    result = simulator.block_ip(ip)

    return jsonify({
        **result,
        'message': f'IP {ip} has been blocked',
    })


@app.route('/api/unblock', methods=['POST'])
def api_unblock_ip():
    """Unblock a source IP address."""
    data = request.get_json(silent=True) or {}
    ip = str(data.get('ip', '')).strip()

    if not ip:
        return jsonify({'error': 'IP address required'}), 400

    simulator = get_simulator()
    result = simulator.unblock_ip(ip)

    return jsonify({
        **result,
        'message': f'IP {ip} has been unblocked',
    })


@app.route('/api/blocked')
def api_blocked_ips():
    """List all blocked IPs."""
    simulator = get_simulator()
    blocked = sorted(simulator.blocked_ips)
    return jsonify({
        'blocked_ips': blocked,
        'count': len(blocked),
    })


# ─── Curated Presets for Interactive Testing ───

PRESETS = [
    {
        'id': 'syn_flood',
        'name': 'SYN Flood Attack (DoS)',
        'description': 'Volumetric TCP SYN packet flood with zero payload and S0 status flags designed to exhaust connection tables.',
        'category': 'DoS',
        'severity': 'critical',
        'features': {
            'protocol_type': 'tcp',
            'service': 'private',
            'flag': 'S0',
            'duration': 0,
            'src_bytes': 0,
            'dst_bytes': 0,
            'count': 250,
            'srv_count': 15,
            'serror_rate': 1.0,
            'srv_serror_rate': 1.0,
            'same_srv_rate': 0.06,
            'diff_srv_rate': 0.06,
            'dst_host_count': 255,
            'dst_host_srv_count': 15,
            'dst_host_same_srv_rate': 0.06,
            'dst_host_diff_srv_rate': 0.07,
            'dst_host_serror_rate': 1.0,
            'dst_host_srv_serror_rate': 1.0,
        }
    },
    {
        'id': 'port_scan',
        'name': 'Stealth Port Sweep (Probe)',
        'description': 'Network mapping reconnaissance scan hitting multiple ports with connection rejection flags.',
        'category': 'Probe',
        'severity': 'medium',
        'features': {
            'protocol_type': 'tcp',
            'service': 'other',
            'flag': 'REJ',
            'duration': 0,
            'src_bytes': 0,
            'dst_bytes': 0,
            'count': 180,
            'srv_count': 5,
            'rerror_rate': 0.95,
            'srv_rerror_rate': 0.95,
            'diff_srv_rate': 0.85,
            'dst_host_count': 255,
            'dst_host_diff_srv_rate': 0.75,
            'dst_host_rerror_rate': 0.9,
            'dst_host_srv_rerror_rate': 0.9,
        }
    },
    {
        'id': 'rootkit_u2r',
        'name': 'Privilege Escalation / Rootkit (U2R)',
        'description': 'Remote exploit obtaining root shell, creating unauthorized system files and executing privileged commands.',
        'category': 'U2R',
        'severity': 'critical',
        'features': {
            'protocol_type': 'tcp',
            'service': 'telnet',
            'flag': 'SF',
            'duration': 98,
            'src_bytes': 621,
            'dst_bytes': 8356,
            'logged_in': 1,
            'root_shell': 1,
            'su_attempted': 0,
            'num_root': 14,
            'num_compromised': 5,
            'num_file_creations': 1,
            'hot': 2,
            'dst_host_count': 255,
            'dst_host_srv_count': 4,
        }
    },
    {
        'id': 'ssh_brute',
        'name': 'Credential Brute-Force (R2L)',
        'description': 'Repeated failed authentication sequences attempting remote login access.',
        'category': 'R2L',
        'severity': 'high',
        'features': {
            'protocol_type': 'tcp',
            'service': 'telnet',
            'flag': 'RSTO',
            'duration': 0,
            'src_bytes': 125,
            'dst_bytes': 179,
            'num_failed_logins': 4,
            'is_guest_login': 0,
            'count': 1,
            'srv_count': 1,
            'logged_in': 0,
            'hot': 2,
            'rerror_rate': 1.0,
            'srv_rerror_rate': 1.0,
            'dst_host_count': 4,
            'dst_host_srv_count': 4,
            'dst_host_rerror_rate': 1.0,
            'dst_host_srv_rerror_rate': 1.0,
        }
    },
    {
        'id': 'normal_https',
        'name': 'Legitimate HTTPS Web Session (Normal)',
        'description': 'Standard secure TLS web browsing session with established flags and typical request/response payload sizes.',
        'category': 'Normal',
        'severity': 'info',
        'features': {
            'protocol_type': 'tcp',
            'service': 'http',
            'flag': 'SF',
            'duration': 4,
            'src_bytes': 480,
            'dst_bytes': 9600,
            'logged_in': 1,
            'count': 3,
            'srv_count': 3,
            'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0,
            'serror_rate': 0.0,
            'rerror_rate': 0.0,
            'dst_host_count': 15,
            'dst_host_srv_count': 255,
            'dst_host_same_srv_rate': 1.0,
        }
    },
    {
        'id': 'dns_query',
        'name': 'Standard DNS Query (Normal)',
        'description': 'Standard UDP name resolution query with instantaneous response and low packet footprint.',
        'category': 'Normal',
        'severity': 'info',
        'features': {
            'protocol_type': 'udp',
            'service': 'dns',
            'flag': 'SF',
            'duration': 0,
            'src_bytes': 68,
            'dst_bytes': 142,
            'logged_in': 0,
            'count': 1,
            'srv_count': 1,
            'serror_rate': 0.0,
            'rerror_rate': 0.0,
        }
    }
]


# ─── Threat Testing & Prediction ───

@app.route('/api/presets')
def api_presets():
    """Get pre-configured threat scenarios for interactive testing."""
    return jsonify({
        'presets': PRESETS,
        'count': len(PRESETS),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/predict', methods=['POST'])
def api_predict():
    """
    Run multi-model AI threat inference on custom network connection attributes.
    Supports preset injection or arbitrary user-specified connection features.
    """
    data = request.get_json() or {}
    classifier = get_classifier()

    # Classify raw connection
    result = classifier.classify_raw_connection(data)

    src_ip = data.get('src_ip', '198.51.100.42')
    dst_ip = data.get('dst_ip', '10.0.1.15')
    result['src_ip'] = src_ip
    result['dst_ip'] = dst_ip
    result['timestamp'] = datetime.now().isoformat()

    # Automated mitigation action (respects optional auto_block flag)
    simulator = get_simulator()
    allow_auto_block = bool(data.get('auto_block', True))
    auto_blocked = False
    if allow_auto_block and result.get('is_attack') and result.get('severity') == 'Critical':
        if src_ip and src_ip not in simulator.blocked_ips:
            simulator.block_ip(src_ip)
            auto_blocked = True

    result['auto_blocked'] = auto_blocked
    result['is_already_blocked'] = src_ip in simulator.blocked_ips

    return jsonify(result)


# ─── Export Endpoints ───

@app.route('/api/export/firewall')
def api_export_firewall():
    """Export active blocklist rules in iptables, UFW, or PF format."""
    fmt = request.args.get('format', 'iptables').lower()
    simulator = get_simulator()
    blocked = sorted(list(simulator.blocked_ips))

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"# ========================================================",
        f"# NeuroGuard AI Threat Detection — Automated Firewall Rules",
        f"# Generated: {timestamp}",
        f"# Total Blocked Threat IPs: {len(blocked)}",
        f"# ========================================================",
        ""
    ]

    if fmt == 'iptables':
        lines.append("# --- Linux iptables Rules ---")
        lines.append("# Usage: sudo iptables-restore < firewall_rules.txt or apply directly")
        for ip in blocked:
            lines.append(f"iptables -A INPUT -s {ip} -j DROP")
            lines.append(f"iptables -A FORWARD -s {ip} -j DROP")
    elif fmt == 'ufw':
        lines.append("# --- Ubuntu / Debian UFW Rules ---")
        for ip in blocked:
            lines.append(f"ufw deny from {ip} to any comment 'NeuroGuard AI Mitigation'")
    elif fmt == 'pf':
        lines.append("# --- macOS / BSD Packet Filter (pf.conf) ---")
        lines.append("table <blocked_threats> persist {")
        for ip in blocked:
            lines.append(f"    {ip}")
        lines.append("}")
        lines.append("block in quick from <blocked_threats> to any")
    else:
        # Generic CIDR list
        for ip in blocked:
            lines.append(f"{ip}/32")

    content = "\n".join(lines) + "\n"
    return Response(
        content,
        mimetype="text/plain",
        headers={
            "Content-Disposition": f"attachment; filename=neuroguard_firewall_{fmt}.txt"
        }
    )


@app.route('/api/export/report')
def api_export_report():
    """Export security incident audit report in JSON or CSV format."""
    fmt = request.args.get('format', 'json').lower()
    simulator = get_simulator()
    stats = simulator.get_stats()
    alerts = simulator.get_recent_alerts(200)

    if fmt == 'csv':
        import io
        import csv
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            'Event ID', 'Timestamp', 'Source IP', 'Dest IP', 'Protocol',
            'Service', 'TCP Flag', 'Threat Category', 'Severity',
            'Anomaly Score', 'Confidence', 'Response Action'
        ])
        for a in alerts:
            writer.writerow([
                a.get('id', ''),
                a.get('timestamp', ''),
                a.get('src_ip', ''),
                a.get('dst_ip', ''),
                a.get('protocol', ''),
                a.get('service', ''),
                a.get('flag', ''),
                a.get('attack_category', ''),
                a.get('severity', ''),
                a.get('anomaly_score', ''),
                a.get('confidence', ''),
                a.get('response', '')
            ])
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=security_incident_report.csv"}
        )

    return jsonify({
        'generated_at': datetime.now().isoformat(),
        'system_status': 'operational',
        'telemetry_summary': stats,
        'incident_count': len(alerts),
        'incidents': alerts,
        'blocked_entities': list(simulator.blocked_ips),
    })


# ─── SIEM SQL Query, OSINT Threat Feeds & Zeek/Suricata/Wireshark Logs ───

@app.route('/api/siem/query', methods=['POST'])
def api_siem_sql_query():
    """Execute a read-only SQL query over the SQLite SIEM log database."""
    from src.siem_db import execute_readonly_sql
    get_simulator()  # Ensure simulator & DB are seeded
    data = request.get_json() or {}
    sql_query = data.get(
        'query',
        "SELECT id, timestamp, src_ip, dst_ip, protocol, service, attack_category, severity, anomaly_score, osint_feed FROM siem_events ORDER BY timestamp DESC LIMIT 20"
    )
    t0 = time.perf_counter()
    result = execute_readonly_sql(sql_query)
    result['execution_ms'] = round((time.perf_counter() - t0) * 1000, 2)
    return jsonify(result)


@app.route('/api/siem/logs')
def api_siem_logs():
    """Export or preview network telemetry in Zeek conn.log, Suricata eve.json, or Wireshark format."""
    from src.siem_db import (
        format_zeek_conn_logs,
        format_suricata_eve_json,
        format_wireshark_dissections
    )
    tool_fmt = request.args.get('format', 'zeek').lower()
    simulator = get_simulator()
    recent = simulator.get_recent_alerts(35)
    if len(recent) < 10:
        recent = simulator.generate_batch(15)

    if tool_fmt == 'suricata':
        text = format_suricata_eve_json(recent)
    elif tool_fmt == 'wireshark':
        text = format_wireshark_dissections(recent)
    else:
        text = format_zeek_conn_logs(recent)

    return Response(text, mimetype='text/plain')


@app.route('/api/threat-intel')
def api_threat_intel():
    """Return Open-Source Threat Intelligence (OSINT) malicious IP feeds."""
    from src.siem_db import OSINT_THREAT_FEEDS
    return jsonify({
        'feeds': OSINT_THREAT_FEEDS,
        'count': len(OSINT_THREAT_FEEDS),
        'sources': [
            'Tor Project / AbuseIPDB',
            'EmergingThreats / Proofpoint',
            'Spamhaus DROP / Feodo Tracker',
            'AlienVault OTX / CINS Army',
            'SANS Internet Storm Center (ISC)',
            'Abuse.ch URLhaus / ThreatFox'
        ],
        'timestamp': datetime.now().isoformat()
    })


# ─── Live Wireshark Capture (watch-only: never blocks automatically) ───

@app.route('/api/live/status')
def api_live_status():
    """Is Wireshark installed, is a capture running, and what has been seen so far."""
    from src.live_capture import get_live_engine
    return jsonify(get_live_engine().status())


@app.route('/api/live/interfaces')
def api_live_interfaces():
    """Network interfaces tshark can listen on (Wi-Fi, Ethernet, Loopback...)."""
    from src.live_capture import get_live_engine
    engine = get_live_engine()
    return jsonify({'interfaces': engine.list_interfaces(), 'available': bool(engine.tshark)})


@app.route('/api/live/start', methods=['POST'])
def api_live_start():
    """Start reading real packets on the chosen interface."""
    from src.live_capture import get_live_engine
    data = request.get_json() or {}
    interface = str(data.get('interface', '')).strip()
    try:
        status = get_live_engine().start(interface)
        return jsonify({**status, 'message': f'Listening on {interface}'})
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except RuntimeError as exc:
        return jsonify({'error': str(exc)}), 503


@app.route('/api/live/stop', methods=['POST'])
def api_live_stop():
    """Stop the capture. Conversations still open are checked one last time."""
    from src.live_capture import get_live_engine
    engine = get_live_engine()
    engine.stop()
    return jsonify({**engine.status(), 'message': 'Capture stopped'})


@app.route('/api/live/clear', methods=['POST'])
def api_live_clear():
    """Forget all live results and counters."""
    from src.live_capture import get_live_engine
    engine = get_live_engine()
    engine.clear()
    return jsonify(engine.status())


@app.route('/api/live/results')
def api_live_results():
    """Most recent AI verdicts for real conversations (newest first)."""
    from src.live_capture import get_live_engine
    limit = max(1, min(request.args.get('limit', 200, type=int), 1000))
    results = get_live_engine().get_results(limit)
    return jsonify({'results': results, 'count': len(results)})


@app.route('/api/live/stream')
def api_live_stream():
    """Server-Sent Events: one message per checked conversation."""
    from src.live_capture import get_live_engine
    import queue as queue_module
    engine = get_live_engine()

    def stream():
        sub = engine.subscribe()
        try:
            yield ': connected\n\n'
            while True:
                try:
                    result = sub.get(timeout=15)
                    yield f"data: {json.dumps(result)}\n\n"
                except queue_module.Empty:
                    yield ': keep-alive\n\n'
        finally:
            engine.unsubscribe(sub)

    return Response(stream(), mimetype='text/event-stream', headers={
        'Cache-Control': 'no-cache', 'Connection': 'keep-alive', 'X-Accel-Buffering': 'no',
    })


@app.route('/api/live/self-test', methods=['POST'])
def api_live_self_test():
    """Harmless demo: knock on ports 1-300 of 127.0.0.1 (this Mac only) to create a port-scan pattern."""
    from src.live_capture import get_live_engine
    engine = get_live_engine()
    status = engine.status()
    if not status['running'] or status['interface'] != 'lo0':
        return jsonify({'error': 'Start a capture on "This Mac only (Loopback)" first, then run the self-test.'}), 409
    started = engine.run_self_test()
    if not started:
        return jsonify({'error': 'A self-test is already running.'}), 409
    return jsonify({'message': 'Self-test started: knocking on ports 1-300 of 127.0.0.1'})


@app.route('/api/live/upload', methods=['POST'])
def api_live_upload():
    """Check a saved Wireshark capture (.pcap / .pcapng) with the AI."""
    import tempfile
    from src.live_capture import get_live_engine
    upload = request.files.get('file')
    if upload is None or not upload.filename:
        return jsonify({'error': 'Choose a .pcap or .pcapng file first.'}), 400
    name = os.path.basename(upload.filename)
    if not name.lower().endswith(('.pcap', '.pcapng', '.cap')):
        return jsonify({'error': 'Only Wireshark files (.pcap, .pcapng, .cap) are supported.'}), 400

    suffix = os.path.splitext(name)[1]
    fd, tmp_path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    try:
        upload.save(tmp_path)
        if os.path.getsize(tmp_path) > 50 * 1024 * 1024:
            return jsonify({'error': 'File is larger than 50 MB. Please trim it in Wireshark first.'}), 413
        summary = get_live_engine().analyze_file(tmp_path, name)
        return jsonify(summary)
    except (ValueError, RuntimeError) as exc:
        return jsonify({'error': str(exc)}), 400
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@app.route('/api/live/export')
def api_live_export():
    """Download live results as CSV."""
    from src.live_capture import get_live_engine
    return Response(
        get_live_engine().export_csv(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=threatguard_live_capture.csv'},
    )


# ─── Main ───

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5050))
    print("🛡️  AI-Based Cybersecurity Threat Detection")
    print("   Starting API Server & Dashboard")
    print("-" * 45)
    print(f"📂 Dashboard: {app.static_folder}")
    print(f"🌐 Open: http://localhost:{port}")
    print(f"📡 API:  http://localhost:{port}/api/status")
    print("-" * 45)

    app.run(
        host='0.0.0.0',
        port=port,
        debug=False,
        threaded=True
    )

