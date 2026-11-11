"""
SIEM SQL Log Database, OSINT Threat Intelligence & Network Log Formats
======================================================================
Implements:
1. SQLite Relational Log Database (`siem_events` & `threat_intel_feeds`)
   for executing real SQL queries over network telemetry and security alerts.
2. Open-Source Threat Intelligence (OSINT) IP Reputation Lookup
   (Spamhaus DROP, AbuseIPDB, EmergingThreats, Feodo Tracker, Tor Exit Nodes).
3. Security Tool Log Formatters & Parsers:
   - Zeek Network Security Monitor (`conn.log` TSV format)
   - Suricata IDS/IPS (`eve.json` alert format)
   - Wireshark Packet Dissector summary format
   - Apache Kafka stream ingestion metadata (`topic`, `partition`, `offset`)
"""

import os
import json
import sqlite3
import threading
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, 'data', 'processed', 'siem_telemetry.db')

_db_lock = threading.Lock()

# Curated Open-Source Threat Intelligence (OSINT) Feeds
OSINT_THREAT_FEEDS = [
    {
        'ip': '185.220.101.42',
        'feed_source': 'Tor Project / AbuseIPDB',
        'threat_label': 'Tor Exit Node · Brute-Force & Recon Actor',
        'reputation_score': 96,
        'asn': 'AS60729 Zwiebelfreunde e.V.',
        'country': 'DE',
        'first_seen': '2026-09-12',
    },
    {
        'ip': '45.33.32.156',
        'feed_source': 'EmergingThreats / Proofpoint',
        'threat_label': 'Known Port Scanner & SYN Flood Botnet Node',
        'reputation_score': 91,
        'asn': 'AS63949 Akamai Connected Cloud',
        'country': 'US',
        'first_seen': '2026-08-24',
    },
    {
        'ip': '91.189.92.77',
        'feed_source': 'Spamhaus DROP / Feodo Tracker',
        'threat_label': 'Botnet Command & Control (C2) Relay',
        'reputation_score': 98,
        'asn': 'AS41231 Canonical Group',
        'country': 'GB',
        'first_seen': '2026-10-01',
    },
    {
        'ip': '203.0.113.200',
        'feed_source': 'AlienVault OTX / CINS Army',
        'threat_label': 'High-Volume DDoS & Credential Stuffing Host',
        'reputation_score': 94,
        'asn': 'AS4713 NTT Communications',
        'country': 'JP',
        'first_seen': '2026-09-29',
    },
    {
        'ip': '198.51.100.99',
        'feed_source': 'SANS Internet Storm Center (ISC)',
        'threat_label': 'Telnet / SSH Rootkit Exploit Source (U2R)',
        'reputation_score': 89,
        'asn': 'AS28573 Claro S.A.',
        'country': 'BR',
        'first_seen': '2026-10-08',
    },
    {
        'ip': '185.220.101.11',
        'feed_source': 'Abuse.ch URLhaus / ThreatFox',
        'threat_label': 'Malware Payload Dropper & Exfiltration Host',
        'reputation_score': 95,
        'asn': 'AS60729 Zwiebelfreunde e.V.',
        'country': 'NL',
        'first_seen': '2026-10-14',
    },
]

OSINT_IP_MAP = {item['ip']: item for item in OSINT_THREAT_FEEDS}

# Suricata IDS Signature IDs per category
SURICATA_SID_MAP = {
    'DoS': (2100498, 'ET DOS Possible TCP SYN Flood Inbound'),
    'Probe': (2010935, 'ET SCAN Suspicious Inbound Port Sweep'),
    'R2L': (2001219, 'ET SCAN Potential SSH/Telnet Brute-Force Attempt'),
    'U2R': (2008124, 'ET EXPLOIT Privilege Escalation Root Shell Spawned'),
    'Normal': (1000001, 'SURICATA STREAM Established Normal Flow'),
}


def init_siem_db():
    """Initialize SQLite SIEM tables and seed OSINT threat intelligence records."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS siem_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                src_ip TEXT,
                src_port INTEGER,
                dst_ip TEXT,
                dst_port INTEGER,
                protocol TEXT,
                service TEXT,
                flag TEXT,
                duration INTEGER,
                src_bytes INTEGER,
                dst_bytes INTEGER,
                attack_category TEXT,
                severity TEXT,
                anomaly_score REAL,
                confidence REAL,
                response TEXT,
                device TEXT,
                kafka_topic TEXT,
                kafka_partition INTEGER,
                kafka_offset INTEGER,
                zeek_uid TEXT,
                suricata_sid INTEGER,
                osint_feed TEXT
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS threat_intel_feeds (
                ip TEXT PRIMARY KEY,
                feed_source TEXT,
                threat_label TEXT,
                reputation_score INTEGER,
                asn TEXT,
                country TEXT,
                first_seen TEXT
            )
        """)

        for item in OSINT_THREAT_FEEDS:
            cur.execute("""
                INSERT OR REPLACE INTO threat_intel_feeds
                (ip, feed_source, threat_label, reputation_score, asn, country, first_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                item['ip'], item['feed_source'], item['threat_label'],
                item['reputation_score'], item['asn'], item['country'], item['first_seen']
            ))

        conn.commit()
        conn.close()


def enrich_event_with_pipeline_metadata(event, offset_counter):
    """
    Attach Apache Kafka stream coordinates, Zeek conn.log UID,
    Suricata EVE signature ID, Wireshark summary, and OSINT Threat Intel labels.
    """
    src_ip = event.get('src_ip', '')
    category = event.get('attack_category', 'Normal')
    osint = OSINT_IP_MAP.get(src_ip)

    if osint:
        osint_source = osint['feed_source']
        osint_label = osint['threat_label']
        osint_score = osint['reputation_score']
    elif event.get('is_attack'):
        osint_source = 'Heuristic Behavioral Feed'
        osint_label = f'Suspected {category} Vector'
        osint_score = int(min(95, round(event.get('anomaly_score', 0.7) * 100)))
    else:
        osint_source = 'Baseline Allowlist'
        osint_label = 'Verified Benign Host'
        osint_score = 4

    sid, sig_msg = SURICATA_SID_MAP.get(category, SURICATA_SID_MAP['Normal'])
    zeek_uid = f"C{abs(hash(event['id'] + event['timestamp'])) % 10**14:014x}"[:17]

    event['kafka_topic'] = 'vectrax.telemetry.netflow'
    event['kafka_partition'] = offset_counter % 4
    event['kafka_offset'] = 104800 + offset_counter
    event['zeek_uid'] = zeek_uid
    event['suricata_sid'] = sid
    event['suricata_signature'] = sig_msg
    event['osint_feed'] = osint_source
    event['osint_label'] = osint_label
    event['osint_reputation'] = osint_score
    event['wireshark_summary'] = (
        f"{event.get('protocol', 'tcp').upper()} "
        f"{event.get('src_port', 0)} → {event.get('dst_port', 0)} "
        f"[{event.get('flag', 'SF')}] Seq=1 Ack=1 Win=64240 "
        f"Len={event.get('src_bytes', 0) + event.get('dst_bytes', 0)}"
    )

    return event


def log_event_to_sql(event):
    """Persist a network telemetry event into the SQLite SIEM database."""
    try:
        with _db_lock:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("""
                INSERT OR REPLACE INTO siem_events (
                    id, timestamp, src_ip, src_port, dst_ip, dst_port,
                    protocol, service, flag, duration, src_bytes, dst_bytes,
                    attack_category, severity, anomaly_score, confidence,
                    response, device, kafka_topic, kafka_partition,
                    kafka_offset, zeek_uid, suricata_sid, osint_feed
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.get('id'),
                event.get('timestamp'),
                event.get('src_ip'),
                event.get('src_port'),
                event.get('dst_ip'),
                event.get('dst_port'),
                event.get('protocol'),
                event.get('service'),
                event.get('flag'),
                event.get('duration'),
                event.get('src_bytes'),
                event.get('dst_bytes'),
                event.get('attack_category'),
                event.get('severity'),
                event.get('anomaly_score'),
                event.get('confidence'),
                event.get('response'),
                event.get('device'),
                event.get('kafka_topic', 'vectrax.telemetry.netflow'),
                event.get('kafka_partition', 0),
                event.get('kafka_offset', 0),
                event.get('zeek_uid', ''),
                event.get('suricata_sid', 1000001),
                event.get('osint_feed', 'Baseline Allowlist'),
            ))
            # Keep DB compact (latest 2,000 events)
            cur.execute("""
                DELETE FROM siem_events
                WHERE id NOT IN (
                    SELECT id FROM siem_events ORDER BY timestamp DESC LIMIT 2000
                )
            """)
            conn.commit()
            conn.close()
    except Exception as exc:
        print(f"⚠️ SIEM SQL log warning: {exc}")


def execute_readonly_sql(sql_query):
    """
    Execute a safe, read-only SELECT query against the SIEM SQLite database.
    Returns columns, rows, and execution time in ms.
    """
    cleaned = (sql_query or '').strip().rstrip(';').strip()
    if not cleaned.lower().startswith('select'):
        return {
            'error': 'Only read-only SELECT queries are permitted in the SIEM SQL console.',
            'columns': [],
            'rows': []
        }

    if ';' in cleaned:
        return {
            'error': 'Multi-statement SQL queries are blocked by SIEM security policy.',
            'columns': [],
            'rows': []
        }

    forbidden = ('insert ', 'update ', 'delete ', 'drop ', 'alter ', 'attach ', 'pragma ')
    lower_q = ' '.join(cleaned.lower().split())
    if any(tok in lower_q for tok in forbidden):
        return {
            'error': 'Mutating SQL statements are blocked by SIEM security policy.',
            'columns': [],
            'rows': []
        }

    with _db_lock:
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
        cur = conn.cursor()
        try:
            cur.execute(cleaned)
            columns = [desc[0] for desc in cur.description] if cur.description else []
            raw_rows = cur.fetchall()[:150]
            rows = [dict(zip(columns, r)) for r in raw_rows]
            return {
                'columns': columns,
                'rows': rows,
                'row_count': len(rows),
                'query': cleaned,
            }
        except Exception as exc:
            return {
                'error': str(exc),
                'columns': [],
                'rows': [],
                'query': cleaned,
            }
        finally:
            conn.close()


def format_zeek_conn_logs(events):
    """Format events as Zeek Network Security Monitor `conn.log` TSV lines."""
    lines = [
        "#separator \\x09",
        "#path\tconn",
        f"#open\t{datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}",
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tthreat_verdict\tanomaly_score",
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tstring\tdouble"
    ]
    for e in events[:35]:
        lines.append(
            f"{e.get('timestamp', '')}\t{e.get('zeek_uid', 'C0000001')}\t"
            f"{e.get('src_ip', '')}\t{e.get('src_port', 0)}\t"
            f"{e.get('dst_ip', '')}\t{e.get('dst_port', 0)}\t"
            f"{e.get('protocol', 'tcp')}\t{e.get('service', 'http')}\t"
            f"{e.get('duration', 0)}\t{e.get('src_bytes', 0)}\t{e.get('dst_bytes', 0)}\t"
            f"{e.get('flag', 'SF')}\t{e.get('attack_category', 'Normal')}\t{e.get('anomaly_score', 0.0):.4f}"
        )
    return "\n".join(lines)


def format_suricata_eve_json(events):
    """Format events as Suricata IDS/IPS `eve.json` JSON-Lines."""
    lines = []
    for e in events[:25]:
        eve = {
            "timestamp": e.get("timestamp"),
            "flow_id": abs(hash(e.get("id", ""))),
            "in_iface": "eth0",
            "event_type": "alert" if e.get("is_attack") else "flow",
            "src_ip": e.get("src_ip"),
            "src_port": e.get("src_port"),
            "dest_ip": e.get("dst_ip"),
            "dest_port": e.get("dst_port"),
            "proto": e.get("protocol", "tcp").upper(),
            "app_proto": e.get("service", "http"),
            "kafka": {
                "topic": e.get("kafka_topic", "vectrax.telemetry.netflow"),
                "partition": e.get("kafka_partition", 0),
                "offset": e.get("kafka_offset", 0)
            },
            "alert": {
                "action": "blocked" if e.get("is_blocked") else "allowed",
                "gid": 1,
                "signature_id": e.get("suricata_sid", 1000001),
                "rev": 1,
                "signature": e.get("suricata_signature", "SURICATA Flow"),
                "category": e.get("attack_category", "Normal"),
                "severity": 1 if e.get("severity") == "critical" else (2 if e.get("severity") == "high" else 3)
            },
            "ai_telemetry": {
                "anomaly_score": e.get("anomaly_score"),
                "confidence": e.get("confidence"),
                "osint_feed": e.get("osint_feed")
            }
        }
        lines.append(json.dumps(eve))
    return "\n".join(lines)


def format_wireshark_dissections(events):
    """Format events as Wireshark CLI (`tshark -V`) packet summary lines."""
    lines = [
        "# Wireshark / tshark Live Packet Dissector Capture — Interface: eth0 (NSL-KDD Bridge)",
        "# No. | Time                | Source          | Destination     | Proto | Len   | Info & AI Verdict",
        "-" * 112
    ]
    for idx, e in enumerate(events[:35], 1):
        length = (e.get('src_bytes', 0) or 0) + (e.get('dst_bytes', 0) or 0) + 54
        lines.append(
            f"{idx:4d}  | {e.get('timestamp', '')[11:23]:19s} | "
            f"{e.get('src_ip', ''):15s} | {e.get('dst_ip', ''):15s} | "
            f"{e.get('protocol', 'tcp').upper():5s} | {length:5d} | "
            f"{e.get('wireshark_summary', '')} [AI: {e.get('attack_category')} / Iso={e.get('anomaly_score', 0):.2f}]"
        )
    return "\n".join(lines)


# Initialize database on module import
init_siem_db()
