"""
Live Wireshark Capture
======================
Reads real packets from this computer using Wireshark's command-line tool
(tshark), groups them into conversations (connections), rebuilds the same
NSL-KDD style values the AI models were trained on, and asks the 5 models
to check each conversation.

Plain-English pipeline:
    1. Catch packets       -> tshark prints one line per packet
    2. Group conversations -> packets between the same two endpoints are merged
    3. Measure             -> duration, bytes each way, how it ended (flag),
                              and "what else happened recently" window stats
    4. AI check            -> ThreatClassifier.classify_raw_connection()
    5. Show                -> results are streamed to the dashboard

Watch-only by design: this module NEVER blocks an IP address. Any blocking
is a manual decision made by the person using the dashboard.

Honest limits:
    - Content values the NSL-KDD dataset took from server logs (failed logins,
      root shells, files created, ...) cannot be seen in packets and are 0.
    - Encrypted HTTPS (port 443) is mapped to the "http" service, because the
      1999-era training data has almost no normal HTTPS examples.
"""

import os
import re
import csv
import io
import time
import queue
import shutil
import socket
import atexit
import threading
import subprocess
from collections import deque
from datetime import datetime

# ─── tshark discovery ───

TSHARK_CANDIDATES = [
    os.environ.get('TSHARK_PATH', ''),
    shutil.which('tshark') or '',
    '/Applications/Wireshark.app/Contents/MacOS/tshark',
    '/opt/homebrew/bin/tshark',
    '/usr/local/bin/tshark',
    '/usr/bin/tshark',
    r'C:\Program Files\Wireshark\tshark.exe',
]

# Fields requested from tshark, in this exact order (one tab-separated line per packet)
TSHARK_FIELDS = [
    'frame.time_epoch',   # 0
    'ip.src',             # 1
    'ip.dst',             # 2
    'ipv6.src',           # 3
    'ipv6.dst',           # 4
    'ip.proto',           # 5
    'ipv6.nxt',           # 6
    'tcp.srcport',        # 7
    'tcp.dstport',        # 8
    'udp.srcport',        # 9
    'udp.dstport',        # 10
    'tcp.flags',          # 11
    'tcp.len',            # 12
    'udp.length',         # 13
    'icmp.type',          # 14
    'icmpv6.type',        # 15
    'frame.len',          # 16
]

# Interfaces that are never useful for this project (virtual / remote-capture plugins)
HIDDEN_INTERFACE_PREFIXES = (
    'awdl', 'llw', 'utun', 'anpi', 'gif', 'stf', 'ap', 'ciscodump', 'randpkt',
    'sshdump', 'udpdump', 'wifidump', 'etwdump', 'dpauxmon', 'sdjournal',
)

# ─── NSL-KDD compatibility tables ───

TCP_SERVICES = {
    20: 'ftp_data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 37: 'time',
    43: 'whois', 53: 'domain', 70: 'gopher', 79: 'finger', 80: 'http',
    102: 'iso_tsap', 109: 'pop_2', 110: 'pop_3', 111: 'sunrpc', 113: 'auth',
    117: 'uucp_path', 119: 'nntp', 139: 'netbios_ssn', 143: 'imap4', 150: 'sql_net',
    179: 'bgp', 194: 'IRC', 210: 'Z39_50', 389: 'ldap',
    # HTTPS: the training data has almost no normal HTTPS, so it is treated as web (http)
    443: 'http',
    512: 'exec', 513: 'login', 514: 'shell', 515: 'printer', 540: 'uucp',
    543: 'klogin', 544: 'kshell', 2784: 'http_2784', 5190: 'aol', 6667: 'IRC',
    8001: 'http_8001', 8080: 'http', 7: 'echo', 9: 'discard', 13: 'daytime',
    11: 'systat', 15: 'netstat', 42: 'name', 57: 'mtp', 95: 'supdup',
    101: 'hostnames', 105: 'csnet_ns', 245: 'link', 520: 'efs', 530: 'courier',
    532: 'remote_job', 1911: 'mtp',
}

UDP_SERVICES = {
    53: 'domain_u', 69: 'tftp_u', 123: 'ntp_u', 137: 'netbios_ns', 138: 'netbios_dgm',
    # QUIC (HTTP/3) runs over UDP 443 — closest equivalent is web traffic
    443: 'http',
}

ICMP_SERVICES = {
    0: 'ecr_i',    # echo reply
    8: 'eco_i',    # echo request (ping)
    3: 'urp_i',    # destination / port unreachable
    5: 'red_i',    # redirect
    13: 'tim_i', 14: 'tim_i',  # timestamp
    129: 'ecr_i', 128: 'eco_i', 1: 'urp_i',  # ICMPv6 equivalents
}

# Services where a completed, two-way conversation implies a logged-in session
LOGIN_SERVICES = {'http', 'ftp', 'ftp_data', 'ssh', 'telnet', 'smtp', 'pop_3', 'imap4'}

# Half-open handshakes ("SYN errors") and refused connections ("REJ errors")
SYN_ERROR_FLAGS = {'S0', 'SH', 'RSTOS0'}
REJ_ERROR_FLAGS = {'REJ'}

FRIENDLY_FLAGS = {
    'SF': 'Opened and closed normally',
    'S0': 'No reply to connection request',
    'S1': 'Open, still talking',
    'S2': 'Sender started closing',
    'S3': 'Receiver started closing',
    'REJ': 'Connection refused',
    'RSTO': 'Sender cut it off',
    'RSTR': 'Receiver cut it off',
    'RSTOS0': 'Request then sudden reset',
    'SH': 'Request then hang-up, no reply',
    'OTH': 'Joined mid-conversation',
}

TCP_FIN, TCP_SYN, TCP_RST, TCP_ACK, TCP_URG = 0x01, 0x02, 0x04, 0x10, 0x20

# Timeouts (seconds) — when a quiet conversation is considered finished
IDLE_TIMEOUT = {'tcp_open': 10.0, 'tcp_handshake': 3.0, 'udp': 4.0, 'dns': 0.6, 'icmp': 2.0}
CLOSE_GRACE = 0.4            # wait briefly after FIN/RST for trailing packets
ACTIVE_TIMEOUT = 60.0        # report long conversations at least once a minute
TIME_WINDOW = 2.0            # NSL-KDD "past 2 seconds" window
HOST_WINDOW = 255            # NSL-KDD "past N connections" window (values cap at 255)
MAX_ACTIVE_FLOWS = 20000
MAX_RESULTS = 1000
MAX_FILE_FLOWS = 5000


def find_tshark():
    """Return the path to tshark if Wireshark is installed, else None."""
    for path in TSHARK_CANDIDATES:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def _first(value):
    """tshark may print several comma-separated values (e.g. ICMP errors); keep the first."""
    if not value:
        return ''
    return value.split(',', 1)[0].strip()


def _to_int(value, default=0):
    value = _first(value)
    if not value:
        return default
    try:
        return int(value, 16) if value.startswith('0x') else int(float(value))
    except ValueError:
        return default


def is_background_address(ip):
    """Multicast / broadcast chatter (Bonjour, SSDP, DHCP...) is not a conversation."""
    if not ip:
        return True
    if ':' in ip:
        return ip.lower().startswith('ff')
    try:
        first_octet = int(ip.split('.', 1)[0])
    except ValueError:
        return True
    return 224 <= first_octet <= 239 or ip == '255.255.255.255' or ip.endswith('.255')


def describe_service(protocol, port, icmp_type=None):
    """Human-friendly service label for the dashboard."""
    names = {
        80: 'Web (HTTP)', 443: 'Secure web (HTTPS)', 53: 'Name lookup (DNS)',
        22: 'Remote login (SSH)', 21: 'File transfer (FTP)', 25: 'Email (SMTP)',
        123: 'Clock sync (NTP)', 993: 'Email (IMAPS)', 5223: 'Apple push',
        143: 'Email (IMAP)', 110: 'Email (POP3)', 23: 'Telnet', 3478: 'Calls (STUN)',
    }
    if protocol == 'icmp':
        return {0: 'Ping reply', 8: 'Ping', 3: 'Unreachable notice'}.get(icmp_type, 'Network notice (ICMP)')
    if port in names:
        label = names[port]
        if protocol == 'udp' and port == 443:
            label = 'Secure web (QUIC)'
        return label
    return f'Port {port}'


# ─── Conversation (flow) model ───

class Flow:
    """One conversation between an originator (who spoke first) and a responder."""

    __slots__ = (
        'seq', 'key', 'protocol', 'src', 'sport', 'dst', 'dport', 'start', 'last',
        'src_bytes', 'dst_bytes', 'src_pkts', 'dst_pkts', 'urgent', 'icmp_type',
        'orig_syn', 'resp_synack', 'orig_fin', 'resp_fin', 'orig_rst', 'resp_rst',
        'closed_at', 'chunk',
    )

    def __init__(self, seq, key, protocol, src, sport, dst, dport, ts):
        self.seq = seq
        self.key = key
        self.protocol = protocol
        self.src, self.sport, self.dst, self.dport = src, sport, dst, dport
        self.start = self.last = ts
        self.src_bytes = self.dst_bytes = 0
        self.src_pkts = self.dst_pkts = 0
        self.urgent = 0
        self.icmp_type = None
        self.orig_syn = self.resp_synack = False
        self.orig_fin = self.resp_fin = False
        self.orig_rst = self.resp_rst = False
        self.closed_at = None
        self.chunk = 0

    @property
    def service(self):
        if self.protocol == 'icmp':
            return ICMP_SERVICES.get(self.icmp_type, 'eco_i')
        table = TCP_SERVICES if self.protocol == 'tcp' else UDP_SERVICES
        if self.dport in table:
            return table[self.dport]
        if 6000 <= self.dport <= 6063:
            return 'X11'
        return 'private' if self.dport >= 1024 else 'other'

    @property
    def flag(self):
        """Map the TCP handshake/teardown we observed to the NSL-KDD connection flag."""
        if self.protocol != 'tcp':
            return 'SF'
        if not self.orig_syn and not self.resp_synack:
            return 'OTH'
        established = self.orig_syn and self.resp_synack
        if not established:
            if self.resp_rst:
                return 'REJ'
            if self.orig_rst:
                return 'RSTOS0'
            if self.orig_fin:
                return 'SH'
            return 'S0'
        if self.orig_rst:
            return 'RSTO'
        if self.resp_rst:
            return 'RSTR'
        if self.orig_fin and self.resp_fin:
            return 'SF'
        if self.orig_fin:
            return 'S2'
        if self.resp_fin:
            return 'S3'
        return 'S1'


class FlowTracker:
    """
    Groups packets into conversations and rebuilds NSL-KDD features when a
    conversation finishes. Not thread-safe on its own; callers hold a lock.
    """

    def __init__(self, on_complete):
        self.on_complete = on_complete
        self.flows = {}
        self.recent = deque(maxlen=4000)   # recently started flows, for window features
        self.seq = 0
        self.packets = 0
        self.background_skipped = 0
        self.unparsed = 0
        self.local_addresses = self._local_addresses()

    @staticmethod
    def _local_addresses():
        addrs = {'127.0.0.1', '::1'}
        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None):
                addrs.add(info[4][0])
        except OSError:
            pass
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('192.0.2.1', 9))  # TEST-NET address, no packet is sent for UDP connect
                addrs.add(s.getsockname()[0])
        except OSError:
            pass
        return addrs

    # ── packet intake ──
    def add_line(self, line):
        parts = line.rstrip('\n').split('\t')
        if len(parts) < len(TSHARK_FIELDS):
            parts += [''] * (len(TSHARK_FIELDS) - len(parts))
        try:
            ts = float(_first(parts[0]))
        except ValueError:
            self.unparsed += 1
            return

        src = _first(parts[1]) or _first(parts[3])
        dst = _first(parts[2]) or _first(parts[4])
        proto_num = _to_int(parts[5], -1) if parts[5] else _to_int(parts[6], -1)
        if not src or not dst:
            self.unparsed += 1
            return

        self.packets += 1
        if is_background_address(dst) or is_background_address(src):
            self.background_skipped += 1
            return

        if proto_num == 6:
            protocol = 'tcp'
            sport, dport = _to_int(parts[7]), _to_int(parts[8])
            payload = _to_int(parts[12])
            tcp_flags = _to_int(parts[11])
            icmp_type = None
        elif proto_num == 17:
            protocol = 'udp'
            sport, dport = _to_int(parts[9]), _to_int(parts[10])
            payload = max(0, _to_int(parts[13]) - 8)
            tcp_flags = 0
            icmp_type = None
        elif proto_num in (1, 58):
            protocol = 'icmp'
            sport = dport = 0
            payload = _to_int(parts[16])
            tcp_flags = 0
            icmp_type = _to_int(parts[14], -1) if parts[14] else _to_int(parts[15], -1)
        else:
            self.unparsed += 1
            return

        self._add_packet(ts, protocol, src, sport, dst, dport, payload, tcp_flags, icmp_type)

    def _add_packet(self, ts, protocol, src, sport, dst, dport, payload, tcp_flags, icmp_type):
        fwd_key = (protocol, src, sport, dst, dport)
        rev_key = (protocol, dst, dport, src, sport)

        flow = self.flows.get(fwd_key)
        is_orig = True
        if flow is None:
            flow = self.flows.get(rev_key)
            is_orig = False
        if flow is None:
            # Missed the SYN but caught the SYN-ACK: the other side started the conversation
            if protocol == 'tcp' and (tcp_flags & TCP_SYN) and (tcp_flags & TCP_ACK):
                flow = self._new_flow(rev_key, protocol, dst, dport, src, sport, ts)
                is_orig = False
            else:
                flow = self._new_flow(fwd_key, protocol, src, sport, dst, dport, ts)
                is_orig = True
                if protocol == 'icmp':
                    flow.icmp_type = icmp_type

        flow.last = max(flow.last, ts)
        if is_orig:
            flow.src_bytes += payload
            flow.src_pkts += 1
        else:
            flow.dst_bytes += payload
            flow.dst_pkts += 1

        if protocol == 'tcp':
            if tcp_flags & TCP_URG:
                flow.urgent += 1
            if tcp_flags & TCP_SYN:
                if is_orig and not (tcp_flags & TCP_ACK):
                    flow.orig_syn = True
                elif not is_orig and (tcp_flags & TCP_ACK):
                    flow.resp_synack = True
            if tcp_flags & TCP_FIN:
                if is_orig:
                    flow.orig_fin = True
                else:
                    flow.resp_fin = True
            if tcp_flags & TCP_RST:
                if is_orig:
                    flow.orig_rst = True
                else:
                    flow.resp_rst = True
            if (flow.orig_fin and flow.resp_fin) or flow.orig_rst or flow.resp_rst:
                flow.closed_at = flow.closed_at or ts

    def _new_flow(self, key, protocol, src, sport, dst, dport, ts):
        if len(self.flows) >= MAX_ACTIVE_FLOWS:
            oldest = min(self.flows.values(), key=lambda f: f.last)
            self._finish(oldest, ts)
        self.seq += 1
        flow = Flow(self.seq, key, protocol, src, sport, dst, dport, ts)
        self.flows[key] = flow
        self.recent.append(flow)
        return flow

    # ── finishing conversations ──
    def sweep(self, now):
        """Finish conversations that have gone quiet or were closed."""
        for flow in list(self.flows.values()):
            idle = now - flow.last
            if flow.closed_at is not None and now - flow.closed_at >= CLOSE_GRACE:
                self._finish(flow, now)
            elif flow.protocol == 'tcp':
                limit = IDLE_TIMEOUT['tcp_open'] if (flow.orig_syn and flow.resp_synack) or flow.flag == 'OTH' \
                    else IDLE_TIMEOUT['tcp_handshake']
                if idle >= limit:
                    self._finish(flow, now)
                elif now - flow.start >= ACTIVE_TIMEOUT * (flow.chunk + 1):
                    self._report(flow, partial=True)
            elif flow.protocol == 'udp':
                is_dns_done = flow.dport == 53 and flow.dst_pkts > 0
                limit = IDLE_TIMEOUT['dns'] if is_dns_done else IDLE_TIMEOUT['udp']
                if idle >= limit:
                    self._finish(flow, now)
                elif now - flow.start >= ACTIVE_TIMEOUT * (flow.chunk + 1):
                    self._report(flow, partial=True)
            elif idle >= IDLE_TIMEOUT['icmp']:
                self._finish(flow, now)

    def flush_all(self):
        for flow in list(self.flows.values()):
            self._finish(flow, flow.last)

    def _finish(self, flow, now):
        self.flows.pop(flow.key, None)
        self._report(flow, partial=False)

    def _report(self, flow, partial):
        flow.chunk += 1
        record = self.build_record(flow, partial)
        self.on_complete(record)

    # ── feature engineering (NSL-KDD compatible) ──
    def build_record(self, flow, partial=False):
        service = flow.service
        flag = flow.flag
        earlier = [g for g in self.recent if g.seq <= flow.seq]

        # Time-based window: connections that started in the 2 seconds before this one
        window = [g for g in earlier if flow.start - TIME_WINDOW <= g.start <= flow.start]
        same_host = [g for g in window if g.dst == flow.dst]
        same_srv = [g for g in window if g.dport == flow.dport and g.protocol == flow.protocol]
        count = max(1, len(same_host))
        srv_count = max(1, len(same_srv))

        def rate(items, flags):
            return round(sum(1 for g in items if g.flag in flags) / len(items), 2) if items else 0.0

        serror_rate = rate(same_host, SYN_ERROR_FLAGS)
        rerror_rate = rate(same_host, REJ_ERROR_FLAGS)
        srv_serror_rate = rate(same_srv, SYN_ERROR_FLAGS)
        srv_rerror_rate = rate(same_srv, REJ_ERROR_FLAGS)
        same_srv_rate = round(sum(1 for g in same_host if g.dport == flow.dport) / len(same_host), 2) if same_host else 1.0
        diff_srv_rate = round(1.0 - same_srv_rate, 2)
        srv_diff_host_rate = round(sum(1 for g in same_srv if g.dst != flow.dst) / len(same_srv), 2) if same_srv else 0.0

        # Host-based window: the last N connections
        last_n = earlier[-HOST_WINDOW:]
        host_conns = [g for g in last_n if g.dst == flow.dst]
        host_srv_conns = [g for g in last_n if g.dport == flow.dport and g.protocol == flow.protocol]
        dst_host_count = min(255, len(host_conns))
        dst_host_srv_count = min(255, len(host_srv_conns))

        def host_rate(items, predicate):
            return round(sum(1 for g in items if predicate(g)) / len(items), 2) if items else 0.0

        record_features = {
            'duration': int(max(0.0, flow.last - flow.start)),
            'protocol_type': flow.protocol,
            'service': service,
            'flag': flag,
            'src_bytes': int(flow.src_bytes),
            'dst_bytes': int(flow.dst_bytes),
            'land': 1 if (flow.src == flow.dst and flow.sport == flow.dport) else 0,
            'wrong_fragment': 0,
            'urgent': int(flow.urgent),
            # Content values below live in server logs, not packets -> not observable
            'hot': 0, 'num_failed_logins': 0, 'num_compromised': 0, 'root_shell': 0,
            'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
            'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
            'logged_in': 1 if (service in LOGIN_SERVICES and flag in ('SF', 'S1', 'S2', 'S3')
                               and flow.src_bytes > 0 and flow.dst_bytes > 0) else 0,
            'count': count,
            'srv_count': srv_count,
            'serror_rate': serror_rate,
            'srv_serror_rate': srv_serror_rate,
            'rerror_rate': rerror_rate,
            'srv_rerror_rate': srv_rerror_rate,
            'same_srv_rate': same_srv_rate,
            'diff_srv_rate': diff_srv_rate,
            'srv_diff_host_rate': srv_diff_host_rate,
            'dst_host_count': dst_host_count,
            'dst_host_srv_count': dst_host_srv_count,
            'dst_host_same_srv_rate': host_rate(host_conns, lambda g: g.dport == flow.dport),
            'dst_host_diff_srv_rate': host_rate(host_conns, lambda g: g.dport != flow.dport),
            'dst_host_same_src_port_rate': host_rate(host_conns, lambda g: g.sport == flow.sport),
            'dst_host_srv_diff_host_rate': host_rate(host_srv_conns, lambda g: g.dst != flow.dst),
            'dst_host_serror_rate': host_rate(host_conns, lambda g: g.flag in SYN_ERROR_FLAGS),
            'dst_host_srv_serror_rate': host_rate(host_srv_conns, lambda g: g.flag in SYN_ERROR_FLAGS),
            'dst_host_rerror_rate': host_rate(host_conns, lambda g: g.flag in REJ_ERROR_FLAGS),
            'dst_host_srv_rerror_rate': host_rate(host_srv_conns, lambda g: g.flag in REJ_ERROR_FLAGS),
        }

        if flow.src in self.local_addresses and flow.dst in self.local_addresses:
            direction = 'inside'
        elif flow.src in self.local_addresses:
            direction = 'outgoing'
        elif flow.dst in self.local_addresses:
            direction = 'incoming'
        else:
            direction = 'passing'

        return {
            'src_ip': flow.src,
            'src_port': flow.sport,
            'dst_ip': flow.dst,
            'dst_port': flow.dport,
            'protocol': flow.protocol,
            'service': service,
            'service_label': describe_service(flow.protocol, flow.dport, flow.icmp_type),
            'flag': flag,
            'flag_label': FRIENDLY_FLAGS.get(flag, flag),
            'duration': record_features['duration'],
            'src_bytes': record_features['src_bytes'],
            'dst_bytes': record_features['dst_bytes'],
            'packets': flow.src_pkts + flow.dst_pkts,
            'direction': direction,
            'partial': partial,
            'started_at': datetime.fromtimestamp(flow.start).isoformat(),
            'features': record_features,
        }


# ─── Live capture engine ───

class LiveCaptureEngine:
    """Runs tshark in the background and streams AI verdicts to subscribers. Watch-only."""

    def __init__(self):
        self.tshark = find_tshark()
        self.version = None
        self.lock = threading.RLock()
        self.proc = None
        self.interface = None
        self.started_at = None
        self.source = None
        self.error = None
        self.stderr_tail = deque(maxlen=20)
        self.tracker = None
        self.results = deque(maxlen=MAX_RESULTS)
        self.subscribers = []
        self.work_queue = queue.Queue(maxsize=2000)
        self.classifier = None
        self.event_counter = 0
        self.self_test_running = False
        self.stats = self._empty_stats()
        self._worker = threading.Thread(target=self._classify_loop, name='live-classifier', daemon=True)
        self._worker.start()
        atexit.register(self.stop)

    @staticmethod
    def _empty_stats():
        return {
            'packets': 0, 'background_skipped': 0, 'conversations': 0,
            'safe': 0, 'flagged': 0, 'dropped': 0,
            'categories': {'Normal': 0, 'DoS': 0, 'Probe': 0, 'R2L': 0, 'U2R': 0, 'Attack': 0},
        }

    # ── setup helpers ──
    def get_classifier(self):
        if self.classifier is None:
            from src.threat_classifier import ThreatClassifier
            self.classifier = ThreatClassifier()
            self.classifier.load_models()
        return self.classifier

    def get_version(self):
        if self.tshark and self.version is None:
            try:
                out = subprocess.run([self.tshark, '-v'], capture_output=True, text=True, timeout=10).stdout
                match = re.search(r'TShark \(Wireshark\) ([\d.]+)', out)
                self.version = match.group(1) if match else out.splitlines()[0] if out else 'unknown'
            except (OSError, subprocess.SubprocessError):
                self.version = 'unknown'
        return self.version

    @staticmethod
    def default_interface():
        try:
            out = subprocess.run(['route', '-n', 'get', 'default'], capture_output=True, text=True, timeout=5).stdout
            match = re.search(r'interface:\s*(\S+)', out)
            if match:
                return match.group(1)
        except (OSError, subprocess.SubprocessError):
            pass
        return 'en0'

    def list_interfaces(self):
        if not self.tshark:
            return []
        try:
            out = subprocess.run([self.tshark, '-D'], capture_output=True, text=True, timeout=15).stdout
        except (OSError, subprocess.SubprocessError):
            return []
        default = self.default_interface()
        interfaces = []
        for line in out.splitlines():
            match = re.match(r'\s*\d+\.\s+(\S+)(?:\s+\((.+)\))?', line)
            if not match:
                continue
            name, label = match.group(1), match.group(2) or ''
            if name.startswith(HIDDEN_INTERFACE_PREFIXES) or name == 'bridge0':
                continue
            if name == 'lo0' or 'loopback' in label.lower():
                friendly = 'This Mac only (Loopback) — use for the safe self-test'
            elif name == default:
                friendly = f'{label or name} — your internet connection'
            else:
                friendly = label or name
            interfaces.append({'name': name, 'label': friendly, 'is_default': name == default})
        interfaces.sort(key=lambda i: (not i['is_default'], i['name'] != 'lo0', i['name']))
        return interfaces

    # ── control ──
    def status(self):
        with self.lock:
            running = self.proc is not None and self.proc.poll() is None
            if self.tracker:
                self.stats['packets'] = self.tracker.packets
                self.stats['background_skipped'] = self.tracker.background_skipped
            return {
                'available': bool(self.tshark),
                'tshark_path': self.tshark,
                'tshark_version': self.get_version(),
                'running': running,
                'interface': self.interface,
                'started_at': self.started_at,
                'error': self.error,
                'active_conversations': len(self.tracker.flows) if (self.tracker and running) else 0,
                'stats': dict(self.stats, categories=dict(self.stats['categories'])),
                'auto_block': False,
                'self_test_running': self.self_test_running,
            }

    def start(self, interface):
        if not self.tshark:
            raise RuntimeError('Wireshark (tshark) was not found on this computer.')
        valid = {i['name'] for i in self.list_interfaces()}
        if interface not in valid:
            raise ValueError(f'Unknown network interface: {interface}')

        self.stop()
        api_port = os.environ.get('PORT', '5050')
        cmd = [
            self.tshark, '-i', interface, '-n', '-l',
            '-f', f'(ip or ip6) and not tcp port {api_port}',
            '-T', 'fields', '-E', 'separator=/t', '-E', 'occurrence=f',
        ]
        for field in TSHARK_FIELDS:
            cmd += ['-e', field]

        with self.lock:
            self.error = None
            self.stderr_tail.clear()
            self.tracker = FlowTracker(self._enqueue)
            self.interface = interface
            self.started_at = datetime.now().isoformat()
            self.source = 'live'
            self.proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1, errors='replace',
            )
            proc = self.proc

        threading.Thread(target=self._read_stdout, args=(proc,), name='tshark-stdout', daemon=True).start()
        threading.Thread(target=self._read_stderr, args=(proc,), name='tshark-stderr', daemon=True).start()
        threading.Thread(target=self._sweep_loop, args=(proc,), name='flow-sweeper', daemon=True).start()

        # Give tshark a moment to report permission problems
        time.sleep(1.2)
        if proc.poll() is not None:
            with self.lock:
                self.error = self._explain_error()
            raise RuntimeError(self.error)
        return self.status()

    def stop(self):
        with self.lock:
            proc = self.proc
            self.proc = None
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        with self.lock:
            if self.tracker:
                self.tracker.flush_all()
        return True

    def clear(self):
        with self.lock:
            self.results.clear()
            self.stats = self._empty_stats()
            if self.tracker:
                self.tracker.packets = 0
                self.tracker.background_skipped = 0

    def _explain_error(self):
        text = ' '.join(self.stderr_tail)
        lower = text.lower()
        if 'permission' in lower or 'bpf' in lower or "don't have permission" in lower:
            return ('macOS did not allow packet capture. Install Wireshark\'s "ChmodBPF" helper '
                    '(Wireshark → Install ChmodBPF) or add your user to the access_bpf group, then try again.')
        return text.strip() or 'tshark stopped unexpectedly.'

    # ── background threads ──
    def _read_stdout(self, proc):
        for line in proc.stdout:
            with self.lock:
                if self.tracker is not None and proc is self.proc:
                    self.tracker.add_line(line)

    def _read_stderr(self, proc):
        for line in proc.stderr:
            line = line.strip()
            if line and not line.startswith('Capturing on'):
                self.stderr_tail.append(line)
        proc.wait()
        if proc.returncode not in (None, 0, -15) and proc is self.proc:
            with self.lock:
                self.error = self._explain_error()

    def _sweep_loop(self, proc):
        while proc.poll() is None:
            time.sleep(0.5)
            with self.lock:
                if self.tracker is not None and proc is self.proc:
                    self.tracker.sweep(time.time())
        with self.lock:
            if proc.returncode not in (None, 0, -15) and not self.error:
                self.error = self._explain_error()

    def _enqueue(self, record):
        record['source'] = self.source or 'live'
        try:
            self.work_queue.put_nowait(record)
        except queue.Full:
            self.stats['dropped'] += 1

    def _classify_loop(self):
        while True:
            record = self.work_queue.get()
            try:
                result = self.classify_record(record)
                self._publish(result)
            except Exception as exc:  # keep the worker alive no matter what
                self.stderr_tail.append(f'AI check failed: {exc}')

    def classify_record(self, record):
        verdict = self.get_classifier().classify_raw_connection(record['features'])
        with self.lock:
            self.event_counter += 1
            number = self.event_counter
        category = str(verdict.get('attack_category', 'Normal'))
        severity = str(verdict.get('severity', 'Info')).lower()
        votes = {}
        for name, vote in (verdict.get('model_votes') or {}).items():
            pred = vote.get('prediction')
            if isinstance(pred, (int, float)) and not isinstance(pred, bool):
                pred = 'Attack' if int(pred) == 1 else 'Normal'
            votes[name] = {'prediction': str(pred), 'confidence': round(float(vote.get('confidence', vote.get('anomaly_score', 0.0))), 4)}

        return {
            'id': f"{'LIVE' if record.get('source') == 'live' else 'FILE'}-{number:06d}",
            'timestamp': datetime.now().isoformat(),
            **{k: v for k, v in record.items() if k != 'features'},
            'is_attack': bool(verdict.get('is_attack')),
            'attack_category': category,
            'severity': severity,
            'confidence': round(float(verdict.get('confidence', 0.0)), 4),
            'anomaly_score': round(float(verdict.get('anomaly_score', 0.0)), 4),
            'model_votes': votes,
            'key_indicators': verdict.get('key_indicators', []),
            'window': {k: record['features'][k] for k in (
                'count', 'srv_count', 'serror_rate', 'rerror_rate', 'same_srv_rate',
                'dst_host_count', 'dst_host_srv_count', 'logged_in')},
            'auto_blocked': False,
        }

    def _count(self, result):
        self.stats['conversations'] += 1
        if result['is_attack']:
            self.stats['flagged'] += 1
        else:
            self.stats['safe'] += 1
        cat = result['attack_category']
        self.stats['categories'][cat] = self.stats['categories'].get(cat, 0) + 1

    def _publish(self, result):
        with self.lock:
            self.results.append(result)
            self._count(result)
            subscribers = list(self.subscribers)
        for sub in subscribers:
            try:
                sub.put_nowait(result)
            except queue.Full:
                pass

    # ── subscriptions (Server-Sent Events) ──
    def subscribe(self):
        sub = queue.Queue(maxsize=500)
        with self.lock:
            self.subscribers.append(sub)
        return sub

    def unsubscribe(self, sub):
        with self.lock:
            if sub in self.subscribers:
                self.subscribers.remove(sub)

    def get_results(self, limit=200):
        with self.lock:
            return list(self.results)[-limit:][::-1]

    # ── saved Wireshark files (.pcap / .pcapng) ──
    def analyze_file(self, path, filename='capture.pcap'):
        if not self.tshark:
            raise RuntimeError('Wireshark (tshark) was not found on this computer.')
        records = []
        tracker = FlowTracker(records.append)
        cmd = [self.tshark, '-r', path, '-n', '-T', 'fields', '-E', 'separator=/t', '-E', 'occurrence=f']
        for field in TSHARK_FIELDS:
            cmd += ['-e', field]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors='replace')
        last_sweep = None
        stderr = ''
        try:
            for line in proc.stdout:
                tracker.add_line(line)
                # Use packet timestamps as the clock so timeouts behave like they did live
                try:
                    ts = float(_first(line.split('\t', 1)[0]))
                except ValueError:
                    continue
                if last_sweep is None or ts - last_sweep >= 0.5:
                    tracker.sweep(ts)
                    last_sweep = ts
                if len(records) >= MAX_FILE_FLOWS:
                    proc.kill()
                    break
            stderr = proc.stderr.read() if proc.stderr else ''
        finally:
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
            proc.wait()
        tracker.flush_all()
        if tracker.packets == 0:
            raise ValueError(stderr.strip() or 'No IP packets were found in this file.')

        previous_source = self.source
        self.source = 'file'
        results = []
        try:
            for record in records[:MAX_FILE_FLOWS]:
                record['source'] = 'file'
                record['file_name'] = filename
                result = self.classify_record(record)
                results.append(result)
                self._publish(result)
        finally:
            self.source = previous_source
        return {
            'file_name': filename,
            'packets': tracker.packets,
            'background_skipped': tracker.background_skipped,
            'conversations': len(results),
            'flagged': sum(1 for r in results if r['is_attack']),
            'truncated': len(records) >= MAX_FILE_FLOWS,
        }

    # ── safe self-test: knock on closed ports of THIS Mac only ──
    def run_self_test(self, ports=range(1, 301)):
        if self.self_test_running:
            return False

        def knock():
            self.self_test_running = True
            try:
                for port in ports:
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.settimeout(0.15)
                            s.connect_ex(('127.0.0.1', port))
                    except OSError:
                        pass
                    time.sleep(0.004)
            finally:
                self.self_test_running = False

        threading.Thread(target=knock, name='self-test-scan', daemon=True).start()
        return True

    def export_csv(self):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            'ID', 'Time', 'Source', 'From IP', 'From Port', 'To IP', 'To Port', 'Protocol',
            'Service', 'Status', 'Seconds', 'Bytes Sent', 'Bytes Received', 'Packets',
            'AI Verdict', 'Risk', 'Unusual Score', 'AI Confidence', 'Auto Blocked',
        ])
        for r in self.get_results(MAX_RESULTS)[::-1]:
            writer.writerow([
                r['id'], r['timestamp'], r.get('source', 'live'), r['src_ip'], r['src_port'],
                r['dst_ip'], r['dst_port'], r['protocol'], r['service'], r['flag'], r['duration'],
                r['src_bytes'], r['dst_bytes'], r['packets'], r['attack_category'], r['severity'],
                r['anomaly_score'], r['confidence'], 'no',
            ])
        return output.getvalue()


_engine = None
_engine_lock = threading.Lock()


def get_live_engine():
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = LiveCaptureEngine()
        return _engine
