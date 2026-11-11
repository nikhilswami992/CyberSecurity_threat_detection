/**
 * ThreatGuard AI // Live Security Alerts Feed & Stream Controller
 */

const feedContainer = document.getElementById('threat-feed-container');
const feedEmptyState = document.getElementById('feed-empty-state');
const blocklistContainer = document.getElementById('blocked-ip-container');
const blocklistEmptyState = document.getElementById('blocklist-empty-state');
const pauseBtn = document.getElementById('pause-feed-btn');

let eventSource = null;
let isPaused = false;
let blockedIPs = new Set();
window.autoBlockEnabled = true;

const FRIENDLY_ATTACK_NAMES = {
    DoS: 'Server Flood (DoS)',
    Probe: 'Port Scan (Probe)',
    R2L: 'Login Hack (R2L)',
    U2R: 'Admin Takeover (U2R)',
    Normal: 'Normal Traffic'
};

function initThreatStream() {
    if (eventSource) {
        eventSource.close();
    }

    const baseUrl = window.API_BASE_URL || (window.location.origin.startsWith('http')
        ? `${window.location.origin}/api`
        : 'http://localhost:5050/api');

    eventSource = new EventSource(`${baseUrl}/events/stream`);

    eventSource.onopen = () => {
        const dot = document.getElementById('stream-dot');
        if (dot) dot.style.backgroundColor = 'var(--primary-600)';
    };

    eventSource.onmessage = (e) => {
        if (isPaused) return;

        try {
            const event = JSON.parse(e.data);

            window.allEventsHistory = window.allEventsHistory || [];
            window.allEventsHistory.unshift(event);
            if (window.allEventsHistory.length > 500) {
                window.allEventsHistory.pop();
            }

            if (window.onNewEventReceived) {
                window.onNewEventReceived(event);
            }

            if (window.aggregateEventForChart) {
                window.aggregateEventForChart(event);
            }

            if (event.is_attack || event.anomaly_score > 0.5) {
                addThreatToFeed(event);
            }

            if (window.autoBlockEnabled && (event.is_blocked || (event.severity === 'critical' && !blockedIPs.has(event.src_ip)))) {
                const label = FRIENDLY_ATTACK_NAMES[event.attack_category] || event.attack_category;
                addIPToBlocklist(event.src_ip, `${label} (${event.id})`);
            }
        } catch (error) {
            console.error('Error parsing telemetry event:', error);
        }
    };

    eventSource.onerror = () => {
        const dot = document.getElementById('stream-dot');
        if (dot) dot.style.backgroundColor = 'var(--accent-red-600)';
    };
}

function addThreatToFeed(event) {
    if (feedEmptyState) {
        feedEmptyState.style.display = 'none';
    }

    const timeStr = new Date(event.timestamp).toLocaleTimeString('en-US', { hour12: false });

    const item = document.createElement('div');
    item.className = 'threat-item';
    item.setAttribute('role', 'button');
    item.setAttribute('tabindex', '0');
    item.title = 'Click to view connection details';

    let barColor = 'var(--primary-600)';
    if (event.anomaly_score > 0.8) barColor = 'var(--accent-red-600)';
    else if (event.anomaly_score > 0.5) barColor = 'var(--accent-ochre-500)';

    const friendlyTitle = FRIENDLY_ATTACK_NAMES[event.attack_category] || `${event.attack_category} Alert`;

    item.innerHTML = `
        <div class="threat-severity ${event.severity}"></div>
        <div class="threat-info">
            <div class="threat-title">
                <span>${friendlyTitle}</span>
                <span class="mono" style="font-size:0.74rem;color:var(--primary-600);font-weight:700;">${event.id}</span>
                <span class="mono" style="font-size:0.74rem;color:var(--neutral-500);">→ ${event.device}</span>
            </div>
            <div class="threat-meta">
                From ${event.src_ip}:${event.src_port} to ${event.dst_ip}:${event.dst_port}
                · ${event.protocol.toUpperCase()}/${event.service}
            </div>
        </div>
        <div class="anomaly-indicator" title="Unusual Score: ${(event.anomaly_score).toFixed(2)} | AI Confidence: ${(event.confidence * 100).toFixed(1)}%">
            <span class="anomaly-score">Risk: ${(event.anomaly_score).toFixed(2)}</span>
            <div class="anomaly-bar">
                <div class="anomaly-bar-fill" style="width: ${Math.min(100, event.anomaly_score * 100)}%; background-color: ${barColor}"></div>
            </div>
        </div>
        <div class="threat-badge ${event.severity}">${event.response}</div>
        <div class="threat-time">${timeStr}</div>
    `;

    item.addEventListener('click', () => {
        if (window.openPacketForensics) {
            window.openPacketForensics(event);
        }
    });

    item.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            if (window.openPacketForensics) {
                window.openPacketForensics(event);
            }
        }
    });

    feedContainer.insertBefore(item, feedContainer.firstChild);

    const threatItems = feedContainer.querySelectorAll('.threat-item');
    if (threatItems.length > 50) {
        threatItems[threatItems.length - 1].remove();
    }
}

async function addIPToBlocklist(ip, reason, skipApiCall = false) {
    if (!ip || blockedIPs.has(ip)) return;

    blockedIPs.add(ip);

    const baseUrl = window.API_BASE_URL || (window.location.origin.startsWith('http')
        ? `${window.location.origin}/api`
        : 'http://localhost:5050/api');

    if (!skipApiCall) {
        try {
            await fetch(`${baseUrl}/block`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip })
            });
        } catch (e) {
            console.error('API Block failed:', e);
        }
    }

    if (blocklistEmptyState) {
        blocklistEmptyState.style.display = 'none';
    }

    const timeStr = new Date().toLocaleTimeString('en-US', { hour12: false });

    const item = document.createElement('div');
    item.className = 'blocked-ip-item';
    item.dataset.ip = ip;

    item.innerHTML = `
        <div class="blocked-ip-info">
            <i class="fa-solid fa-ban blocked-ip-icon" aria-hidden="true"></i>
            <div>
                <div class="blocked-ip-addr">${ip}</div>
                <div class="blocked-ip-time">${timeStr} · ${reason || 'Blocked Automatically'}</div>
            </div>
        </div>
        <button type="button" class="unblock-btn">UNBLOCK</button>
    `;

    const unblockBtn = item.querySelector('.unblock-btn');
    if (unblockBtn) {
        unblockBtn.addEventListener('click', () => window.unblockIP(ip));
    }

    if (blocklistContainer) {
        blocklistContainer.insertBefore(item, blocklistContainer.firstChild);
    }

    if (!skipApiCall && window.fetchStats) {
        window.fetchStats();
    }
}

window.addIPToBlocklist = addIPToBlocklist;

window.unblockIP = async function(ip) {
    const baseUrl = window.API_BASE_URL || (window.location.origin.startsWith('http')
        ? `${window.location.origin}/api`
        : 'http://localhost:5050/api');

    try {
        await fetch(`${baseUrl}/unblock`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });

        blockedIPs.delete(ip);

        if (window.allEventsHistory) {
            window.allEventsHistory.forEach(e => {
                if (e.src_ip === ip) e.is_blocked = false;
            });
        }

        if (blocklistContainer) {
            const item = blocklistContainer.querySelector(`[data-ip="${ip}"]`);
            if (item) {
                item.style.opacity = '0';
                setTimeout(() => {
                    item.remove();
                    if (blockedIPs.size === 0 && blocklistEmptyState) {
                        blocklistEmptyState.style.display = 'flex';
                    }
                }, 200);
            }
        }
        if (window.renderThreatsTable) window.renderThreatsTable();
        if (window.fetchFullBlocklist) window.fetchFullBlocklist();
        if (window.fetchStats) window.fetchStats();
        if (window.showToast) {
            window.showToast(`Unblocked IP address ${ip}`, 'info');
        }
    } catch (error) {
        console.error('Failed to unblock IP:', error);
    }
};

function toggleStreamPause() {
    isPaused = !isPaused;
    const modalStreamBtn = document.getElementById('modal-toggle-stream-btn');
    const rightCounter = document.getElementById('right-alert-counter');

    if (isPaused) {
        if (pauseBtn) {
            pauseBtn.innerHTML = '<span class="status-dot" id="stream-dot" style="background-color:var(--accent-ochre-500);"></span> <i class="fa-solid fa-play" aria-hidden="true"></i> <span id="pause-feed-label">Live Feed: Paused</span>';
        }
        if (rightCounter) rightCounter.textContent = 'PAUSED';
        if (modalStreamBtn) {
            modalStreamBtn.textContent = 'Paused (Click to Resume)';
            modalStreamBtn.className = 'btn btn-sm btn-secondary';
        }
    } else {
        if (pauseBtn) {
            pauseBtn.innerHTML = '<span class="status-dot" id="stream-dot" style="background-color:var(--primary-600);"></span> <i class="fa-solid fa-pause" aria-hidden="true"></i> <span id="pause-feed-label">Live Feed: On</span>';
        }
        if (rightCounter) rightCounter.textContent = 'LIVE';
        if (modalStreamBtn) {
            modalStreamBtn.textContent = 'Active';
            modalStreamBtn.className = 'btn btn-sm btn-primary';
        }
    }
    return isPaused;
}

window.toggleStreamPause = toggleStreamPause;

if (pauseBtn) {
    pauseBtn.addEventListener('click', toggleStreamPause);
}

async function fetchInitialBlocklist() {
    const baseUrl = window.API_BASE_URL || (window.location.origin.startsWith('http')
        ? `${window.location.origin}/api`
        : 'http://localhost:5050/api');

    try {
        const res = await fetch(`${baseUrl}/blocked`);
        if (res.ok) {
            const data = await res.json();
            (data.blocked_ips || []).forEach(ip => {
                addIPToBlocklist(ip, 'Blocked by Firewall Rule', true);
            });
        }
    } catch (e) {
        console.error('Failed to fetch initial blocklist:', e);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    initThreatStream();
    fetchInitialBlocklist();
});
