/**
 * ThreatGuard AI — Main UI & Easy-to-Understand Security Controller
 */

const API_BASE_URL = window.location.origin.startsWith('http')
    ? `${window.location.origin}/api`
    : 'http://localhost:5050/api';
window.API_BASE_URL = API_BASE_URL;

// ─── DOM References ───
const clockElement = document.getElementById('clock');
const navItems = document.querySelectorAll('.nav-item');
const pageTitle = document.getElementById('page-title');
const sidebar = document.getElementById('sidebar');
const sidebarBackdrop = document.getElementById('sidebar-backdrop');
const mobileMenuBtn = document.getElementById('mobile-menu-btn');

const views = {
    dashboard: document.getElementById('view-dashboard'),
    threats: document.getElementById('view-threats'),
    sandbox: document.getElementById('view-sandbox'),
    siem: document.getElementById('view-siem'),
    blocklist: document.getElementById('view-blocklist'),
    models: document.getElementById('view-models'),
    live: document.getElementById('view-live')
};

const viewTitles = {
    dashboard: '01 // Live Overview — Real-Time AI Threat Detection',
    threats: '02 // Threat Log — All Checked Network Connections',
    sandbox: '03 // Test a Packet — Interactive AI Threat Tester',
    siem: '04 // Security Database — SQL Search & Threat Lists',
    blocklist: '05 // Blocked IPs — Automatic Firewall Rules',
    models: '06 // AI Accuracy — 5 Machine Learning Model Results',
    live: '07 // Live Wireshark — Real Network Traffic (Watch-Only)'
};

const FRIENDLY_CATEGORY_LABELS = {
    Normal: 'Safe / Normal',
    DoS: 'DoS (Server Flood)',
    Probe: 'Port Scan (Probe)',
    R2L: 'Login Hack (R2L)',
    U2R: 'Admin Takeover (U2R)',
    Attack: 'Suspicious Pattern'
};

// Stats Elements
const statTotal = document.getElementById('stat-total');
const statAttacks = document.getElementById('stat-attacks');
const statBlocked = document.getElementById('stat-blocked');
const attackRate = document.getElementById('attack-rate');
const statLatency = document.getElementById('stat-latency');

// Active filter state
let activeSeverityFilter = 'all';
let threatSearchQuery = '';

// ─── IntersectionObserver Scroll Reveal (Reveals Once, Staggers Max 3-4 Items) ───
function initScrollReveal() {
    const items = document.querySelectorAll('.reveal-on-scroll');
    if (!('IntersectionObserver' in window)) {
        items.forEach(el => el.classList.add('is-visible'));
        return;
    }

    const observer = new IntersectionObserver((entries, obs) => {
        const visibleBatch = entries.filter(e => e.isIntersecting);
        visibleBatch.forEach((entry, idx) => {
            const delayMs = Math.min(idx, 3) * 85;
            entry.target.style.transitionDelay = `${delayMs}ms`;
            entry.target.classList.add('is-visible');
            obs.unobserve(entry.target);
        });
    }, {
        threshold: 0.08,
        rootMargin: '0px 0px -24px 0px'
    });

    items.forEach(el => observer.observe(el));
}

document.addEventListener('DOMContentLoaded', initScrollReveal);

// ─── Toast Notification Helper ───
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = 'toast-item';
    let borderColor = 'var(--primary-600)';
    let icon = 'fa-circle-info';
    if (type === 'critical' || type === 'danger') {
        borderColor = 'var(--accent-red-600)';
        icon = 'fa-shield-halved';
    } else if (type === 'success') {
        borderColor = 'var(--primary-600)';
        icon = 'fa-circle-check';
    }
    toast.style.borderLeftColor = borderColor;
    toast.innerHTML = `<i class="fa-solid ${icon}" style="color:${borderColor}" aria-hidden="true"></i> <span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 180ms cubic-bezier(0.22, 1, 0.36, 1)';
        setTimeout(() => toast.remove(), 200);
    }, 3200);
}
window.showToast = showToast;

// ─── Live Clock ───
function updateClock() {
    if (!clockElement) return;
    const now = new Date();
    clockElement.textContent = now.toLocaleTimeString('en-US', { hour12: false });
}
setInterval(updateClock, 1000);
updateClock();

// ─── Mobile Sidebar Toggle ───
function closeMobileSidebar() {
    if (sidebar) sidebar.classList.remove('open');
    if (sidebarBackdrop) sidebarBackdrop.classList.remove('active');
}

if (mobileMenuBtn) {
    mobileMenuBtn.addEventListener('click', () => {
        if (sidebar) sidebar.classList.toggle('open');
        if (sidebarBackdrop && sidebar) {
            sidebarBackdrop.classList.toggle('active', sidebar.classList.contains('open'));
        }
    });
}
if (sidebarBackdrop) {
    sidebarBackdrop.addEventListener('click', closeMobileSidebar);
}

// ─── Navigation Router ───
function switchView(targetView) {
    if (!views[targetView]) return;

    navItems.forEach(nav => {
        nav.classList.toggle('active', nav.getAttribute('data-view') === targetView);
    });

    Object.values(views).forEach(view => {
        if (view) {
            view.style.display = 'none';
            view.classList.remove('view-active');
        }
    });

    const activePanel = views[targetView];
    activePanel.style.display = 'block';
    void activePanel.offsetWidth;
    activePanel.classList.add('view-active');

    if (pageTitle && viewTitles[targetView]) {
        pageTitle.textContent = viewTitles[targetView];
    }

    closeMobileSidebar();
    window.scrollTo({ top: 0, behavior: 'smooth' });

    if (targetView === 'dashboard') {
        if (window.resizeDashboardCharts) window.resizeDashboardCharts();
    } else if (targetView === 'threats') {
        renderThreatsTable();
    } else if (targetView === 'sandbox') {
        loadPresets();
    } else if (targetView === 'siem') {
        runSiemSqlQuery();
        fetchSiemToolLogs('zeek');
        fetchOsintThreatFeeds();
    } else if (targetView === 'blocklist') {
        fetchFullBlocklist();
    } else if (targetView === 'models') {
        fetchMetrics();
    } else if (targetView === 'live') {
        initLiveWiresharkView();
    }
}
window.switchView = switchView;

navItems.forEach(item => {
    item.addEventListener('click', () => {
        const targetView = item.getAttribute('data-view');
        switchView(targetView);
    });
});

document.querySelectorAll('[data-view-trigger]').forEach(el => {
    el.addEventListener('click', () => {
        switchView(el.getAttribute('data-view-trigger'));
    });
    el.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            switchView(el.getAttribute('data-view-trigger'));
        }
    });
});

document.querySelectorAll('[data-jump-view]').forEach(btn => {
    btn.addEventListener('click', () => {
        const target = btn.getAttribute('data-jump-view');
        switchView(target);
    });
});

const quickInspectBtn = document.getElementById('quick-inspect-btn');
if (quickInspectBtn) {
    quickInspectBtn.addEventListener('click', () => {
        switchView('sandbox');
    });
}

// ─── Live Stats & Network Risk Meter ───
function updateStats(stats, latencyMs) {
    if (!stats) return;

    if (statTotal) statTotal.textContent = (stats.total_connections || 0).toLocaleString();
    if (statAttacks) statAttacks.textContent = (stats.attack_count || 0).toLocaleString();
    if (statBlocked) statBlocked.textContent = (stats.blocked_count || 0).toLocaleString();
    if (attackRate) attackRate.textContent = (stats.attack_rate || 0).toFixed(1) + '%';
    if (statLatency && latencyMs !== undefined) {
        const msVal = Math.max(4, Math.round(latencyMs));
        statLatency.textContent = msVal;
        const latBar = document.getElementById('hero-latency-bar');
        if (latBar) {
            latBar.style.width = `${Math.min(100, Math.max(10, (msVal / 120) * 100))}%`;
        }
    }

    const atkBar = document.getElementById('hero-attack-ratio-bar');
    if (atkBar) {
        atkBar.style.width = `${Math.min(100, Math.max(6, stats.attack_rate || 0))}%`;
    }

    const tabBlocked = document.getElementById('tab-blocked-count');
    if (tabBlocked) tabBlocked.textContent = stats.blocked_count || 0;

    const digBlocked = document.getElementById('digest-blocked-sub');
    if (digBlocked) digBlocked.textContent = `${stats.blocked_count || 0} attacker IPs blocked automatically`;

    const badge = document.getElementById('active-alert-badge');
    const notifBtn = document.getElementById('notifications-btn');
    const notifDot = document.getElementById('notif-dot');

    if (badge) badge.textContent = stats.active_alerts || 0;

    if ((stats.active_alerts || 0) > 0) {
        if (notifBtn) notifBtn.classList.add('alert-active');
        if (notifDot) notifDot.style.display = 'block';
    } else {
        if (notifBtn) notifBtn.classList.remove('alert-active');
        if (notifDot) notifDot.style.display = 'none';
    }

    // Update Network Risk Level Meter in Section 3
    const postureBadge = document.getElementById('posture-level-badge');
    const postureFill = document.getElementById('posture-meter-fill');
    const rate = stats.attack_rate || 0;

    if (postureBadge && postureFill) {
        const clampedWidth = Math.min(100, Math.max(12, rate * 1.4));
        postureFill.style.width = `${clampedWidth}%`;

        if (rate >= 38) {
            postureBadge.textContent = 'HIGH DANGER';
            postureBadge.className = 'status-tag tag-alert mono';
            postureFill.style.backgroundColor = '#E48272';
        } else if (rate >= 18) {
            postureBadge.textContent = 'MEDIUM RISK';
            postureBadge.className = 'status-tag tag-slate mono';
            postureFill.style.backgroundColor = '#E89E50';
        } else {
            postureBadge.textContent = 'SAFE / NORMAL';
            postureBadge.className = 'status-tag tag-nominal mono';
            postureFill.style.backgroundColor = '#7FA996';
        }
    }
}

async function fetchStats() {
    const t0 = performance.now();
    try {
        const response = await fetch(`${API_BASE_URL}/stats`);
        const t1 = performance.now();
        if (response.ok) {
            const data = await response.json();
            updateStats(data, t1 - t0);
            if (window.updatePieChart) {
                window.updatePieChart(data.categories);
            }
        }
    } catch (error) {
        console.error('Failed to fetch stats:', error);
    }
}
window.fetchStats = fetchStats;

// ─── View 02: Threat Log Table ───
function renderThreatsTable() {
    const tbody = document.getElementById('threats-full-table-body');
    const counter = document.getElementById('threats-total-count');
    if (!tbody || !counter) return;

    const events = window.allEventsHistory || [];

    const filtered = events.filter(evt => {
        if (activeSeverityFilter !== 'all') {
            if (activeSeverityFilter === 'info' && evt.severity !== 'info') return false;
            if (activeSeverityFilter !== 'info' && evt.severity !== activeSeverityFilter) return false;
        }
        if (threatSearchQuery) {
            const q = threatSearchQuery.toLowerCase();
            const match = (evt.src_ip && evt.src_ip.toLowerCase().includes(q)) ||
                          (evt.dst_ip && evt.dst_ip.toLowerCase().includes(q)) ||
                          (evt.id && evt.id.toLowerCase().includes(q)) ||
                          (evt.attack_category && evt.attack_category.toLowerCase().includes(q)) ||
                          (evt.service && evt.service.toLowerCase().includes(q)) ||
                          (evt.protocol && evt.protocol.toLowerCase().includes(q));
            if (!match) return false;
        }
        return true;
    });

    counter.textContent = filtered.length;
    tbody.innerHTML = '';

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" class="mono table-empty-cell">No network connections match your current search or filter.</td></tr>`;
        return;
    }

    filtered.slice(0, 60).forEach(evt => {
        const tr = document.createElement('tr');
        const timeStr = new Date(evt.timestamp).toLocaleTimeString('en-US', { hour12: false });

        const sevClass = evt.severity || 'info';
        const sevLabel = sevClass === 'info' ? 'SAFE' : sevClass.toUpperCase();
        const friendlyCat = FRIENDLY_CATEGORY_LABELS[evt.attack_category] || evt.attack_category;

        let barColor = 'var(--primary-600)';
        if (evt.anomaly_score > 0.8) barColor = 'var(--accent-red-600)';
        else if (evt.anomaly_score > 0.5) barColor = 'var(--accent-ochre-500)';

        tr.innerHTML = `
            <td class="mono" style="color:var(--neutral-600);">${timeStr}</td>
            <td class="mono" style="color:var(--primary-600);font-weight:700;">${evt.id}</td>
            <td><span class="threat-badge ${sevClass}">${sevLabel}</span></td>
            <td><strong>${friendlyCat}</strong></td>
            <td class="mono" style="font-size:0.8rem;">${evt.src_ip}:${evt.src_port} → ${evt.dst_ip}:${evt.dst_port}</td>
            <td class="mono" style="font-size:0.8rem;">${evt.protocol.toUpperCase()} / ${evt.service} <span style="color:var(--neutral-500);">(${evt.flag})</span></td>
            <td class="mono">
                ${(evt.anomaly_score).toFixed(2)}
                <div class="anomaly-bar" style="display:inline-block;width:44px;margin-left:6px;vertical-align:middle;">
                    <div class="anomaly-bar-fill" style="width:${Math.min(100, evt.anomaly_score * 100)}%; background-color:${barColor}"></div>
                </div>
            </td>
            <td class="mono">${(evt.confidence * 100).toFixed(1)}%</td>
            <td style="text-align: right;" onclick="event.stopPropagation();">
                <button type="button" class="btn btn-sm btn-secondary" onclick="replayEventInSandbox('${evt.id}')" title="Test this packet in AI Tester">
                    <i class="fa-solid fa-flask" aria-hidden="true"></i> Test in AI
                </button>
                ${evt.is_blocked
                    ? '<span class="mono" style="color:var(--accent-red-600);font-size:0.74rem;font-weight:700;margin-left:6px;">BLOCKED</span>'
                    : `<button type="button" class="btn btn-sm btn-danger" style="margin-left:4px;" onclick="blockThreatIP('${evt.src_ip}', '${evt.attack_category}')">Block IP</button>`
                }
            </td>
        `;

        tr.addEventListener('click', () => {
            openPacketForensics(evt);
        });

        tbody.appendChild(tr);
    });
}
window.renderThreatsTable = renderThreatsTable;

window.onNewEventReceived = function(evt) {
    if (views.threats && views.threats.style.display === 'block') {
        renderThreatsTable();
    }
    renderCenterPacketsTable();
    updateHeroVisualTicker(evt);
};

function updateHeroVisualTicker(evt) {
    if (!evt) return;
    const tickerText = document.getElementById('hero-ticker-text');
    const stageTag = document.getElementById('hero-flow-status-tag');
    const sparkContainer = document.getElementById('hero-sparkline-total');

    const friendlyCat = FRIENDLY_CATEGORY_LABELS[evt.attack_category] || evt.attack_category;
    if (tickerText) {
        tickerText.textContent = `${evt.id} · ${evt.src_ip}:${evt.src_port} → ${evt.protocol.toUpperCase()}/${evt.service} · AI Verdict: ${friendlyCat} (${(evt.confidence * 100).toFixed(0)}%)`;
    }
    if (stageTag) {
        if (evt.is_attack) {
            stageTag.textContent = `ALERT: ${friendlyCat.toUpperCase()}`;
            stageTag.style.backgroundColor = 'var(--accent-red-50)';
            stageTag.style.color = 'var(--accent-red-700)';
            stageTag.style.borderColor = 'var(--accent-red-200)';
        } else {
            stageTag.textContent = 'SAFE TRAFFIC VERIFIED';
            stageTag.style.backgroundColor = 'var(--primary-50)';
            stageTag.style.color = 'var(--primary-700)';
            stageTag.style.borderColor = 'var(--primary-200)';
        }
    }
    if (sparkContainer && sparkContainer.children.length > 0) {
        const bars = Array.from(sparkContainer.children);
        bars.forEach((b, i) => {
            if (i < bars.length - 1) {
                b.style.height = bars[i + 1].style.height;
                b.style.backgroundColor = bars[i + 1].style.backgroundColor;
            } else {
                const h = Math.min(100, Math.max(30, Math.round((evt.anomaly_score || 0.25) * 95 + 25)));
                b.style.height = `${h}%`;
                b.style.backgroundColor = evt.is_attack ? 'var(--accent-red-500)' : 'var(--primary-500)';
            }
        });
    }
}

function renderCenterPacketsTable() {
    const tbody = document.getElementById('center-live-packets-tbody');
    if (!tbody) return;
    const events = (window.allEventsHistory || []).slice(0, 10);
    if (events.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="mono table-empty-cell">Waiting for live network connections...</td></tr>`;
        return;
    }

    tbody.innerHTML = '';
    events.forEach(evt => {
        const tr = document.createElement('tr');
        const sevClass = evt.severity || 'info';
        const scoreColor = evt.anomaly_score > 0.5 ? '#F0AFA4' : '#AEC9BC';
        const friendlyCat = FRIENDLY_CATEGORY_LABELS[evt.attack_category] || evt.attack_category;
        tr.innerHTML = `
            <td class="mono" style="color:#AEC9BC;font-size:0.78rem;font-weight:700;">${evt.id}</td>
            <td class="mono" style="font-size:0.78rem;color:#FAF8F4;">${evt.src_ip} → ${evt.dst_ip}:${evt.dst_port}</td>
            <td class="mono" style="font-size:0.76rem;color:#D5E3DC;">${evt.protocol.toUpperCase()}/${evt.service}</td>
            <td><span class="threat-badge ${sevClass}">${friendlyCat}</span></td>
            <td class="mono" style="font-size:0.78rem;font-weight:700;color:${scoreColor};">${(evt.anomaly_score).toFixed(2)}</td>
        `;
        tr.addEventListener('click', () => openPacketForensics(evt));
        tbody.appendChild(tr);
    });
}

window.blockThreatIP = async function(ip, reason) {
    if (window.addIPToBlocklist) {
        await window.addIPToBlocklist(ip, reason || 'Blocked Manually');
    }
    if (window.allEventsHistory) {
        window.allEventsHistory.forEach(e => {
            if (e.src_ip === ip) e.is_blocked = true;
        });
    }
    showToast(`Blocked IP address ${ip}`, 'critical');
    renderThreatsTable();
    fetchFullBlocklist();
};

// Filter pills
document.querySelectorAll('.filter-pill[data-filter]').forEach(pill => {
    pill.addEventListener('click', () => {
        document.querySelectorAll('.filter-pill[data-filter]').forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        activeSeverityFilter = pill.getAttribute('data-filter');
        renderThreatsTable();
    });
});

// Search input
const threatSearchInput = document.getElementById('threat-search-input');
if (threatSearchInput) {
    threatSearchInput.addEventListener('input', (e) => {
        threatSearchQuery = e.target.value.trim();
        renderThreatsTable();
    });
}

const globalQuickSearch = document.getElementById('global-quick-search');
if (globalQuickSearch) {
    globalQuickSearch.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            threatSearchQuery = e.target.value.trim();
            if (threatSearchInput) threatSearchInput.value = threatSearchQuery;
            switchView('threats');
        }
    });
}

const rightFeedFilter = document.getElementById('right-feed-filter');
if (rightFeedFilter) {
    rightFeedFilter.addEventListener('input', (e) => {
        const q = e.target.value.trim().toLowerCase();
        const items = document.querySelectorAll('#threat-feed-container .threat-item');
        items.forEach(item => {
            const text = item.textContent.toLowerCase();
            item.style.display = (!q || text.includes(q)) ? 'grid' : 'none';
        });
    });
}

// Clear feed button
const clearFeedBtn = document.getElementById('clear-feed-btn');
if (clearFeedBtn) {
    clearFeedBtn.addEventListener('click', () => {
        window.allEventsHistory = [];
        renderThreatsTable();
        renderCenterPacketsTable();
        showToast('Cleared connection log list', 'info');
    });
}

// ─── Slide-Over Connection Details Drawer ───
const forensicsDrawer = document.getElementById('forensics-drawer');
const forensicsBackdrop = document.getElementById('forensics-drawer-backdrop');
const closeDrawerBtn = document.getElementById('close-drawer-btn');
const drawerBody = document.getElementById('forensics-drawer-body');
const drawerTitle = document.getElementById('drawer-title');
const drawerKicker = document.getElementById('drawer-kicker');

function closeForensicsDrawer() {
    if (forensicsDrawer) forensicsDrawer.classList.remove('open');
    if (forensicsBackdrop) forensicsBackdrop.classList.remove('open');
}

if (closeDrawerBtn) closeDrawerBtn.addEventListener('click', closeForensicsDrawer);
if (forensicsBackdrop) forensicsBackdrop.addEventListener('click', closeForensicsDrawer);

function openPacketForensics(evt) {
    if (!forensicsDrawer || !drawerBody || !evt) return;

    const friendlyCat = FRIENDLY_CATEGORY_LABELS[evt.attack_category] || evt.attack_category;
    if (drawerKicker) drawerKicker.textContent = `CONNECTION DETAILS // ${evt.id}`;
    if (drawerTitle) drawerTitle.textContent = `${friendlyCat}`;

    const sevClass = evt.severity || 'info';
    const sevLabel = sevClass === 'info' ? 'SAFE TRAFFIC' : `${sevClass.toUpperCase()} RISK`;

    drawerBody.innerHTML = `
        <div class="diagnostics-verdict" style="border-left: 4px solid var(--${sevClass});">
            <div class="verdict-left">
                <span class="mono" style="font-size:0.7rem;color:var(--neutral-500);font-weight:700;">AI DECISION SUMMARY</span>
                <h3>${friendlyCat}</h3>
                <div class="mono" style="font-size:0.78rem;color:var(--neutral-600);">
                    Target Device: <strong>${evt.device || 'internal-server'}</strong>
                </div>
            </div>
            <div style="text-align:right;">
                <span class="verdict-badge ${sevClass}">${sevLabel}</span>
                <div class="mono" style="font-size:0.74rem;color:var(--neutral-600);margin-top:6px;">
                    AI Confidence: ${(evt.confidence * 100).toFixed(1)}%
                </div>
            </div>
        </div>

        <div class="forensic-grid">
            <div class="forensic-cell">
                <div class="forensic-cell-label">Sender IP &amp; Port</div>
                <div class="forensic-cell-val">${evt.src_ip}:${evt.src_port}</div>
            </div>
            <div class="forensic-cell">
                <div class="forensic-cell-label">Target IP &amp; Port</div>
                <div class="forensic-cell-val">${evt.dst_ip}:${evt.dst_port}</div>
            </div>
            <div class="forensic-cell">
                <div class="forensic-cell-label">Connection Type &amp; Service</div>
                <div class="forensic-cell-val">${evt.protocol.toUpperCase()} / ${evt.service}</div>
            </div>
            <div class="forensic-cell">
                <div class="forensic-cell-label">Connection Status (Flag)</div>
                <div class="forensic-cell-val">${evt.flag}</div>
            </div>
            <div class="forensic-cell">
                <div class="forensic-cell-label">Data Sent → Received</div>
                <div class="forensic-cell-val">${(evt.src_bytes || 0).toLocaleString()} B → ${(evt.dst_bytes || 0).toLocaleString()} B</div>
            </div>
            <div class="forensic-cell">
                <div class="forensic-cell-label">Connection Length</div>
                <div class="forensic-cell-val">${evt.duration || 0} seconds</div>
            </div>
            <div class="forensic-cell">
                <div class="forensic-cell-label">Unusual Behavior Score</div>
                <div class="forensic-cell-val" style="color:${evt.anomaly_score > 0.5 ? 'var(--accent-red-600)' : 'var(--primary-600)'};">${(evt.anomaly_score).toFixed(2)} / 1.00</div>
            </div>
            <div class="forensic-cell">
                <div class="forensic-cell-label">Public Threat List Check</div>
                <div class="forensic-cell-val" style="font-size:0.76rem;color:var(--secondary-800);">${evt.osint_feed || 'Clean / Not Listed'}</div>
            </div>
        </div>

        <div class="forensic-cell" style="margin-top:4px;">
            <div class="forensic-cell-label">Plain-English Packet Summary</div>
            <div class="forensic-cell-val" style="font-size:0.76rem;color:var(--primary-700);">${evt.wireshark_summary || 'Standard network connection'}</div>
        </div>

        <div style="display:flex;flex-direction:column;gap:8px;margin-top:8px;">
            <button type="button" class="btn btn-primary btn-block" onclick="replayEventInSandbox('${evt.id}')">
                <i class="fa-solid fa-flask" aria-hidden="true"></i> Test This Connection in AI Tester
            </button>
            <button type="button" class="btn btn-danger btn-block" onclick="blockThreatIP('${evt.src_ip}', '${evt.attack_category} (${evt.id})'); closeForensicsDrawer();">
                <i class="fa-solid fa-ban" aria-hidden="true"></i> Block Sender IP Address (${evt.src_ip})
            </button>
        </div>
    `;

    forensicsDrawer.classList.add('open');
    forensicsBackdrop.classList.add('open');
}
window.openPacketForensics = openPacketForensics;
window.closeForensicsDrawer = closeForensicsDrawer;

window.replayEventInSandbox = function(eventId) {
    const events = window.allEventsHistory || [];
    const evt = events.find(e => e.id === eventId);
    closeForensicsDrawer();
    switchView('sandbox');

    if (!evt) return;

    setTimeout(() => {
        if (document.getElementById('sb-src-ip')) document.getElementById('sb-src-ip').value = evt.src_ip || '185.220.101.42';
        if (document.getElementById('sb-dst-ip')) document.getElementById('sb-dst-ip').value = evt.dst_ip || '10.0.1.15';
        if (document.getElementById('sb-protocol')) document.getElementById('sb-protocol').value = evt.protocol || 'tcp';
        if (document.getElementById('sb-service')) {
            const svcSelect = document.getElementById('sb-service');
            const options = Array.from(svcSelect.options).map(o => o.value);
            svcSelect.value = options.includes(evt.service) ? evt.service : 'other';
        }
        if (document.getElementById('sb-flag')) {
            const flagSelect = document.getElementById('sb-flag');
            const options = Array.from(flagSelect.options).map(o => o.value);
            flagSelect.value = options.includes(evt.flag) ? evt.flag : 'SF';
        }
        if (document.getElementById('sb-duration')) document.getElementById('sb-duration').value = evt.duration || 0;
        if (document.getElementById('sb-src-bytes')) document.getElementById('sb-src-bytes').value = evt.src_bytes || 0;
        if (document.getElementById('sb-dst-bytes')) document.getElementById('sb-dst-bytes').value = evt.dst_bytes || 0;
        if (document.getElementById('sb-count')) document.getElementById('sb-count').value = evt.is_attack ? 220 : 4;
        if (document.getElementById('sb-serror')) document.getElementById('sb-serror').value = (evt.flag === 'S0' || evt.flag === 'REJ') ? 1.0 : 0.0;

        const runBtn = document.getElementById('run-ai-inference-btn');
        if (runBtn) runBtn.click();
        showToast(`Loaded connection ${evt.id} into AI Tester`, 'info');
    }, 100);
};

// Notifications Drawer (Header Bell Button)
const notificationsBtn = document.getElementById('notifications-btn');
if (notificationsBtn) {
    notificationsBtn.addEventListener('click', async () => {
        if (!forensicsDrawer || !drawerBody) return;
        if (drawerKicker) drawerKicker.textContent = 'RECENT SECURITY ALERTS';
        if (drawerTitle) drawerTitle.textContent = 'Latest Detected Cyber Attacks';

        const alerts = (window.allEventsHistory || []).filter(e => e.is_attack).slice(0, 15);

        if (alerts.length === 0) {
            drawerBody.innerHTML = `
                <div class="empty-state">
                    <i class="fa-solid fa-shield-halved empty-icon" aria-hidden="true"></i>
                    <div class="empty-text">No cyber attacks detected yet in this session.</div>
                </div>
            `;
        } else {
            drawerBody.innerHTML = alerts.map(a => {
                const friendlyCat = FRIENDLY_CATEGORY_LABELS[a.attack_category] || a.attack_category;
                return `
                <div class="forensic-cell" style="cursor:pointer;" onclick="window.replayEventInSandbox('${a.id}')">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                        <span class="threat-badge ${a.severity}">${a.severity} · ${friendlyCat}</span>
                        <span class="mono" style="font-size:0.74rem;color:var(--primary-600);font-weight:700;">${a.id}</span>
                    </div>
                    <div class="mono" style="font-size:0.82rem;color:var(--neutral-900);font-weight:700;">
                        From ${a.src_ip}:${a.src_port} → ${a.dst_ip}:${a.dst_port}
                    </div>
                    <div class="mono" style="font-size:0.72rem;color:var(--neutral-600);margin-top:3px;">
                        Service: ${a.protocol.toUpperCase()}/${a.service} · Risk Score: ${(a.anomaly_score).toFixed(2)} · Click to test in AI →
                    </div>
                </div>
            `;
            }).join('');
        }

        forensicsDrawer.classList.add('open');
        forensicsBackdrop.classList.add('open');
    });
}

// ─── System Settings Modal ───
const settingsBtn = document.getElementById('settings-btn');
const settingsModalBackdrop = document.getElementById('settings-modal-backdrop');
const closeSettingsBtn = document.getElementById('close-settings-btn');
const modalToggleStreamBtn = document.getElementById('modal-toggle-stream-btn');
const modalToggleAutoblockBtn = document.getElementById('modal-toggle-autoblock-btn');

if (settingsBtn && settingsModalBackdrop) {
    settingsBtn.addEventListener('click', async () => {
        settingsModalBackdrop.classList.add('open');
        const statusText = document.getElementById('modal-api-status-text');
        if (statusText) {
            try {
                const res = await fetch(`${API_BASE_URL}/status`);
                if (res.ok) {
                    const data = await res.json();
                    const loadedCount = Object.values(data.models || {}).filter(Boolean).length;
                    statusText.textContent = `Online (v${data.version}) · All ${loadedCount} AI models are active and ready.`;
                }
            } catch (e) {
                statusText.textContent = 'Could not connect to the AI server.';
            }
        }
    });
}
if (closeSettingsBtn && settingsModalBackdrop) {
    closeSettingsBtn.addEventListener('click', () => settingsModalBackdrop.classList.remove('open'));
}
if (settingsModalBackdrop) {
    settingsModalBackdrop.addEventListener('click', (e) => {
        if (e.target === settingsModalBackdrop) settingsModalBackdrop.classList.remove('open');
    });
}
if (modalToggleStreamBtn) {
    modalToggleStreamBtn.addEventListener('click', () => {
        if (window.toggleStreamPause) {
            const paused = window.toggleStreamPause();
            showToast(paused ? 'Live traffic feed paused' : 'Live traffic feed resumed', 'info');
        }
    });
}
if (modalToggleAutoblockBtn) {
    modalToggleAutoblockBtn.addEventListener('click', () => {
        window.autoBlockEnabled = !window.autoBlockEnabled;
        modalToggleAutoblockBtn.textContent = window.autoBlockEnabled ? 'Enabled' : 'Disabled';
        modalToggleAutoblockBtn.className = window.autoBlockEnabled ? 'btn btn-sm btn-primary' : 'btn btn-sm btn-secondary';
        const blockTag = document.getElementById('block-mode-tag');
        if (blockTag) blockTag.textContent = window.autoBlockEnabled ? 'AUTO-BLOCK ON' : 'MANUAL BLOCK ONLY';
        showToast(`Automatic IP blocking ${window.autoBlockEnabled ? 'turned on' : 'turned off'}`, 'info');
    });
}

// ─── View 03: Interactive AI Threat Tester (Sandbox) ───
let cachedPresets = [];
let activePresetFeatures = null;

async function loadPresets() {
    const container = document.getElementById('sandbox-presets-container');
    if (!container) return;
    if (container.children.length > 0 && cachedPresets.length > 0) return;

    try {
        const res = await fetch(`${API_BASE_URL}/presets`);
        if (res.ok) {
            const data = await res.json();
            cachedPresets = data.presets || [];
            container.innerHTML = '';

            cachedPresets.forEach((p, idx) => {
                const card = document.createElement('div');
                card.className = `preset-card ${idx === 0 ? 'active' : ''}`;
                card.innerHTML = `
                    <div class="preset-card-header">
                        <span class="preset-title">${p.name}</span>
                        <span class="threat-badge ${p.severity}">${p.category}</span>
                    </div>
                    <div class="preset-desc">${p.description}</div>
                `;
                card.addEventListener('click', () => {
                    document.querySelectorAll('.preset-card').forEach(c => c.classList.remove('active'));
                    card.classList.add('active');
                    populateSandboxForm(p);
                });
                container.appendChild(card);
            });

            if (cachedPresets.length > 0) {
                populateSandboxForm(cachedPresets[0]);
            }
        }
    } catch (e) {
        console.error('Failed to load presets:', e);
    }
}

function populateSandboxForm(preset) {
    const f = preset.features || {};
    activePresetFeatures = { ...f };
    if (document.getElementById('sb-protocol')) document.getElementById('sb-protocol').value = f.protocol_type || 'tcp';
    if (document.getElementById('sb-service')) document.getElementById('sb-service').value = f.service || 'http';
    if (document.getElementById('sb-flag')) document.getElementById('sb-flag').value = f.flag || 'SF';
    if (document.getElementById('sb-duration')) document.getElementById('sb-duration').value = f.duration !== undefined ? f.duration : 0;
    if (document.getElementById('sb-src-bytes')) document.getElementById('sb-src-bytes').value = f.src_bytes !== undefined ? f.src_bytes : 0;
    if (document.getElementById('sb-dst-bytes')) document.getElementById('sb-dst-bytes').value = f.dst_bytes !== undefined ? f.dst_bytes : 0;
    if (document.getElementById('sb-count')) document.getElementById('sb-count').value = f.count !== undefined ? f.count : 1;
    if (document.getElementById('sb-serror')) document.getElementById('sb-serror').value = f.serror_rate !== undefined ? f.serror_rate : 0.0;
    if (document.getElementById('sb-failed-logins')) document.getElementById('sb-failed-logins').value = f.num_failed_logins !== undefined ? f.num_failed_logins : 0;
    if (document.getElementById('sb-root-shell')) document.getElementById('sb-root-shell').value = f.root_shell !== undefined ? f.root_shell : 0;
}

const sandboxForm = document.getElementById('sandbox-form');
if (sandboxForm) {
    sandboxForm.querySelectorAll('input, select').forEach(el => {
        if (el.id !== 'sb-src-ip' && el.id !== 'sb-dst-ip') {
            el.addEventListener('change', () => {
                activePresetFeatures = null;
                document.querySelectorAll('.preset-card').forEach(c => c.classList.remove('active'));
            });
        }
    });
}

const sandboxResetBtn = document.getElementById('sandbox-reset-btn');
if (sandboxResetBtn) {
    sandboxResetBtn.addEventListener('click', () => {
        document.querySelectorAll('.preset-card').forEach(c => c.classList.remove('active'));
        if (cachedPresets.length > 4) {
            populateSandboxForm(cachedPresets[4]);
            showToast('Reset form to Normal Safe Web Traffic', 'info');
        }
    });
}

const runInferenceBtn = document.getElementById('run-ai-inference-btn');
if (runInferenceBtn) {
    runInferenceBtn.addEventListener('click', async () => {
        const countVal = parseFloat(document.getElementById('sb-count').value) || 1;
        const serrorVal = parseFloat(document.getElementById('sb-serror').value) || 0;
        const flagVal = document.getElementById('sb-flag').value;

        const payload = {
            ...(activePresetFeatures || {}),
            src_ip: document.getElementById('sb-src-ip').value || '185.220.101.42',
            dst_ip: document.getElementById('sb-dst-ip').value || '10.0.1.15',
            protocol_type: document.getElementById('sb-protocol').value,
            service: document.getElementById('sb-service').value,
            flag: flagVal,
            duration: parseFloat(document.getElementById('sb-duration').value) || 0,
            src_bytes: parseFloat(document.getElementById('sb-src-bytes').value) || 0,
            dst_bytes: parseFloat(document.getElementById('sb-dst-bytes').value) || 0,
            count: countVal,
            srv_count: (activePresetFeatures && activePresetFeatures.srv_count !== undefined) ? activePresetFeatures.srv_count : countVal,
            serror_rate: serrorVal,
            srv_serror_rate: serrorVal,
            num_failed_logins: parseFloat(document.getElementById('sb-failed-logins').value) || 0,
            root_shell: parseFloat(document.getElementById('sb-root-shell').value) || 0,
            auto_block: Boolean(window.autoBlockEnabled)
        };

        runInferenceBtn.disabled = true;
        runInferenceBtn.innerHTML = 'Checking connection with all 5 AI models...';

        const t0 = performance.now();
        try {
            const res = await fetch(`${API_BASE_URL}/predict`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const t1 = performance.now();
            const latencyBadge = document.getElementById('sandbox-latency-badge');
            if (latencyBadge) {
                latencyBadge.textContent = `CHECKED IN ${Math.round(t1 - t0)}MS`;
            }

            if (res.ok) {
                const data = await res.json();
                if (data.auto_blocked && window.addIPToBlocklist) {
                    window.addIPToBlocklist(data.src_ip, `${data.attack_category} (AI Tester)`, true);
                    fetchStats();
                }
                renderDiagnostics(data);
            } else {
                showToast('AI check returned an error', 'danger');
            }
        } catch (e) {
            console.error('Inference error:', e);
            showToast('Could not reach the AI server', 'danger');
        } finally {
            runInferenceBtn.disabled = false;
            runInferenceBtn.innerHTML = '<i class="fa-solid fa-bolt" aria-hidden="true"></i> Run AI Threat Check';
        }
    });
}

function renderDiagnostics(data) {
    const container = document.getElementById('sandbox-results-container');
    if (!container) return;

    const sevClass = (data.severity || 'info').toLowerCase();
    const isAttack = data.is_attack;
    const friendlyCat = FRIENDLY_CATEGORY_LABELS[data.attack_category] || data.attack_category;

    let barColor = 'var(--primary-600)';
    if (data.anomaly_score > 0.8) barColor = 'var(--accent-red-600)';
    else if (data.anomaly_score > 0.5) barColor = 'var(--accent-ochre-500)';

    const votes = data.model_votes || {};
    const rfBin = votes.rf_binary || { prediction: 0, confidence: 0 };
    const rfMulti = votes.rf_multi || { prediction: 'Normal', confidence: 0 };
    const nnBin = votes.nn_binary || { prediction: rfBin.prediction, confidence: rfBin.confidence };
    const iso = votes.isolation_forest || { prediction: 'Normal', anomaly_score: 0 };

    const indicatorsHtml = (data.key_indicators || []).map(ind => `
        <div class="indicator-tag">
            <i class="fa-solid ${isAttack ? 'fa-triangle-exclamation' : 'fa-circle-check'}" style="color:${isAttack ? 'var(--accent-red-600)' : 'var(--primary-600)'}" aria-hidden="true"></i>
            <span>${ind}</span>
        </div>
    `).join('');

    container.innerHTML = `
        <div class="diagnostics-container">
            <div class="diagnostics-verdict" style="border-left: 4px solid var(--${sevClass});">
                <div class="verdict-left">
                    <span class="mono" style="font-size:0.7rem;text-transform:uppercase;color:var(--neutral-500);font-weight:700;">FINAL AI DECISION</span>
                    <h3>${friendlyCat}</h3>
                    <div class="mono" style="font-size:0.78rem;color:var(--neutral-600);">
                        Sender IP: <strong>${data.src_ip}</strong> → Recommended Action: <strong>${data.response ? data.response.action : 'ALLOW'}</strong>
                    </div>
                </div>
                <div style="text-align:right;">
                    <div class="verdict-badge ${sevClass}">${isAttack ? data.severity.toUpperCase() + ' RISK' : 'SAFE TRAFFIC'}</div>
                    <div class="mono" style="font-size:0.74rem;color:var(--neutral-600);margin-top:6px;">AI Confidence: ${(data.confidence * 100).toFixed(1)}%</div>
                </div>
            </div>

            <div class="diagnostics-gauge-box">
                <div class="gauge-header">
                    <span>How Unusual Is This Traffic? (0 = Normal, 1 = Very Suspicious)</span>
                    <span class="gauge-score" style="color:${barColor};">${(data.anomaly_score).toFixed(2)} / 1.00</span>
                </div>
                <div class="gauge-bar">
                    <div class="gauge-bar-fill" style="width:${Math.min(100, data.anomaly_score * 100)}%; background-color:${barColor};"></div>
                </div>
                <div class="mono" style="display:flex;justify-content:space-between;font-size:0.68rem;color:var(--neutral-500);margin-top:6px;">
                    <span>0.00 (Normal Everyday Traffic)</span>
                    <span>0.50 (Suspicious Cutoff)</span>
                    <span>1.00 (High Danger)</span>
                </div>
            </div>

            <div class="diagnostics-votes">
                <div class="vote-card">
                    <div class="vote-title">Model 1: Random Forest (Safe vs. Attack)</div>
                    <div class="vote-result" style="color:${rfBin.prediction === 1 ? 'var(--accent-red-600)' : 'var(--primary-600)'}">
                        ${rfBin.prediction === 1 ? 'ATTACK DETECTED' : 'SAFE TRAFFIC'}
                    </div>
                    <div class="vote-conf">Confidence: ${(rfBin.confidence * 100).toFixed(1)}%</div>
                </div>
                <div class="vote-card">
                    <div class="vote-title">Model 2: Random Forest (Attack Type)</div>
                    <div class="vote-result" style="color:${rfMulti.prediction !== 'Normal' ? 'var(--accent-red-600)' : 'var(--primary-600)'}">
                        ${(FRIENDLY_CATEGORY_LABELS[rfMulti.prediction] || rfMulti.prediction).toUpperCase()}
                    </div>
                    <div class="vote-conf">Confidence: ${(rfMulti.confidence * 100).toFixed(1)}%</div>
                </div>
                <div class="vote-card">
                    <div class="vote-title">Model 3: Unknown Threat Finder</div>
                    <div class="vote-result" style="color:${iso.prediction === 'Anomaly' ? 'var(--accent-red-600)' : 'var(--primary-600)'}">
                        ${iso.prediction === 'Anomaly' ? 'UNUSUAL / SUSPICIOUS' : 'NORMAL BEHAVIOR'}
                    </div>
                    <div class="vote-conf">Unusual Score: ${(iso.anomaly_score).toFixed(2)}</div>
                </div>
                <div class="vote-card">
                    <div class="vote-title">Model 4: Deep Neural Network</div>
                    <div class="vote-result" style="color:${nnBin.prediction === 1 ? 'var(--accent-red-600)' : 'var(--primary-600)'}">
                        ${nnBin.prediction === 1 ? 'ATTACK DETECTED' : 'SAFE TRAFFIC'}
                    </div>
                    <div class="vote-conf">Confidence: ${(nnBin.confidence * 100).toFixed(1)}%</div>
                </div>
            </div>

            <div class="diagnostics-indicators">
                <div class="indicators-title">Why the AI Made This Decision:</div>
                ${indicatorsHtml}
            </div>

            <div>
                ${!data.is_already_blocked
                    ? `<button type="button" class="btn btn-danger btn-block" id="sandbox-toggle-block-btn">
                         <i class="fa-solid fa-ban" aria-hidden="true"></i> Block This Sender IP (${data.src_ip})
                       </button>`
                    : `<button type="button" class="btn btn-secondary btn-block" id="sandbox-toggle-block-btn">
                         <i class="fa-solid fa-rotate-left" aria-hidden="true"></i> Unblock ${data.src_ip}
                       </button>`
                }
            </div>
        </div>
    `;

    const toggleBlockBtn = document.getElementById('sandbox-toggle-block-btn');
    if (toggleBlockBtn) {
        toggleBlockBtn.addEventListener('click', async () => {
            if (!data.is_already_blocked) {
                await window.blockThreatIP(data.src_ip, data.attack_category);
                data.is_already_blocked = true;
            } else if (window.unblockIP) {
                await window.unblockIP(data.src_ip);
                data.is_already_blocked = false;
            }
            renderDiagnostics(data);
        });
    }
}

// ─── View 05: Blocked IPs Controller ───
async function fetchFullBlocklist() {
    const container = document.getElementById('full-blocklist-container');
    const counter = document.getElementById('full-blocklist-count');
    if (!container || !counter) return;

    try {
        const res = await fetch(`${API_BASE_URL}/blocked`);
        if (res.ok) {
            const data = await res.json();
            const blocked = data.blocked_ips || [];
            counter.textContent = blocked.length;
            container.innerHTML = '';

            if (blocked.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <i class="fa-solid fa-shield-halved empty-icon" style="color: var(--primary-600);" aria-hidden="true"></i>
                        <div class="empty-text">No IP addresses are currently blocked.</div>
                    </div>
                `;
                return;
            }

            blocked.forEach(ip => {
                const item = document.createElement('div');
                item.className = 'blocked-ip-item';
                item.dataset.ip = ip;
                item.style.marginBottom = '8px';
                item.innerHTML = `
                    <div class="blocked-ip-info">
                        <i class="fa-solid fa-ban blocked-ip-icon" aria-hidden="true"></i>
                        <div>
                            <div class="blocked-ip-addr">${ip}</div>
                            <div class="blocked-ip-time">Blocked by Firewall · All Incoming Traffic Dropped</div>
                        </div>
                    </div>
                    <button type="button" class="unblock-btn">UNBLOCK</button>
                `;
                const unblockBtn = item.querySelector('.unblock-btn');
                if (unblockBtn) {
                    unblockBtn.addEventListener('click', () => window.unblockFromConsole(ip));
                }
                container.appendChild(item);
            });
        }
    } catch (e) {
        console.error('Failed to fetch full blocklist:', e);
    }
}
window.fetchFullBlocklist = fetchFullBlocklist;

window.unblockFromConsole = async function(ip) {
    if (window.unblockIP) {
        await window.unblockIP(ip);
    }
    fetchFullBlocklist();
};

// Manual IP Block with IPv4 Validation
const manualBlockBtn = document.getElementById('manual-block-btn');
const manualIpInput = document.getElementById('manual-ip-input');
const manualFeedback = document.getElementById('manual-block-feedback');

function isValidIPv4(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    return parts.every(p => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}

if (manualBlockBtn && manualIpInput) {
    manualBlockBtn.addEventListener('click', async () => {
        const ip = manualIpInput.value.trim();
        if (!isValidIPv4(ip)) {
            if (manualFeedback) {
                manualFeedback.textContent = '[ERROR] Please enter a valid IPv4 address (for example: 203.0.113.50).';
                manualFeedback.style.color = 'var(--accent-red-600)';
            }
            return;
        }
        if (manualFeedback) {
            manualFeedback.textContent = `[BLOCKED] Added ${ip} to the blocked IP list.`;
            manualFeedback.style.color = 'var(--primary-600)';
        }
        await window.blockThreatIP(ip, 'Blocked Manually');
        manualIpInput.value = '';
        fetchFullBlocklist();
    });

    manualIpInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            manualBlockBtn.click();
        }
    });
}

// ─── View 04: Security Database (SQL) & Known Hacker IP List ───
const SQL_PRESETS = {
    recent: "SELECT id, timestamp, src_ip, dst_ip, protocol, service, attack_category, severity, anomaly_score, osint_feed FROM siem_events ORDER BY timestamp DESC LIMIT 15",
    critical: "SELECT id, timestamp, src_ip, dst_ip, service, flag, attack_category, anomaly_score, zeek_uid, suricata_sid FROM siem_events WHERE severity = 'critical' ORDER BY anomaly_score DESC LIMIT 15",
    groupby: "SELECT attack_category, severity, COUNT(*) AS event_count, ROUND(AVG(anomaly_score), 4) AS avg_anomaly, ROUND(AVG(src_bytes + dst_bytes), 0) AS avg_bytes FROM siem_events GROUP BY attack_category, severity ORDER BY event_count DESC",
    osint_join: "SELECT e.id, e.src_ip, t.feed_source, t.threat_label, t.reputation_score, t.country, e.attack_category, e.anomaly_score FROM siem_events e INNER JOIN threat_intel_feeds t ON e.src_ip = t.ip ORDER BY e.timestamp DESC LIMIT 15"
};

async function runSiemSqlQuery(customSql) {
    const sqlInput = document.getElementById('siem-sql-input');
    const thead = document.getElementById('siem-sql-thead');
    const tbody = document.getElementById('siem-sql-tbody');
    const execBadge = document.getElementById('sql-exec-time');
    if (!sqlInput || !thead || !tbody) return;

    const query = customSql || sqlInput.value.trim();
    if (customSql) sqlInput.value = customSql;

    try {
        const res = await fetch(`${API_BASE_URL}/siem/query`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query })
        });
        const data = await res.json();

        if (execBadge) {
            execBadge.textContent = data.error ? 'SQL ERROR' : `${data.row_count || 0} RESULTS · ${data.execution_ms || 1.2}MS`;
        }

        if (data.error) {
            thead.innerHTML = '';
            tbody.innerHTML = `<tr><td style="color:var(--accent-red-600);padding:1rem;" class="mono">${data.error}</td></tr>`;
            return;
        }

        const cols = data.columns || [];
        const rows = data.rows || [];

        thead.innerHTML = `<tr>${cols.map(c => `<th>${c}</th>`).join('')}</tr>`;
        if (rows.length === 0) {
            tbody.innerHTML = `<tr><td colspan="${cols.length || 1}" class="mono table-empty-cell">No matching records found.</td></tr>`;
            return;
        }

        tbody.innerHTML = rows.map(r => `
            <tr>
                ${cols.map(c => `<td class="mono" style="font-size:0.78rem;">${r[c] !== null && r[c] !== undefined ? r[c] : '—'}</td>`).join('')}
            </tr>
        `).join('');
    } catch (e) {
        console.error('SIEM SQL query failed:', e);
    }
}

document.querySelectorAll('[data-sql-preset]').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('[data-sql-preset]').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const key = btn.getAttribute('data-sql-preset');
        if (SQL_PRESETS[key]) {
            runSiemSqlQuery(SQL_PRESETS[key]);
        }
    });
});

const runSqlBtn = document.getElementById('run-sql-query-btn');
if (runSqlBtn) {
    runSqlBtn.addEventListener('click', () => runSiemSqlQuery());
}

async function fetchSiemToolLogs(tool = 'zeek') {
    const preview = document.getElementById('siem-tool-logs-preview');
    if (!preview) return;
    try {
        const res = await fetch(`${API_BASE_URL}/siem/logs?format=${tool}`);
        if (res.ok) {
            preview.textContent = await res.text();
        }
    } catch (e) {
        preview.textContent = '# Error loading security logs.';
    }
}

document.querySelectorAll('[data-log-tool]').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('[data-log-tool]').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        fetchSiemToolLogs(tab.getAttribute('data-log-tool'));
    });
});

async function fetchOsintThreatFeeds() {
    const tbody = document.getElementById('osint-feeds-tbody');
    if (!tbody) return;
    try {
        const res = await fetch(`${API_BASE_URL}/threat-intel`);
        if (res.ok) {
            const data = await res.json();
            const feeds = data.feeds || [];
            tbody.innerHTML = feeds.map(f => `
                <tr>
                    <td class="mono" style="color:var(--secondary-800);font-weight:700;">${f.ip} <span style="color:var(--neutral-500);">(${f.country})</span></td>
                    <td style="font-size:0.82rem;font-weight:600;">${f.feed_source}</td>
                    <td style="font-size:0.82rem;color:var(--neutral-600);">${f.threat_label}</td>
                    <td class="mono"><span class="threat-badge critical">${f.reputation_score}/100</span></td>
                    <td>
                        <button type="button" class="btn btn-sm btn-danger" onclick="blockThreatIP('${f.ip}', 'Public Threat List: ${f.feed_source}')">Block IP</button>
                    </td>
                </tr>
            `).join('');
        }
    } catch (e) {
        console.error('Failed to load OSINT feeds:', e);
    }
}

// ─── View 06: AI Model Comparison Table ───
async function fetchMetrics() {
    try {
        const response = await fetch(`${API_BASE_URL}/metrics`);
        if (response.ok) {
            const data = await response.json();
            renderMetricsTable(data.metrics);
        }
    } catch (error) {
        console.error('Failed to fetch metrics:', error);
    }
}

function renderMetricsTable(metrics) {
    const tbody = document.getElementById('metrics-table-body');
    if (!tbody || !metrics) return;
    tbody.innerHTML = '';

    const displayNames = {
        rf_binary: ['Random Forest (Safe vs. Attack)', 'Decides if a connection is safe or a cyber attack'],
        rf_multi: ['Random Forest (Attack Type)', 'Sorts attacks into Server Flood, Port Scan, Login, or Admin hack'],
        nn_binary: ['Deep Neural Network (Safe vs. Attack)', 'Multi-layer AI brain checking for attack patterns'],
        nn_multi: ['Deep Neural Network (Attack Type)', 'Deep AI sorting traffic into 5 categories'],
        isolation_forest: ['Isolation Forest (Unknown Threat Finder)', 'Spots brand-new or unusual threats without prior examples']
    };

    for (const [key, data] of Object.entries(metrics)) {
        if (!displayNames[key]) continue;

        const [name, task] = displayNames[key];
        const acc = (data.accuracy * 100).toFixed(2);
        const prec = data.precision !== undefined ? (data.precision * 100).toFixed(2) + '%' : '—';
        const f1 = (data.f1_score * 100).toFixed(2);
        const fpr = data.false_positive_rate !== undefined ? (data.false_positive_rate * 100).toFixed(2) + '%' : '—';

        let barClass = 'good';
        if (data.accuracy >= 0.78) barClass = 'excellent';
        else if (data.accuracy < 0.72) barClass = 'fair';

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td class="model-name">${name}</td>
            <td style="color:var(--neutral-600);">${task}</td>
            <td class="metric-value">${acc}% <div class="metric-bar"><div class="metric-bar-fill ${barClass}" style="width: ${acc}%"></div></div></td>
            <td class="metric-value">${prec}</td>
            <td class="metric-value">${f1}%</td>
            <td class="metric-value" style="color:${data.false_positive_rate !== undefined && data.false_positive_rate < 0.03 ? 'var(--primary-600)' : 'var(--neutral-900)'}">${fpr}</td>
        `;
        tbody.appendChild(tr);
    }
}

// ─── Global Keyboard Shortcuts ───
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeForensicsDrawer();
        if (settingsModalBackdrop) settingsModalBackdrop.classList.remove('open');
    }
    const tag = (document.activeElement && document.activeElement.tagName) || '';
    const isInput = tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';
    if (!isInput && ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k')) {
        e.preventDefault();
        switchView('sandbox');
    }
});

// ─── Initial API Handshake & Polling ───
fetch(`${API_BASE_URL}/status`)
    .then(res => {
        if (!res.ok) throw new Error('Status check failed');
        return res.json();
    })
    .catch(err => {
        console.error('API Error:', err);
        const dot = document.getElementById('stream-dot');
        if (dot) dot.style.backgroundColor = 'var(--accent-red-600)';
    });

setInterval(fetchStats, 3500);
fetchStats();

// ═══════════════════════════════════════════════════════════════════
// VIEW 07: LIVE WIRESHARK CAPTURE CONTROLLER (WATCH-ONLY, NO AUTO-BLOCK)
// ═══════════════════════════════════════════════════════════════════
let liveEventSource = null;
let liveStatusTimer = null;
let liveResultsHistory = [];
let liveActiveFilter = 'all';
let liveDismissedIPs = new Set();
let liveInitialized = false;
let liveCaptureRunning = false;

async function initLiveWiresharkView() {
    if (!liveInitialized) {
        liveInitialized = true;
        bindLiveWiresharkEvents();
        await loadLiveInterfaces();
        await loadInitialLiveResults();
        connectLiveStream();
        liveStatusTimer = setInterval(() => {
            if ((views.live && views.live.style.display === 'block') || liveCaptureRunning) {
                refreshLiveStatus();
            }
        }, 2000);
    }
    await refreshLiveStatus();
}

async function loadLiveInterfaces() {
    const select = document.getElementById('live-interface-select');
    const startBtn = document.getElementById('live-start-btn');
    if (!select) return;

    try {
        const res = await fetch(`${API_BASE_URL}/live/interfaces`);
        const data = await res.json();
        const interfaces = data.interfaces || [];
        select.innerHTML = '';

        if (!data.available || interfaces.length === 0) {
            select.innerHTML = `<option value="">Wireshark (tshark) not found on this Mac</option>`;
            if (startBtn) startBtn.disabled = true;
            return;
        }

        interfaces.forEach(iface => {
            const opt = document.createElement('option');
            opt.value = iface.name;
            opt.textContent = `${iface.name} — ${iface.label}`;
            if (iface.is_default) opt.selected = true;
            select.appendChild(opt);
        });
        if (startBtn) startBtn.disabled = false;
    } catch (e) {
        select.innerHTML = `<option value="">Could not load network connections</option>`;
    }
}

async function loadInitialLiveResults() {
    try {
        const res = await fetch(`${API_BASE_URL}/live/results?limit=200`);
        if (res.ok) {
            const data = await res.json();
            liveResultsHistory = data.results || [];
            renderLiveConversationsTable();
            renderLiveReviewList();
        }
    } catch (e) {
        console.error('Failed to load live results:', e);
    }
}

async function refreshLiveStatus() {
    try {
        const res = await fetch(`${API_BASE_URL}/live/status`);
        if (!res.ok) return;
        const status = await res.json();
        applyLiveStatusUI(status);
    } catch (e) {
        // silent poll
    }
}

function applyLiveStatusUI(status) {
    liveCaptureRunning = Boolean(status.running);

    const stateTag = document.getElementById('live-state-tag');
    const startBtn = document.getElementById('live-start-btn');
    const select = document.getElementById('live-interface-select');
    const toolLine = document.getElementById('live-tool-line');
    const errBox = document.getElementById('live-error-box');
    const navLiveState = document.getElementById('nav-live-state');
    const navLiveFlagged = document.getElementById('nav-live-flagged');

    if (toolLine) {
        if (status.available) {
            toolLine.innerHTML = `<i class="fa-solid fa-circle-check" aria-hidden="true"></i> <span>Wireshark <strong>tshark ${status.tshark_version || ''}</strong> ready (${status.tshark_path})</span>`;
        } else {
            toolLine.innerHTML = `<i class="fa-solid fa-triangle-exclamation" style="color:var(--accent-red-600)" aria-hidden="true"></i> <span>Wireshark (tshark) was not found in /Applications/Wireshark.app</span>`;
        }
    }

    if (errBox) {
        if (status.error) {
            errBox.hidden = false;
            errBox.textContent = status.error;
        } else {
            errBox.hidden = true;
            errBox.textContent = '';
        }
    }

    if (stateTag) {
        if (liveCaptureRunning) {
            stateTag.className = 'status-tag tag-nominal mono';
            stateTag.innerHTML = `<i class="fa-solid fa-tower-broadcast" aria-hidden="true"></i> LISTENING ON ${(status.interface || '').toUpperCase()}`;
        } else {
            stateTag.className = 'status-tag tag-slate mono';
            stateTag.innerHTML = `<i class="fa-solid fa-circle-pause" aria-hidden="true"></i> STOPPED`;
        }
    }

    if (startBtn) {
        startBtn.disabled = !status.available;
        if (liveCaptureRunning) {
            startBtn.className = 'btn btn-danger';
            startBtn.innerHTML = `<i class="fa-solid fa-stop" aria-hidden="true"></i> <span>Stop Capture</span>`;
        } else {
            startBtn.className = 'btn btn-primary';
            startBtn.innerHTML = `<i class="fa-solid fa-play" aria-hidden="true"></i> <span>Start Capture</span>`;
        }
    }

    if (select && status.interface && liveCaptureRunning) {
        select.value = status.interface;
    }

    const st = status.stats || {};
    const setEl = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = Number(val || 0).toLocaleString();
    };
    setEl('live-count-packets', st.packets || 0);
    setEl('live-count-background', st.background_skipped || 0);
    setEl('live-count-open', status.active_conversations || 0);
    setEl('live-count-checked', st.conversations || 0);
    setEl('live-count-safe', st.safe || 0);
    setEl('live-count-flagged', st.flagged || 0);

    if (navLiveState) {
        navLiveState.hidden = !liveCaptureRunning;
    }
    if (navLiveFlagged) {
        const flaggedCount = st.flagged || 0;
        navLiveFlagged.hidden = flaggedCount === 0;
        navLiveFlagged.textContent = flaggedCount;
    }
}

function connectLiveStream() {
    if (liveEventSource) {
        liveEventSource.close();
    }
    liveEventSource = new EventSource(`${API_BASE_URL}/live/stream`);
    liveEventSource.onmessage = (e) => {
        try {
            const item = JSON.parse(e.data);
            liveResultsHistory.unshift(item);
            if (liveResultsHistory.length > 500) {
                liveResultsHistory.pop();
            }
            renderLiveConversationsTable();
            renderLiveReviewList();
            refreshLiveStatus();
        } catch (err) {
            console.error('Live stream parse error:', err);
        }
    };
}

function bindLiveWiresharkEvents() {
    const startBtn = document.getElementById('live-start-btn');
    const select = document.getElementById('live-interface-select');
    const selfTestBtn = document.getElementById('live-selftest-btn');
    const pcapInput = document.getElementById('live-pcap-input');
    const clearBtn = document.getElementById('live-clear-btn');

    if (startBtn) {
        startBtn.addEventListener('click', async () => {
            startBtn.disabled = true;
            try {
                if (liveCaptureRunning) {
                    const res = await fetch(`${API_BASE_URL}/live/stop`, { method: 'POST' });
                    const data = await res.json();
                    applyLiveStatusUI(data);
                    showToast('Stopped live Wireshark capture.', 'info');
                } else {
                    const iface = select ? select.value : 'en0';
                    const res = await fetch(`${API_BASE_URL}/live/start`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ interface: iface })
                    });
                    const data = await res.json();
                    if (!res.ok) {
                        showToast(data.error || 'Could not start capture', 'danger');
                        await refreshLiveStatus();
                    } else {
                        applyLiveStatusUI(data);
                        showToast(`Wireshark is now listening on ${iface} (Watch-Only).`, 'success');
                    }
                }
            } catch (e) {
                showToast('Network error talking to capture server.', 'danger');
            } finally {
                startBtn.disabled = false;
            }
        });
    }

    if (selfTestBtn) {
        selfTestBtn.addEventListener('click', async () => {
            selfTestBtn.disabled = true;
            try {
                // If not already listening on lo0, automatically switch to lo0 and start capture
                if (!liveCaptureRunning || (select && select.value !== 'lo0')) {
                    if (select) select.value = 'lo0';
                    const startRes = await fetch(`${API_BASE_URL}/live/start`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ interface: 'lo0' })
                    });
                    const startData = await startRes.json();
                    if (!startRes.ok) {
                        showToast(startData.error || 'Could not start Loopback capture', 'danger');
                        return;
                    }
                    applyLiveStatusUI(startData);
                }

                const res = await fetch(`${API_BASE_URL}/live/self-test`, { method: 'POST' });
                const data = await res.json();
                if (!res.ok) {
                    showToast(data.error || 'Self-test could not run', 'danger');
                } else {
                    showToast('Running safe self-test on 127.0.0.1 (ports 1–300)... Watch the table!', 'success');
                }
            } catch (e) {
                showToast('Failed to trigger self-test.', 'danger');
            } finally {
                setTimeout(() => { selfTestBtn.disabled = false; }, 2500);
            }
        });
    }

    if (pcapInput) {
        pcapInput.addEventListener('change', async () => {
            const file = pcapInput.files && pcapInput.files[0];
            if (!file) return;
            const formData = new FormData();
            formData.append('file', file);
            showToast(`Checking ${file.name} with the 5 AI models...`, 'info');
            try {
                const res = await fetch(`${API_BASE_URL}/live/upload`, {
                    method: 'POST',
                    body: formData
                });
                const data = await res.json();
                if (!res.ok) {
                    showToast(data.error || 'Could not read .pcap file', 'danger');
                } else {
                    await loadInitialLiveResults();
                    await refreshLiveStatus();
                    showToast(`Checked ${data.conversations} conversations from ${data.file_name} (${data.flagged} flagged).`, 'success');
                }
            } catch (e) {
                showToast('Upload failed.', 'danger');
            } finally {
                pcapInput.value = '';
            }
        });
    }

    if (clearBtn) {
        clearBtn.addEventListener('click', async () => {
            await fetch(`${API_BASE_URL}/live/clear`, { method: 'POST' });
            liveResultsHistory = [];
            liveDismissedIPs.clear();
            renderLiveConversationsTable();
            renderLiveReviewList();
            await refreshLiveStatus();
            showToast('Cleared live Wireshark list.', 'info');
        });
    }

    document.querySelectorAll('[data-live-filter]').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('[data-live-filter]').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            liveActiveFilter = btn.getAttribute('data-live-filter') || 'all';
            renderLiveConversationsTable();
        });
    });
}

function renderLiveConversationsTable() {
    const tbody = document.getElementById('live-table-body');
    const countEl = document.getElementById('live-table-count');
    if (!tbody) return;

    const filtered = liveResultsHistory.filter(item => {
        if (liveActiveFilter === 'flagged') return Boolean(item.is_attack);
        if (liveActiveFilter === 'safe') return !item.is_attack;
        return true;
    });

    if (countEl) countEl.textContent = filtered.length;

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="mono table-empty-cell">No conversations match this view yet. Press <strong>Start Capture</strong> or run the <strong>Safe Self-Test Scan</strong>.</td></tr>`;
        return;
    }

    tbody.innerHTML = '';
    filtered.slice(0, 120).forEach(item => {
        const tr = document.createElement('tr');
        const timeStr = new Date(item.timestamp).toLocaleTimeString('en-US', { hour12: false });
        const sevClass = item.is_attack ? (item.severity || 'medium') : 'info';
        const friendlyCat = FRIENDLY_CATEGORY_LABELS[item.attack_category] || item.attack_category;
        const badgeText = item.is_attack ? `FLAGGED: ${friendlyCat}` : 'SAFE / NORMAL';

        let barColor = 'var(--primary-600)';
        if (item.anomaly_score > 0.7) barColor = 'var(--accent-red-600)';
        else if (item.anomaly_score > 0.45) barColor = 'var(--accent-ochre-500)';

        tr.innerHTML = `
            <td class="mono" style="color:var(--neutral-600);">${timeStr}</td>
            <td><span class="threat-badge ${sevClass}">${badgeText}</span></td>
            <td class="mono" style="font-size:0.8rem;">${item.src_ip}:${item.src_port} → ${item.dst_ip}:${item.dst_port}</td>
            <td><strong>${item.service_label || item.service}</strong> <span class="mono" style="color:var(--neutral-500);font-size:0.75rem;">(${item.protocol.toUpperCase()})</span></td>
            <td><span style="color:var(--neutral-700);">${item.flag_label || item.flag}</span> <span class="mono" style="color:var(--neutral-500);font-size:0.74rem;">[${item.flag}]</span></td>
            <td class="mono" style="font-size:0.8rem;">${Number(item.src_bytes || 0).toLocaleString()} B ↑ / ${Number(item.dst_bytes || 0).toLocaleString()} B ↓</td>
            <td class="mono">
                ${Number(item.anomaly_score || 0).toFixed(2)}
                <div class="anomaly-bar" style="display:inline-block;width:44px;margin-left:6px;vertical-align:middle;">
                    <div class="anomaly-bar-fill" style="width:${Math.min(100, (item.anomaly_score || 0) * 100)}%; background-color:${barColor}"></div>
                </div>
            </td>
            <td style="text-align: right;">
                <button type="button" class="btn btn-sm btn-secondary">
                    <i class="fa-solid fa-eye" aria-hidden="true"></i> Inspect
                </button>
            </td>
        `;

        tr.addEventListener('click', () => openLiveConversationDetails(item));
        tbody.appendChild(tr);
    });
}

function renderLiveReviewList() {
    const container = document.getElementById('live-review-list');
    if (!container) return;

    // Group flagged conversations by target or sender IP so you can review each address once
    const byIp = new Map();
    liveResultsHistory.forEach(item => {
        if (!item.is_attack) return;
        const candidateIp = item.direction === 'outgoing' ? item.dst_ip : item.src_ip;
        if (!candidateIp || liveDismissedIPs.has(candidateIp)) return;
        const existing = byIp.get(candidateIp) || {
            ip: candidateIp,
            count: 0,
            latest: item,
            categories: new Set()
        };
        existing.count += 1;
        existing.categories.add(FRIENDLY_CATEGORY_LABELS[item.attack_category] || item.attack_category);
        byIp.set(candidateIp, existing);
    });

    if (byIp.size === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-text">No flagged addresses waiting for review. When the AI spots something suspicious, it appears here for your decision.</div>
            </div>
        `;
        return;
    }

    container.innerHTML = '';
    Array.from(byIp.values()).slice(0, 20).forEach(group => {
        const div = document.createElement('div');
        const isCrit = group.latest.severity === 'critical';
        div.className = `live-review-item ${isCrit ? 'is-critical' : ''}`;
        const cats = Array.from(group.categories).join(', ');
        const isLocal = group.ip === '127.0.0.1' || group.ip === '::1';

        div.innerHTML = `
            <div>
                <div class="mono" style="font-weight:700;font-size:0.9rem;color:var(--neutral-900);">
                    ${group.ip} ${isLocal ? '<span class="status-tag tag-slate mono" style="margin-left:6px;">THIS MAC (SELF-TEST)</span>' : ''}
                </div>
                <div class="live-review-meta">
                    Flagged <strong>${group.count}</strong> time${group.count > 1 ? 's' : ''} as <strong>${cats}</strong> · Last service: ${group.latest.service_label || group.latest.service}
                </div>
            </div>
            <div class="live-review-actions">
                <button type="button" class="btn btn-sm btn-secondary" data-dismiss-ip="${group.ip}">Ignore</button>
                <button type="button" class="btn btn-sm btn-danger" data-manual-block-ip="${group.ip}" data-manual-block-cat="${cats}">
                    <i class="fa-solid fa-ban" aria-hidden="true"></i> Block IP
                </button>
            </div>
        `;

        const dismissBtn = div.querySelector('[data-dismiss-ip]');
        if (dismissBtn) {
            dismissBtn.addEventListener('click', () => {
                liveDismissedIPs.add(group.ip);
                renderLiveReviewList();
            });
        }
        const blockBtn = div.querySelector('[data-manual-block-ip]');
        if (blockBtn) {
            blockBtn.addEventListener('click', () => {
                if (window.blockThreatIP) {
                    window.blockThreatIP(group.ip, `Manual review from Live Wireshark (${cats})`);
                }
                liveDismissedIPs.add(group.ip);
                renderLiveReviewList();
            });
        }
        container.appendChild(div);
    });
}

function openLiveConversationDetails(item) {
    if (!forensicsDrawer || !drawerBody || !item) return;

    const friendlyCat = FRIENDLY_CATEGORY_LABELS[item.attack_category] || item.attack_category;
    if (drawerKicker) drawerKicker.textContent = `LIVE WIRESHARK // ${item.id}`;
    if (drawerTitle) drawerTitle.textContent = item.is_attack ? `Flagged: ${friendlyCat}` : 'Safe / Normal Conversation';

    const sevClass = item.is_attack ? (item.severity || 'medium') : 'info';
    const votes = item.model_votes || {};
    const voteRows = Object.entries(votes).map(([modelKey, v]) => {
        const labelMap = {
            rf_binary: 'Random Forest (Safe vs. Attack)',
            rf_multi: 'Random Forest (Attack Type)',
            nn_binary: 'Neural Network (Safe vs. Attack)',
            nn_multi: 'Neural Network (Attack Type)',
            isolation_forest: 'Isolation Forest (Unusual Finder)'
        };
        return `<div class="forensic-cell">
            <div class="forensic-cell-label">${labelMap[modelKey] || modelKey}</div>
            <div class="forensic-cell-val">${v.prediction} (${(Number(v.confidence || 0) * 100).toFixed(0)}%)</div>
        </div>`;
    }).join('');

    const w = item.window || {};
    drawerBody.innerHTML = `
        <div class="diagnostics-verdict" style="border-left: 4px solid var(--${sevClass});">
            <div class="verdict-left">
                <span class="mono" style="font-size:0.7rem;color:var(--neutral-500);font-weight:700;">WATCH-ONLY AI VERDICT (NOT AUTO-BLOCKED)</span>
                <h3>${friendlyCat}</h3>
                <div class="mono" style="font-size:0.78rem;color:var(--neutral-600);">
                    ${item.service_label || item.service} · ${item.packets || 1} packet${(item.packets || 1) > 1 ? 's' : ''}
                </div>
            </div>
            <div style="text-align:right;">
                <span class="verdict-badge ${sevClass}">${item.is_attack ? 'NEEDS REVIEW' : 'SAFE'}</span>
                <div class="mono" style="font-size:0.74rem;color:var(--neutral-600);margin-top:6px;">
                    Confidence: ${(Number(item.confidence || 0) * 100).toFixed(1)}%
                </div>
            </div>
        </div>

        <div class="forensic-grid">
            <div class="forensic-cell">
                <div class="forensic-cell-label">From IP &amp; Port</div>
                <div class="forensic-cell-val">${item.src_ip}:${item.src_port}</div>
            </div>
            <div class="forensic-cell">
                <div class="forensic-cell-label">To IP &amp; Port</div>
                <div class="forensic-cell-val">${item.dst_ip}:${item.dst_port}</div>
            </div>
            <div class="forensic-cell">
                <div class="forensic-cell-label">How It Ended</div>
                <div class="forensic-cell-val">${item.flag_label || item.flag} (${item.flag})</div>
            </div>
            <div class="forensic-cell">
                <div class="forensic-cell-label">Bytes Sent → Received</div>
                <div class="forensic-cell-val">${Number(item.src_bytes || 0).toLocaleString()} B → ${Number(item.dst_bytes || 0).toLocaleString()} B</div>
            </div>
            <div class="forensic-cell">
                <div class="forensic-cell-label">2-Second Window Burst</div>
                <div class="forensic-cell-val">${w.count || 1} conns (SYN err: ${Math.round((w.serror_rate || 0) * 100)}%, REJ err: ${Math.round((w.rerror_rate || 0) * 100)}%)</div>
            </div>
            <div class="forensic-cell">
                <div class="forensic-cell-label">Unusual Score</div>
                <div class="forensic-cell-val">${Number(item.anomaly_score || 0).toFixed(2)} / 1.00</div>
            </div>
        </div>

        <div class="card-kicker mono" style="margin-top:8px;">HOW EACH OF THE 5 AI MODELS VOTED</div>
        <div class="forensic-grid">
            ${voteRows}
        </div>

        <div class="forensic-cell" style="margin-top:6px;">
            <div class="forensic-cell-label">Why the AI reached this decision</div>
            <div class="forensic-cell-val" style="font-size:0.78rem;color:var(--primary-700);">
                ${(item.key_indicators || []).join(' • ') || 'Normal connection pattern'}
            </div>
        </div>

        <div style="display:flex;flex-direction:column;gap:8px;margin-top:10px;">
            <button type="button" class="btn btn-danger btn-block" onclick="blockThreatIP('${item.src_ip}', 'Manual block from Live Wireshark (${item.id})'); closeForensicsDrawer();">
                <i class="fa-solid fa-ban" aria-hidden="true"></i> Manually Block Sender IP (${item.src_ip})
            </button>
        </div>
    `;

    forensicsDrawer.classList.add('open');
    forensicsBackdrop.classList.add('open');
}

