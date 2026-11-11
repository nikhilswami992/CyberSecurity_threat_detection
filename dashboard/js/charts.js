/**
 * ThreatGuard AI // Live Traffic Charts & Activity Wave Controller
 * Strictly solid fills and strokes (no gradients, no shadowBlur glows, WCAG 2.2 AA).
 */

Chart.defaults.color = '#524C43';
Chart.defaults.font.family = "'Space Grotesk', sans-serif";
Chart.defaults.font.size = 11;
Chart.defaults.scale.grid.color = '#E5E0D5';

let trafficChart;
let threatPieChart;

let maxDataPoints = 18;
let attacksOnlyMode = false;

const timeLabels = [
    '00:10', '00:15', '00:20', '00:25', '00:30', '00:35',
    '00:40', '00:45', '00:50', '00:55', '01:00', '01:05',
    '01:10', '01:15', '01:20', '01:25', '01:30', 'LIVE'
];
const normalData = [18, 11, 15, 24, 14, 19, 10, 22, 16, 20, 14, 18, 12, 17, 13, 19, 15, 16];
const attackData = [7, 4, 3, 14, 6, 11, 4, 12, 15, 8, 6, 10, 5, 9, 4, 10, 6, 8];

let oscSpikeIntensity = 1.0;
let recentBytesTotal = 14800;

function initCharts() {
    // 1. Live Traffic Line Chart (Normal Safe Traffic vs. Detected Cyber Attacks)
    const trafficCanvas = document.getElementById('trafficChart');
    if (trafficCanvas) {
        const ctxTraffic = trafficCanvas.getContext('2d');

        trafficChart = new Chart(ctxTraffic, {
            type: 'line',
            data: {
                labels: timeLabels,
                datasets: [
                    {
                        label: 'Normal Safe Traffic',
                        data: normalData,
                        borderColor: '#1B4D3E',
                        backgroundColor: 'rgba(27, 77, 62, 0.08)',
                        borderWidth: 2.2,
                        tension: 0.22,
                        fill: true,
                        pointStyle: 'rect',
                        pointRadius: 3.5,
                        pointBackgroundColor: '#1B4D3E',
                        pointBorderColor: '#FAF8F4',
                        pointBorderWidth: 1.5,
                        pointHoverRadius: 5
                    },
                    {
                        label: 'Detected Cyber Attacks',
                        data: attackData,
                        borderColor: '#C83A2B',
                        backgroundColor: 'rgba(200, 58, 43, 0.08)',
                        borderWidth: 2.2,
                        borderDash: [4, 2],
                        tension: 0.18,
                        fill: false,
                        pointStyle: 'triangle',
                        pointRadius: 4.5,
                        pointBackgroundColor: '#C83A2B',
                        pointBorderColor: '#FAF8F4',
                        pointBorderWidth: 1.5,
                        pointHoverRadius: 6
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        backgroundColor: '#161513',
                        titleColor: '#FAF8F4',
                        bodyColor: '#E5E0D5',
                        borderColor: '#3B3630',
                        borderWidth: 1,
                        padding: 10
                    }
                },
                scales: {
                    x: {
                        grid: { color: '#E5E0D5' },
                        ticks: { maxTicksLimit: 8, color: '#524C43' }
                    },
                    y: {
                        beginAtZero: true,
                        border: { display: false },
                        grid: { color: '#E5E0D5' },
                        ticks: { maxTicksLimit: 5, color: '#524C43' }
                    }
                }
            }
        });
    }

    // 2. Attack Types Ring Chart
    const pieCanvas = document.getElementById('threatPieChart');
    if (pieCanvas) {
        const ctxPie = pieCanvas.getContext('2d');
        threatPieChart = new Chart(ctxPie, {
            type: 'doughnut',
            data: {
                labels: ['DoS (Server Floods)', 'Port Scans', 'Login & Admin Hacks', 'Normal Safe Traffic'],
                datasets: [{
                    data: [35, 25, 15, 25],
                    backgroundColor: [
                        '#C83A2B', // Vermilion Alert (DoS)
                        '#B85D19', // Ochre Copper (Port Scans)
                        '#243B53', // Mineral Slate (Login/Admin Hacks)
                        '#1B4D3E'  // Signal Pine (Normal Safe Traffic)
                    ],
                    borderColor: '#FAF8F4',
                    borderWidth: 3,
                    hoverOffset: 3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '72%',
                rotation: -45,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: '#161513',
                        titleColor: '#FAF8F4',
                        bodyColor: '#E5E0D5',
                        borderColor: '#3B3630',
                        borderWidth: 1
                    }
                }
            }
        });
    }

    // 3. Live Network Activity Wave
    initOscilloscope();

    // Time-window & filter buttons
    document.querySelectorAll('[data-chart-window]').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('[data-chart-window]').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            maxDataPoints = parseInt(btn.getAttribute('data-chart-window'), 10) === 60 ? 30 : 18;
        });
    });

    const toggleAttacksBtn = document.getElementById('toggle-attacks-only-btn');
    if (toggleAttacksBtn) {
        toggleAttacksBtn.addEventListener('click', () => {
            attacksOnlyMode = !attacksOnlyMode;
            toggleAttacksBtn.classList.toggle('active', attacksOnlyMode);
            if (trafficChart) {
                trafficChart.setDatasetVisibility(0, !attacksOnlyMode);
                trafficChart.update();
            }
        });
    }
}

function initOscilloscope() {
    const canvas = document.getElementById('waveformCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const prefersReducedMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    let phase = 0;

    function resize() {
        const rect = canvas.parentElement.getBoundingClientRect();
        if (rect.width > 0 && rect.height > 0) {
            canvas.width = Math.max(300, Math.floor(rect.width));
            canvas.height = Math.max(130, Math.floor(rect.height));
        }
    }
    resize();
    window.addEventListener('resize', resize);
    window.resizeDashboardCharts = resize;

    function renderFrame() {
        if (canvas.offsetParent === null) {
            if (!prefersReducedMotion) {
                requestAnimationFrame(renderFrame);
            }
            return;
        }
        const w = canvas.width;
        const h = canvas.height;
        const midY = h * 0.54;

        ctx.clearRect(0, 0, w, h);

        // Crisp grid lines on warm stone surface
        ctx.strokeStyle = '#D2CBC0';
        ctx.lineWidth = 1;
        for (let y = 28; y < h; y += 34) {
            ctx.beginPath();
            ctx.moveTo(0, y);
            ctx.lineTo(w, y);
            ctx.stroke();
        }
        for (let x = 44; x < w; x += 64) {
            ctx.beginPath();
            ctx.moveTo(x, 0);
            ctx.lineTo(x, h);
            ctx.stroke();
        }

        // Reference centerline
        ctx.beginPath();
        ctx.moveTo(0, midY);
        ctx.lineTo(w, midY);
        ctx.strokeStyle = '#A8A093';
        ctx.lineWidth = 1;
        ctx.stroke();

        // Solid Signal Pine / Vermilion waveform stroke
        ctx.beginPath();
        for (let x = 0; x < w; x += 2) {
            const normX = x / w;
            const envelope = Math.sin(normX * Math.PI);
            const carrier = Math.sin(x * 0.42 + phase * 2.8) * Math.cos(x * 0.18 - phase * 1.5);
            const burst = Math.pow(Math.abs(Math.sin(x * 0.065 + phase * 0.55)), 6) * 38 * oscSpikeIntensity;
            const microNoise = Math.sin(x * 1.6 + phase * 4.2) * 6;
            const yOffset = (carrier * 14 + (x % 4 === 0 ? burst : -burst * 0.62) + microNoise) * envelope;

            const y = midY - yOffset;
            if (x === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        }

        ctx.strokeStyle = oscSpikeIntensity > 1.35 ? '#C83A2B' : '#1B4D3E';
        ctx.lineWidth = 1.6;
        ctx.stroke();

        phase += 0.04;
        oscSpikeIntensity = Math.max(0.85, oscSpikeIntensity * 0.985);

        if (!prefersReducedMotion) {
            requestAnimationFrame(renderFrame);
        }
    }

    renderFrame();
}

let currentSecondNormal = 0;
let currentSecondAttack = 0;

function aggregateEventForChart(event) {
    if (event.is_attack) {
        currentSecondAttack++;
        oscSpikeIntensity = Math.min(2.0, oscSpikeIntensity + 0.45);
    } else {
        currentSecondNormal++;
        oscSpikeIntensity = Math.min(1.3, oscSpikeIntensity + 0.12);
    }

    recentBytesTotal = (event.src_bytes || 320) + (event.dst_bytes || 1450);
    const bytesEl = document.getElementById('osc-bytes-sec');
    if (bytesEl) {
        bytesEl.textContent = `${(recentBytesTotal / 1024 + 8.4).toFixed(1)} KB/s`;
    }
}

setInterval(() => {
    if (!trafficChart) return;

    const now = new Date();
    const timeStr = now.toLocaleTimeString('en-US', { hour12: false }).slice(3, 8);

    const normVal = currentSecondNormal * 6 + Math.floor(8 + (now.getSeconds() % 7));
    const atkVal = currentSecondAttack * 6 + Math.floor(3 + ((now.getSeconds() * 3) % 5));

    timeLabels.push(timeStr);
    normalData.push(normVal);
    attackData.push(atkVal);

    while (timeLabels.length > maxDataPoints) {
        timeLabels.shift();
        normalData.shift();
        attackData.shift();
    }

    const totalRate = currentSecondNormal + currentSecondAttack;
    const rateEl = document.getElementById('conn-rate');
    if (rateEl) {
        rateEl.textContent = `${Math.max(1, totalRate)} pkt/s`;
    }

    currentSecondNormal = 0;
    currentSecondAttack = 0;

    trafficChart.update('none');
}, 1500);

function updatePieChart(categories) {
    if (!categories) return;

    const dos = categories['DoS'] || 0;
    const probe = categories['Probe'] || 0;
    const r2l = categories['R2L'] || 0;
    const u2r = categories['U2R'] || 0;
    const normal = categories['Normal'] || 0;
    const totalAttacks = dos + probe + r2l + u2r;

    const elTotal = document.getElementById('taxonomy-total-attacks');
    if (elTotal) elTotal.textContent = `${totalAttacks.toLocaleString()} Attacks`;

    const digDos = document.getElementById('digest-dos-meta');
    const digProbe = document.getElementById('digest-probe-meta');
    const digR2l = document.getElementById('digest-r2l-meta');
    if (digDos) digDos.textContent = `${dos.toLocaleString()} server flood attacks`;
    if (digProbe) digProbe.textContent = `${probe.toLocaleString()} port scan sweeps`;
    if (digR2l) digR2l.textContent = `${(r2l + u2r).toLocaleString()} login/admin hack attempts`;

    if (threatPieChart && totalAttacks > 0) {
        threatPieChart.data.datasets[0].data = [
            Math.max(1, dos),
            Math.max(1, probe),
            Math.max(1, r2l + u2r),
            Math.max(1, Math.round(normal * 0.35))
        ];
        threatPieChart.update();
    }
}

window.updatePieChart = updatePieChart;
window.aggregateEventForChart = aggregateEventForChart;

document.addEventListener('DOMContentLoaded', initCharts);
