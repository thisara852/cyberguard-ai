// CyberGuard AI SOC Dashboard JavaScript Controller
let authToken = "";
let currentIncidentId = null;
let ws = null;

document.addEventListener("DOMContentLoaded", async () => {
  await autoLoginAdmin();
  initWebSocket();
  refreshDashboard();
  loadAttackGraph();
  loadMLOpsHealth();
});

// Auto-login as default Admin for seamless dashboard exploration
async function autoLoginAdmin() {
  try {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "admin", password: "Admin@123" })
    });
    if (res.ok) {
      const data = await res.json();
      authToken = data.access_token;
      document.getElementById("headerUsername").textContent = data.user.username;
      document.getElementById("headerRole").textContent = data.user.role;
    }
  } catch (e) {
    console.error("Auto-login error:", e);
  }
}

function getAuthHeaders() {
  return {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${authToken}`
  };
}

// Tab Switching
function switchTab(tabId) {
  document.querySelectorAll(".nav-item").forEach(el => el.classList.remove("active"));
  document.querySelectorAll(".page-section").forEach(el => el.classList.remove("active"));

  const targetSection = document.getElementById(`section-${tabId}`);
  if (targetSection) targetSection.classList.add("active");

  const navElements = document.querySelectorAll(".nav-item");
  const tabNames = ['dashboard', 'events', 'ml', 'scanners', 'incidents', 'visualization', 'assistant', 'mlops', 'admin'];
  const idx = tabNames.indexOf(tabId);
  if (idx !== -1 && navElements[idx]) {
    navElements[idx].classList.add("active");
  }

  // Contextual refresh
  if (tabId === "events") loadEvents();
  if (tabId === "incidents") loadIncidents();
  if (tabId === "visualization") loadAttackGraph();
  if (tabId === "admin") loadAuditLogs();
  if (tabId === "mlops") loadMLOpsHealth();
}

// Real-Time WebSocket Connection (FR-20)
function initWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws/soc`;
  
  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    document.getElementById("wsStatusText").textContent = "SOC REAL-TIME: CONNECTED";
    document.getElementById("wsStatus").style.color = "var(--success)";
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.type === "NEW_ALERT") {
        handleRealTimeAlert(data.alert);
      }
    } catch (e) {}
  };

  ws.onclose = () => {
    document.getElementById("wsStatusText").textContent = "RECONNECTING...";
    document.getElementById("wsStatus").style.color = "var(--warning)";
    setTimeout(initWebSocket, 3000);
  };
}

function handleRealTimeAlert(alert) {
  refreshDashboard();
  // Play subtle visual highlight on table
  const badge = document.getElementById("alertStreamBadge");
  badge.textContent = `NEW ALERT: ${alert.threat_type}`;
  badge.style.background = "var(--danger)";
  setTimeout(() => {
    badge.textContent = "LIVE STREAM";
    badge.style.background = "rgba(244, 63, 94, 0.15)";
  }, 4000);
}

// 1. Dashboard Telemetry & Alerts (FR-32)
async function refreshDashboard() {
  try {
    const res = await fetch("/api/analytics/overview", { headers: getAuthHeaders() });
    if (!res.ok) return;
    const data = await res.json();

    document.getElementById("valPosture").textContent = data.security_posture_score;
    document.getElementById("meterPosture").style.width = `${data.security_posture_score}%`;
    document.getElementById("valAlerts").textContent = data.total_alerts;
    document.getElementById("valAssets").textContent = data.total_monitored_devices;
    document.getElementById("valIncidents").textContent = data.active_incidents;

    document.getElementById("cntCritical").textContent = `${data.severity_breakdown.critical} Critical`;
    document.getElementById("cntHigh").textContent = `${data.severity_breakdown.high} High`;

    loadAlertsTable();
  } catch (e) {
    console.error("Failed to load overview:", e);
  }
}

async function loadAlertsTable() {
  try {
    const res = await fetch("/api/alerts/?limit=10", { headers: getAuthHeaders() });
    if (!res.ok) return;
    const alerts = await res.json();
    const tbody = document.getElementById("alertsTableBody");

    if (!alerts || alerts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No recent alerts detected</td></tr>`;
      return;
    }

    tbody.innerHTML = alerts.map(a => {
      const sevClass = a.severity === "CRITICAL" ? "badge-critical" : (a.severity === "HIGH" ? "badge-high" : (a.severity === "MEDIUM" ? "badge-medium" : "badge-low"));
      const timeStr = new Date(a.created_at).toLocaleTimeString();
      return `
        <tr>
          <td>${timeStr}</td>
          <td><strong>${a.threat_type}</strong></td>
          <td><span class="${sevClass}">${a.severity}</span></td>
          <td><code>${a.source_ip}</code></td>
          <td><code>${a.target_ip}</code></td>
          <td><strong>${a.risk_score}</strong></td>
          <td><span style="color: var(--text-secondary); font-size: 11px;">${a.status}</span></td>
          <td>
            ${a.status === 'OPEN' ? `<button class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="acknowledgeAlert(${a.id})">Ack</button>` : ''}
            ${a.status !== 'ESCALATED' ? `<button class="btn btn-primary" style="padding: 4px 8px; font-size: 11px;" onclick="escalateAlert(${a.id})">Escalate</button>` : '<span style="font-size:11px; color:var(--accent-cyan)">Escalated</span>'}
          </td>
        </tr>
      `;
    }).join("");
  } catch (e) {
    console.error("Alerts error:", e);
  }
}

async function acknowledgeAlert(id) {
  await fetch(`/api/alerts/${id}/acknowledge`, { method: "POST", headers: getAuthHeaders() });
  refreshDashboard();
}

async function escalateAlert(id) {
  const res = await fetch(`/api/alerts/${id}/escalate`, { method: "POST", headers: getAuthHeaders() });
  if (res.ok) {
    alert("Alert successfully escalated to formal incident!");
    refreshDashboard();
  }
}

// 2. Live Security Events (FR-06, FR-07)
async function loadEvents() {
  try {
    const res = await fetch("/api/events/?limit=25", { headers: getAuthHeaders() });
    if (!res.ok) return;
    const events = await res.json();
    const tbody = document.getElementById("eventsTableBody");

    if (!events.length) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No events found. Click 'Generate 30 Events' to test!</td></tr>`;
      return;
    }

    tbody.innerHTML = events.map(e => `
      <tr>
        <td>${new Date(e.timestamp).toLocaleTimeString()}</td>
        <td><code>${e.source_ip}</code> &rarr; <code>${e.destination_ip}:${e.destination_port}</code></td>
        <td>${e.protocol} / ${e.service}</td>
        <td>${e.packet_count} pkts / ${e.bytes_sent + e.bytes_received} B</td>
        <td><span style="color: var(--accent-cyan); font-family: 'JetBrains Mono', monospace;">${e.flags}</span></td>
        <td>${e.event_category}</td>
      </tr>
    `).join("");
  } catch (e) {
    console.error("Events error:", e);
  }
}

async function generateSampleEvents(count) {
  await fetch(`/api/events/generate-sample?count=${count}`, { method: "POST", headers: getAuthHeaders() });
  loadEvents();
  refreshDashboard();
}

// 3. Machine Learning Inference Sandbox (FR-10, FR-11, FR-17)
async function runMLInference() {
  const payload = {
    source_ip: document.getElementById("mlSrcIp").value,
    destination_ip: document.getElementById("mlDstIp").value,
    destination_port: parseInt(document.getElementById("mlDstPort").value),
    protocol: document.getElementById("mlProto").value,
    packet_count: parseInt(document.getElementById("mlPackets").value),
    bytes_sent: parseInt(document.getElementById("mlBytes").value)
  };

  const box = document.getElementById("mlResultBox");
  box.innerHTML = `<span style="color: var(--accent-cyan);">Evaluating telemetry through ML pipelines...</span>`;

  try {
    const res = await fetch("/api/ml/predict-intrusion", {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error("Inference failed");
    const data = await res.json();

    const sevClass = data.severity === "CRITICAL" ? "badge-critical" : (data.severity === "HIGH" ? "badge-high" : "badge-medium");

    box.innerHTML = `
      <div style="background: rgba(0,0,0,0.3); padding: 16px; border-radius: 8px; border: 1px solid var(--border-color);">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
          <h4 style="color: var(--text-primary); font-size: 16px;">Detection: <strong>${data.threat_type}</strong></h4>
          <span class="${sevClass}">${data.severity} SEVERITY</span>
        </div>
        <p><strong>Calculated Risk Score:</strong> ${data.risk_score} / 100</p>
        <p><strong>ML Confidence:</strong> ${(data.confidence * 100).toFixed(1)}%</p>
        <p><strong>Isolation Forest Anomaly:</strong> ${data.anomaly_score}</p>
        <p><strong>Model Engine:</strong> ${data.model_name} (v${data.model_version})</p>
        <hr style="border: 0; border-top: 1px solid var(--border-color); margin: 12px 0;">
        <h5 style="color: var(--accent-blue); margin-bottom: 6px;">Explainability & Factor Contributions:</h5>
        <pre style="font-size: 11px; background: rgba(0,0,0,0.5); padding: 8px; border-radius: 4px; overflow-x: auto;">${JSON.stringify(data.explanation, null, 2)}</pre>
      </div>
    `;
    refreshDashboard();
  } catch (e) {
    box.innerHTML = `<span style="color: var(--danger);">Inference error: ${e.message}</span>`;
  }
}

async function retrainModel() {
  const res = await fetch("/api/ml/train?samples=1500", { method: "POST", headers: getAuthHeaders() });
  if (res.ok) {
    const d = await res.json();
    alert(`Retraining complete! Model: ${d.model_name} (Accuracy: ${d.metrics.accuracy}, F1: ${d.metrics.f1_score})`);
    loadMLOpsHealth();
  }
}

// 4. Phishing & Malware Scanners (FR-14, FR-15)
async function scanPhishingURL() {
  const url = encodeURIComponent(document.getElementById("phishUrlInput").value);
  const out = document.getElementById("phishResult");
  out.innerHTML = "Analyzing lexical and structural URL markers...";

  const res = await fetch(`/api/ml/scan-url?url=${url}`, { method: "POST", headers: getAuthHeaders() });
  if (res.ok) {
    const d = await res.json();
    const color = d.classification === "Phishing" ? "var(--danger)" : (d.classification === "Suspicious" ? "var(--warning)" : "var(--success)");
    out.innerHTML = `
      <div style="background: rgba(0,0,0,0.3); padding: 12px; border-radius: 8px; border: 1px solid ${color};">
        <h4 style="color: ${color};">Verdict: ${d.classification} (Risk: ${d.risk_score} / 100)</h4>
        <p style="margin-top: 6px; color: var(--text-secondary);"><strong>Entropy:</strong> ${d.features.entropy} | <strong>Confidence:</strong> ${(d.confidence*100).toFixed(0)}%</p>
        <ul style="margin-left: 18px; margin-top: 8px; color: var(--text-muted);">
          ${d.reasons.map(r => `<li>${r}</li>`).join("")}
        </ul>
      </div>
    `;
  }
}

async function scanMalwareMetadata() {
  const filename = encodeURIComponent(document.getElementById("malFilename").value);
  const entropy = document.getElementById("malEntropy").value;
  const imports = encodeURIComponent(document.getElementById("malImports").value);
  const out = document.getElementById("malResult");
  out.innerHTML = "Analyzing file payload metadata...";

  const res = await fetch(`/api/ml/scan-file?filename=${filename}&section_entropy=${entropy}&imports=${imports}`, {
    method: "POST",
    headers: getAuthHeaders()
  });
  if (res.ok) {
    const d = await res.json();
    const color = d.classification === "Malicious" ? "var(--danger)" : (d.classification === "Suspicious" ? "var(--warning)" : "var(--success)");
    out.innerHTML = `
      <div style="background: rgba(0,0,0,0.3); padding: 12px; border-radius: 8px; border: 1px solid ${color};">
        <h4 style="color: ${color};">Verdict: ${d.classification}</h4>
        <p style="margin-top: 6px;"><strong>Recommended Action:</strong> <span style="color: var(--accent-cyan); font-weight: 600;">${d.recommended_action}</span></p>
        <ul style="margin-left: 18px; margin-top: 8px; color: var(--text-muted);">
          ${d.reasons.map(r => `<li>${r}</li>`).join("")}
        </ul>
      </div>
    `;
  }
}

// 5. Incident Lifecycle & Playbooks (FR-23 to FR-28, FR-40)
async function loadIncidents() {
  const res = await fetch("/api/incidents/", { headers: getAuthHeaders() });
  if (!res.ok) return;
  const incs = await res.json();
  const tbody = document.getElementById("incidentsTableBody");

  if (!incs.length) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted);">No open incidents</td></tr>`;
    return;
  }

  tbody.innerHTML = incs.map(inc => {
    const sevClass = inc.severity === "CRITICAL" ? "badge-critical" : "badge-high";
    return `
      <tr>
        <td><code>${inc.incident_code}</code></td>
        <td><strong>${inc.title}</strong></td>
        <td><span class="${sevClass}">${inc.severity}</span></td>
        <td><span style="color: var(--accent-cyan); font-weight: 600;">${inc.status}</span></td>
        <td>${inc.assigned_to || 'Unassigned'}</td>
        <td>${inc.risk_score}</td>
        <td>
          <button class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="viewIncidentDetail(${inc.id})">Investigate</button>
        </td>
      </tr>
    `;
  }).join("");
}

async function viewIncidentDetail(id) {
  currentIncidentId = id;
  const res = await fetch(`/api/incidents/${id}`, { headers: getAuthHeaders() });
  if (!res.ok) return;
  const inc = await res.json();

  document.getElementById("incidentDetailPanel").style.display = "block";
  document.getElementById("incDetailTitle").textContent = `${inc.incident_code}: ${inc.title} (${inc.status})`;

  const list = document.getElementById("incTimelineList");
  list.innerHTML = inc.timeline.map(t => `
    <div class="timeline-item">
      <div class="timeline-dot"></div>
      <div style="font-size: 11px; color: var(--text-muted);">${new Date(t.timestamp).toLocaleString()} by <strong>${t.performed_by}</strong></div>
      <div style="font-weight: 600; margin-top: 2px;">${t.action}</div>
      <div style="color: var(--text-secondary); font-size: 12.5px; margin-top: 2px;">${t.notes || ''}</div>
    </div>
  `).join("");
}

async function executeIncidentPlaybook(actionType) {
  if (!currentIncidentId) return;
  const res = await fetch(`/api/incidents/${currentIncidentId}/respond`, {
    method: "POST",
    headers: getAuthHeaders(),
    body: JSON.stringify({
      action_type: actionType,
      target_entity: "185.220.101.5",
      reason: "Automated threat response playbook executed by SOC analyst"
    })
  });
  if (res.ok) {
    alert(`Playbook ${actionType} executed and verified in immutable audit logs!`);
    viewIncidentDetail(currentIncidentId);
    refreshDashboard();
  }
}

// 6. Interactive Attack Topology Canvas (FR-36)
async function loadAttackGraph() {
  const canvas = document.getElementById("attackCanvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  canvas.width = canvas.parentElement.clientWidth;
  canvas.height = canvas.parentElement.clientHeight;

  const res = await fetch("/api/analytics/attack-graph", { headers: getAuthHeaders() });
  if (!res.ok) return;
  const data = await res.json();

  drawAttackGraph(ctx, canvas.width, canvas.height, data.nodes, data.edges);
}

function drawAttackGraph(ctx, w, h, nodes, edges) {
  ctx.clearRect(0, 0, w, h);

  // Position nodes into 3 columns: Attackers (left), Firewall (center), Targets (right)
  const attackers = nodes.filter(n => n.type === "ATTACKER");
  const firewalls = nodes.filter(n => n.type === "FIREWALL");
  const targets = nodes.filter(n => n.type === "TARGET");

  const posMap = {};

  attackers.forEach((n, idx) => {
    posMap[n.id] = { x: 120, y: 70 + idx * ((h - 140) / Math.max(attackers.length - 1, 1)) };
  });

  firewalls.forEach((n, idx) => {
    posMap[n.id] = { x: w / 2, y: h / 2 };
  });

  targets.forEach((n, idx) => {
    posMap[n.id] = { x: w - 160, y: 70 + idx * ((h - 140) / Math.max(targets.length - 1, 1)) };
  });

  // Draw connecting edges with glow
  edges.forEach(e => {
    const p1 = posMap[e.source];
    const p2 = posMap[e.target];
    if (p1 && p2) {
      ctx.beginPath();
      ctx.moveTo(p1.x, p1.y);
      ctx.lineTo(p2.x, p2.y);
      ctx.strokeStyle = "rgba(0, 242, 254, 0.25)";
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Animated pulsating packet marker
      const t = (Date.now() % 2000) / 2000;
      const px = p1.x + (p2.x - p1.x) * t;
      const py = p1.y + (p2.y - p1.y) * t;
      ctx.beginPath();
      ctx.arc(px, py, 3, 0, Math.PI * 2);
      ctx.fillStyle = "#00f2fe";
      ctx.fill();
    }
  });

  // Draw Nodes
  nodes.forEach(n => {
    const pos = posMap[n.id];
    if (!pos) return;

    ctx.beginPath();
    if (n.type === "ATTACKER") {
      ctx.arc(pos.x, pos.y, 14, 0, Math.PI * 2);
      ctx.fillStyle = "rgba(244, 63, 94, 0.85)";
      ctx.fill();
      ctx.strokeStyle = "#f43f5e";
    } else if (n.type === "FIREWALL") {
      ctx.rect(pos.x - 18, pos.y - 18, 36, 36);
      ctx.fillStyle = "rgba(0, 242, 254, 0.85)";
      ctx.fill();
      ctx.strokeStyle = "#00f2fe";
    } else {
      ctx.arc(pos.x, pos.y, 14, 0, Math.PI * 2);
      ctx.fillStyle = "rgba(245, 158, 11, 0.85)";
      ctx.fill();
      ctx.strokeStyle = "#f59e0b";
    }
    ctx.lineWidth = 2;
    ctx.stroke();

    // Node Label
    ctx.font = "11px Inter, sans-serif";
    ctx.fillStyle = "#ffffff";
    ctx.textAlign = "center";
    ctx.fillText(n.label, pos.x, pos.y + 28);
  });
}

// 7. AI Security Copilot Chat (FR-37, FR-38)
async function sendChatMessage() {
  const input = document.getElementById("chatInput");
  const text = input.value.trim();
  if (!text) return;

  const msgContainer = document.getElementById("chatMessages");
  msgContainer.innerHTML += `<div class="chat-bubble user">${text}</div>`;
  input.value = "";
  msgContainer.scrollTop = msgContainer.scrollHeight;

  try {
    const res = await fetch("/api/assistant/ask", {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify({ query: text })
    });
    if (res.ok) {
      const data = await res.json();
      let formattedAnswer = data.answer.replace(/\n/g, "<br>");
      let recs = data.recommendations ? `<div style="margin-top: 8px; font-size: 12px; color: var(--accent-cyan);"><strong>Recommended Actions:</strong><ul style="margin-left: 16px;">${data.recommendations.map(r => `<li>${r}</li>`).join("")}</ul></div>` : '';

      msgContainer.innerHTML += `
        <div class="chat-bubble ai">
          ${formattedAnswer}
          ${recs}
        </div>
      `;
      msgContainer.scrollTop = msgContainer.scrollHeight;
    }
  } catch (e) {
    msgContainer.innerHTML += `<div class="chat-bubble ai" style="color: var(--danger);">Failed to query assistant.</div>`;
  }
}

// 8. MLOps Telemetry (FR-48, FR-49)
async function loadMLOpsHealth() {
  try {
    const res = await fetch("/api/mlops/health", { headers: getAuthHeaders() });
    if (!res.ok) return;
    const d = await res.json();

    document.getElementById("mlopsStatus").textContent = d.status;
    document.getElementById("mlopsStatus").style.color = d.status === "HEALTHY" ? "var(--success)" : "var(--warning)";
    document.getElementById("mlopsModelName").textContent = d.model_name;
    document.getElementById("mlopsLatency").textContent = d.average_latency_ms;
    document.getElementById("mlopsDrift").textContent = d.drift_score;
    document.getElementById("mlopsTotal").textContent = d.total_monitored_inferences.toLocaleString();
  } catch (e) {
    console.error("MLOps error:", e);
  }
}

// 9. Audit Trail (FR-42)
async function loadAuditLogs() {
  try {
    const res = await fetch("/api/admin/audit-logs?limit=25", { headers: getAuthHeaders() });
    if (!res.ok) return;
    const logs = await res.json();
    const tbody = document.getElementById("auditLogsBody");

    tbody.innerHTML = logs.map(l => `
      <tr>
        <td>${new Date(l.timestamp).toLocaleString()}</td>
        <td><strong>${l.username}</strong></td>
        <td><code>${l.action}</code></td>
        <td>${l.resource_type || '-'}</td>
        <td style="color: var(--text-secondary); font-size: 12px;">${l.details || ''}</td>
        <td><code>${l.ip_address}</code></td>
      </tr>
    `).join("");
  } catch (e) {
    console.error("Audit error:", e);
  }
}

// Live Attack Simulation Button (Simulates real-world attack against the platform)
async function triggerSimulatedAttack() {
  const attacks = [
    { source_ip: "185.220.101.5", destination_ip: "192.168.1.10", destination_port: 80, protocol: "TCP", packet_count: 500, bytes_sent: 85000, flags: "SYN" },
    { source_ip: "45.154.255.88", destination_ip: "192.168.1.20", destination_port: 22, protocol: "TCP", packet_count: 15, bytes_sent: 1200, flags: "FIN" },
    { source_ip: "194.26.29.112", destination_ip: "192.168.1.10", destination_port: 8080, protocol: "TCP", packet_count: 1, bytes_sent: 60, flags: "SYN" }
  ];

  const attack = attacks[Math.floor(Math.random() * attacks.length)];
  const res = await fetch("/api/ml/predict-intrusion", {
    method: "POST",
    headers: getAuthHeaders(),
    body: JSON.stringify(attack)
  });

  if (res.ok) {
    const d = await res.json();
    alert(`⚡ Simulated Attack Injected!\nAdversary: ${attack.source_ip}\nDetected Threat: ${d.threat_type}\nRisk Score: ${d.risk_score}/100 (${d.severity})`);
    refreshDashboard();
    loadAttackGraph();
  }
}
