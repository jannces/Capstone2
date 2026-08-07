/* WiFi Admin Guardian — dashboard client
   Real-time via Socket.IO; Chart.js visuals; WebAudio alerts. */
"use strict";

const CSRF = document.querySelector('meta[name="csrf-token"]').content;
const $ = (s) => document.querySelector(s);

let alarmEnabled = window.ALARM_DEFAULT === 1 || window.ALARM_DEFAULT === "1";

/* ── helpers ─────────────────────────────────────────────────────────── */
async function api(url, opts = {}) {
  opts.headers = Object.assign({ "X-CSRF-Token": CSRF,
    "Content-Type": "application/json" }, opts.headers || {});
  const r = await fetch(url, opts);
  if (r.status === 401) { location.href = "/login"; return null; }
  return r.json();
}
const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
  (c) => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));
const fmtDur = (s) => {
  s = Math.max(0, s|0);
  const h = (s/3600)|0, m = ((s%3600)/60)|0;
  return h ? `${h}h ${m}m` : m ? `${m}m ${s%60}s` : `${s}s`;
};
const debounce = (fn, ms) => { let t; return (...a) => {
  clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };

/* ── audio alerts (WebAudio, no files needed) ────────────────────────── */
let audioCtx = null;
function beep(freqs, dur, gainVal) {
  if (!alarmEnabled) return;
  try {
    audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
    freqs.forEach((f, i) => {
      const o = audioCtx.createOscillator(), g = audioCtx.createGain();
      o.type = "square"; o.frequency.value = f;
      g.gain.setValueAtTime(gainVal, audioCtx.currentTime + i * dur);
      g.gain.exponentialRampToValueAtTime(0.001,
        audioCtx.currentTime + (i + 1) * dur);
      o.connect(g).connect(audioCtx.destination);
      o.start(audioCtx.currentTime + i * dur);
      o.stop(audioCtx.currentTime + (i + 1) * dur);
    });
  } catch (e) { /* audio blocked until user interacts */ }
}
const alarmSound  = () => beep([880, 660, 880, 660, 880, 660], 0.22, 0.18); // critical
const notifySound = () => beep([620, 780], 0.15, 0.10);                     // medium/low

/* ── tabs ─────────────────────────────────────────────────────────────── */
const loaders = { devices: loadDevices, threats: loadThreats,
  logs: loadLogs, reports: loadReports, settings: loadSettings,
  overview: loadOverview };
function showTab(name) {
  document.querySelectorAll(".tab").forEach((t) =>
    t.classList.toggle("active", t.dataset.tab === name));
  document.querySelectorAll(".panel").forEach((p) =>
    p.classList.toggle("d-none", p.id !== "tab-" + name));
  (loaders[name] || (() => {}))();
}
document.querySelectorAll(".tab").forEach((t) =>
  t.addEventListener("click", () => showTab(t.dataset.tab)));
window.showTab = showTab;

/* ── charts ───────────────────────────────────────────────────────────── */
Chart.defaults.color = "#7d93ab";
Chart.defaults.borderColor = "#1e3048";
let chSeverity, chTimeline;

function initCharts() {
  chSeverity = new Chart($("#chartSeverity"), {
    type: "doughnut",
    data: { labels: ["Critical", "High", "Medium", "Low"],
      datasets: [{ data: [0, 0, 0, 0],
        backgroundColor: ["#ff5d5d", "#ff8d5d", "#ffb454", "#37e8a3"],
        borderColor: "#111e2e", borderWidth: 3 }] },
    options: { plugins: { legend: { position: "right" } }, cutout: "62%" }
  });
  chTimeline = new Chart($("#chartTimeline"), {
    type: "line",
    data: { labels: [], datasets: [{ label: "Threats/hour", data: [],
      borderColor: "#ff5d5d", backgroundColor: "rgba(255,93,93,.12)",
      fill: true, tension: .3, pointRadius: 3 }] },
    options: { scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
      plugins: { legend: { display: false } } }
  });
}

async function loadOverview() {
  const tl = await api("/api/threats/timeline");
  if (tl && chTimeline) {
    chTimeline.data.labels = tl.map((r) => r.hour.slice(11, 16));
    chTimeline.data.datasets[0].data = tl.map((r) => r.n);
    chTimeline.update();
  }
}

/* ── activity feed ────────────────────────────────────────────────────── */
function feed(icon, text) {
  const li = document.createElement("li");
  const t = new Date().toTimeString().slice(0, 8);
  li.innerHTML = `<span class="t">${t}</span><span>${icon} ${text}</span>`;
  const f = $("#activityFeed");
  f.prepend(li);
  while (f.children.length > 60) f.lastChild.remove();
}

/* ── devices ──────────────────────────────────────────────────────────── */
async function loadDevices() {
  const q = $("#devSearch").value, st = $("#devStatus").value;
  const data = await api(`/api/devices?q=${encodeURIComponent(q)}&status=${st}`);
  if (!data) return;
  $("#bDevices").textContent = data.length;
  $("#devBody").innerHTML = data.map((d) => `
    <tr>
      <td class="st-${d.status}"><span class="st-dot"></span>${d.status}</td>
      <td class="mono">${esc(d.ip)}${d.is_gateway ? ' <span class="tag tag-ok">gateway</span>' : ""}${d.is_self ? ' <span class="tag">this PC</span>' : ""}</td>
      <td class="mono">${esc(d.mac)}</td>
      <td>${esc(d.hostname) || "—"}</td>
      <td>${esc(d.vendor)}</td>
      <td class="mono">${esc(d.first_seen)}</td>
      <td class="mono">${esc(d.last_seen)}</td>
      <td class="mono">${fmtDur(d.online_secs)}</td>
    </tr>`).join("");
}
$("#devSearch").addEventListener("input", debounce(loadDevices, 250));
$("#devStatus").addEventListener("change", loadDevices);

async function clearDevices(scope) {
  const msg = scope === "all"
    ? "Remove ALL devices from the list? Devices still on the network will reappear as they send traffic."
    : "Remove all offline devices from the list? (Live devices are kept.)";
  if (!confirm(msg)) return;
  const r = await api("/api/devices/clear", { method: "POST",
    body: JSON.stringify({ scope, csrf_token: CSRF }) });
  if (r && r.ok) {
    feed("🗑️", `Cleared ${r.removed} ${scope} device(s)`);
    loadDevices();
  }
}
$("#clearOffline").addEventListener("click", () => clearDevices("offline"));
$("#clearAll").addEventListener("click", () => clearDevices("all"));

/* ── threats ──────────────────────────────────────────────────────────── */
async function loadThreats() {
  const p = new URLSearchParams({
    q: $("#thSearch").value, type: $("#thType").value,
    severity: $("#thSeverity").value, status: $("#thStatus").value,
    date_from: $("#thFrom").value, date_to: $("#thTo").value });
  const data = await api("/api/threats?" + p);
  if (!data) return;
  const active = data.filter((t) => t.status === "New").length;
  $("#bThreats").textContent = active || "";
  $("#threatList").innerHTML = data.length ? data.map(threatCard).join("")
    : '<div class="hint">No threats match the current filter. Quiet network — good sign.</div>';
}
function threatCard(t) {
  let ev = "";
  try { ev = Object.entries(JSON.parse(t.evidence || "{}"))
    .map(([k, v]) => `${esc(k)}: ${esc(JSON.stringify(v))}`).join(" · "); }
  catch (e) {}
  const btn = (st, lbl) =>
    `<button class="btn btn-sm btn-outline-light" onclick="setThreat('${t.id}','${st}')">${lbl}</button>`;
  return `<div class="threat-item sev-${t.severity}">
    <div class="threat-head">
      <span class="sev-pill ${t.severity}">${t.severity}</span>
      <strong>${esc(t.threat_type)}</strong>
      <span class="status-chip ${esc(t.status)}">${esc(t.status)}</span>
      <span class="threat-meta ms-auto mono">${esc(t.ts)} · #${esc(t.id)}</span>
    </div>
    <div class="threat-desc">${esc(t.description)}</div>
    <div class="threat-meta mono">src ${esc(t.src_ip)} ${esc(t.src_mac)}${t.dst_ip ? " → " + esc(t.dst_ip) : ""}</div>
    ${ev ? `<div class="threat-meta">evidence — ${ev}</div>` : ""}
    <div class="threat-meta">rule — ${esc(t.detection_rule)}</div>
    <div class="threat-mit"><i class="bi bi-wrench-adjustable"></i> ${esc(t.mitigation)}</div>
    <div class="threat-actions">
      ${t.status === "New" ? btn("Acknowledged", "Acknowledge") : ""}
      ${t.status !== "Resolved" ? btn("Resolved", "Mark resolved") : ""}
      ${t.status !== "False Positive" ? btn("False Positive", "False positive") : ""}
    </div>
  </div>`;
}
window.setThreat = async (id, status) => {
  await api(`/api/threats/${id}/status`, { method: "POST",
    body: JSON.stringify({ status, csrf_token: CSRF }) });
  loadThreats();
};
["thSearch"].forEach((id) => $("#" + id)
  .addEventListener("input", debounce(loadThreats, 250)));
["thType", "thSeverity", "thStatus", "thFrom", "thTo"].forEach((id) =>
  $("#" + id).addEventListener("change", loadThreats));

/* ── logs ─────────────────────────────────────────────────────────────── */
async function loadLogs() {
  const kind = $("#logKind").value, q = $("#logSearch").value;
  if (kind === "connection") {
    $("#logHead").innerHTML =
      "<tr><th>Time</th><th>Event</th><th>IP</th><th>MAC</th><th>Hostname</th><th>Vendor</th></tr>";
    const data = await api("/api/logs/connection?q=" + encodeURIComponent(q));
    $("#logBody").innerHTML = (data || []).map((r) => `<tr>
      <td class="mono">${esc(r.ts)}</td>
      <td class="${r.event === "disconnected" ? "st-offline" : "st-online"}">${esc(r.event)}</td>
      <td class="mono">${esc(r.ip)}</td><td class="mono">${esc(r.mac)}</td>
      <td>${esc(r.hostname) || "—"}</td><td>${esc(r.vendor)}</td></tr>`).join("");
  } else {
    $("#logHead").innerHTML =
      "<tr><th>Time</th><th>User</th><th>Action</th><th>Detail</th><th>IP</th></tr>";
    const data = await api("/api/logs/admin");
    $("#logBody").innerHTML = (data || []).map((r) => `<tr>
      <td class="mono">${esc(r.ts)}</td><td>${esc(r.username)}</td>
      <td>${esc(r.action)}</td><td>${esc(r.detail)}</td>
      <td class="mono">${esc(r.ip)}</td></tr>`).join("");
  }
}
$("#logKind").addEventListener("change", loadLogs);
$("#logSearch").addEventListener("input", debounce(loadLogs, 250));

/* ── reports ──────────────────────────────────────────────────────────── */
async function loadReports() {
  const data = await api("/api/reports/history");
  $("#repBody").innerHTML = (data || []).map((r) => `<tr>
    <td class="mono">${esc(r.ts)}</td><td>${esc(r.report_type)}</td>
    <td>${esc(r.fmt).toUpperCase()}</td><td class="mono">${esc(r.filename)}</td>
    <td>${esc(r.created_by)}</td></tr>`).join("");
}

/* ── settings ─────────────────────────────────────────────────────────── */
async function loadSettings() {
  const s = await api("/api/settings");
  if (!s) return;
  $("#setAlarm").checked = s.alarm_enabled === "1";
  $("#setProbe").value = s.probe_interval || 3;
  $("#setMiss").value = s.offline_miss_threshold || 2;
  const m = await api("/api/metrics");
  if (m) $("#metricsBox").innerHTML = `
    <dt>Total threats detected</dt><dd>${m.total_threats}</dd>
    <dt>Marked false positive</dt><dd>${m.false_positives}</dd>
    <dt>False-positive rate</dt><dd>${m.false_positive_rate}%</dd>
    <dt>Avg detection latency</dt><dd>${m.avg_detect_latency_ms} ms</dd>
    <dt>Max detection latency</dt><dd>${m.max_detect_latency_ms} ms</dd>`;
}
$("#saveSettings").addEventListener("click", async () => {
  await api("/api/settings", { method: "POST", body: JSON.stringify({
    csrf_token: CSRF,
    alarm_enabled: $("#setAlarm").checked ? "1" : "0",
    probe_interval: $("#setProbe").value,
    offline_miss_threshold: $("#setMiss").value,
    scan_active: $("#setScan").checked }) });
  alarmEnabled = $("#setAlarm").checked;
  syncAlarmIcon();
  feed("⚙️", "Settings saved");
});

/* alarm quick-toggle in topbar */
function syncAlarmIcon() {
  $("#alarmIcon").className = alarmEnabled ? "bi bi-volume-up" : "bi bi-volume-mute";
}
$("#alarmToggle").addEventListener("click", async () => {
  alarmEnabled = !alarmEnabled;
  syncAlarmIcon();
  await api("/api/settings", { method: "POST", body: JSON.stringify(
    { csrf_token: CSRF, alarm_enabled: alarmEnabled ? "1" : "0" }) });
});

/* ── threat popup ─────────────────────────────────────────────────────── */
let popupTimer;
function showPopup(t) {
  $("#tpTitle").textContent = `${t.severity} — ${t.threat_type}`;
  $("#tpBody").textContent = t.description;
  $("#threatPopup").classList.remove("d-none");
  clearTimeout(popupTimer);
  popupTimer = setTimeout(hidePopup, 12000);
}
window.hidePopup = () => $("#threatPopup").classList.add("d-none");

/* ── Socket.IO real-time ──────────────────────────────────────────────── */
const socket = io();

socket.on("heartbeat", (h) => {
  $("#cDevices").textContent = h.devices.online;
  $("#cDevicesSub").textContent =
    `${h.devices.total} total · ${h.devices.offline} offline`;
  $("#cCritical").textContent = h.severity.Critical;
  $("#cMedium").textContent = h.severity.Medium + h.severity.High;
  $("#cPackets").textContent = h.packets.packets_analyzed.toLocaleString();
  $("#pktCounter").textContent = h.packets.packets_analyzed.toLocaleString();
  $("#pktBreakdown").textContent =
    `ARP ${h.packets.arp_packets} · TCP ${h.packets.tcp_packets} · ` +
    `DHCP ${h.packets.dhcp_packets} · mDNS ${h.packets.mdns_packets}`;
  $("#serverClock").textContent = h.server_time;
  $("#scanDot").classList.toggle("paused", !h.scan_active);
  $("#monitorTag").innerHTML = h.scan_active
    ? '<i class="bi bi-broadcast"></i> monitoring'
    : '<i class="bi bi-pause-circle"></i> paused';
  $("#monitorTag").className = h.scan_active ? "tag tag-ok" : "tag tag-warn";
});

socket.on("device_update", (d) => {
  feed(d.status === "online" ? "🟢" : "⚪",
    `${esc(d.ip)} (${esc(d.vendor)}) is ${d.status}`);
  if (!$("#tab-devices").classList.contains("d-none")) loadDevices();
});

socket.on("connection_event", (e) => {
  if (e.event === "disconnected") notifySound();
  if (!$("#tab-logs").classList.contains("d-none")) loadLogs();
});

socket.on("new_threat", (t) => {
  feed("🚨", `<strong>${esc(t.severity)}</strong> ${esc(t.threat_type)}: ${esc(t.description)}`);
  showPopup(t);
  if (t.severity === "Critical" || t.severity === "High") alarmSound();
  else notifySound();
  if (chSeverity) {
    const i = { Critical: 0, High: 1, Medium: 2, Low: 3 }[t.severity];
    chSeverity.data.datasets[0].data[i]++;
    chSeverity.update();
  }
  document.querySelector(".card-g.sev-critical").classList.add("flash");
  setTimeout(() => document.querySelector(".card-g.sev-critical")
    .classList.remove("flash"), 900);
  if (!$("#tab-threats").classList.contains("d-none")) loadThreats();
  loadOverview();
});

socket.on("threat_status", () => {
  if (!$("#tab-threats").classList.contains("d-none")) loadThreats();
});

/* ── boot ─────────────────────────────────────────────────────────────── */
initCharts();
(async () => {
  const s = await api("/api/summary");
  if (s && chSeverity) {
    chSeverity.data.datasets[0].data = ["Critical", "High", "Medium", "Low"]
      .map((k) => s.severity[k]);
    chSeverity.update();
  }
  loadOverview();
  syncAlarmIcon();
  if (location.hash === "#settings") showTab("settings");
})();
