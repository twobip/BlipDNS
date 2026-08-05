/* ============================================================
   BlipDNS Controller — SPA front-end
   Wired to the blipc control-plane API.
   ============================================================ */

/* ---------- API client (session-cookie auth) ---------- */
// Static assets are public; all /api/* calls carry the HttpOnly session cookie
// automatically (same-origin). A 401 means the session expired/lost — bounce to
// the login page.
const API = (path, opts = {}) =>
  fetch(path, opts).then((r) => {
    if (r.status === 401 && !location.pathname.startsWith("/login")) {
      location.href = "/login";
      throw new Error("session expired");
    }
    if (!r.ok) return r.text().then((t) => { throw new Error((t || r.statusText) || (r.status + " " + r.statusText)); });
    return r;
  });

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
const fmt = (n) => (n ?? 0).toLocaleString();
const timeAgo = (t) => {
  if (!t) return "—";
  const s = (Date.now() - new Date(t).getTime()) / 1000;
  if (s < 60) return Math.max(0, Math.round(s)) + "s ago";
  if (s < 3600) return Math.round(s / 60) + "m ago";
  if (s < 86400) return Math.round(s / 3600) + "h ago";
  return Math.round(s / 86400) + "d ago";
};
const relTime = (t) => (t ? new Date(t).toLocaleString() : "—");

/* ---------- icons ---------- */
const IC = {
  dash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg>',
  inst: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/></svg>',
  query: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>',
  block: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z"/><path d="m4.9 4.9 14.2 14.2"/></svg>',
  set: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3"/><path d="M1 14h6M9 8h6M17 16h6"/></svg>',
  sun: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
  copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
  edit: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.8 2.8 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/></svg>',
  trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/></svg>',
  shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
  check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>',
  warn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.8 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.8a2 2 0 0 0-3.4 0z"/><path d="M12 9v4m0 4h.01"/></svg>',
  arrow: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14m-6-6 6 6-6 6"/></svg>',
  globe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.8 5.7 3.8 9S14.5 18.4 12 21c-2.5-2.6-3.8-5.7-3.8-9S9.5 5.6 12 3z"/></svg>',
  device: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="4" width="20" height="13" rx="2"/><path d="M8 21h8M12 17v4"/></svg>',
};

/* ---------- routing ---------- */
const NAV = [
  { id: "dashboard", label: "Dashboard", icon: IC.dash, group: "Overview" },
  { id: "queries", label: "Query Log", icon: IC.query, group: "Overview" },
  { id: "instances", label: "Instances", icon: IC.inst, group: "DNS" },
  { id: "blocklist", label: "Rules & Blocklist", icon: IC.block, group: "DNS" },
  { id: "settings", label: "Settings", icon: IC.set, group: "System" },
];
const TITLES = {
  dashboard: ["Dashboard", "Fleet throughput &amp; health"],
  queries: ["Query Log", "Live DNS resolution history"],
  instances: ["Instances", "Managed blipd resolvers"],
  blocklist: ["Rules &amp; Blocklist", "Global domains and per-instance policies"],
  settings: ["Settings", "Upstreams and controller configuration"],
};
let current = "dashboard";

function renderNav() {
  const nav = $("nav");
  nav.innerHTML = "";
  let lastGrp = "";
  for (const item of NAV) {
    if (item.group !== lastGrp) {
      lastGrp = item.group;
      nav.insertAdjacentHTML("beforeend", `<div class="nav-group">${item.group}</div>`);
    }
    const a = document.createElement("a");
    a.className = "nav-item" + (item.id === current ? " active" : "");
    a.dataset.nav = item.id;
    a.href = "/" + item.id;
    a.innerHTML = `<span class="nav-icon">${item.icon}</span><span>${item.label}</span>`;
    a.addEventListener("click", (e) => { e.preventDefault(); go(item.id); });
    nav.appendChild(a);
  }
}

function go(page, push = true) {
  current = page;
  document.querySelectorAll(".nav-item").forEach((a) => a.classList.toggle("active", a.dataset.nav === page));
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("hidden", v.id !== "view-" + page));
  if (push) {
    history.pushState({ page }, "", "/" + page);
  }
  const t = TITLES[page] || ["", ""];
  $("page-title").innerHTML = t[0];
  $("page-sub").textContent = t[1];
  refresh();
  if (page === "instances") renderEvents();
  if (page === "settings") refreshSettings();
  if (page === "blocklist") loadBlocklist();
}

/* ---------- toast ---------- */
function toast(msg, kind = "ok") {
  const box = $("toasts");
  const el = document.createElement("div");
  el.className = "toast " + kind;
  const ic = kind === "err" ? IC.warn : kind === "info" ? IC.shield : IC.check;
  el.innerHTML = `${ic}<span>${esc(msg)}</span>`;
  box.appendChild(el);
  setTimeout(() => { el.classList.add("hide"); setTimeout(() => el.remove(), 200); }, 3200);
}

/* ---------- state ---------- */
let instances = [];
let blDomains = [];
let chart = null;
let chartRange = "24h";
let sse = null, evLive = false;
let pollTimer = null;

/* ---------- data refresh ---------- */
async function refresh() {
  try {
    const res = await API("/api/instances");
    instances = await res.json();
    updateConn();
    if (current === "dashboard") renderDashboard();
    else if (current === "instances") renderInstances();
    else if (current === "queries") renderQueries();
    else if (current === "blocklist") renderPolicies();
  } catch (e) {
    const c = $("conn");
    if (c) { c.textContent = "offline"; c.className = "badge err"; }
  }
}

function updateConn() {
  const on = instances.filter((i) => i.online).length;
  const c = $("conn");
  if (c) {
    c.textContent = on + "/" + instances.length + " online";
    c.className = "badge " + (on === instances.length && instances.length ? "on" : on > 0 ? "warn" : "off");
  }
  const dot = $("fleet-dot"), st = $("fleet-status");
  if (dot) dot.className = "dot " + (instances.length && on === instances.length ? "on" : on > 0 ? "warn" : instances.length ? "err" : "off");
  if (st) st.textContent = on + "/" + instances.length + " online";
}

/* ---------- dashboard ---------- */
async function renderDashboard() {
  let tq = 0, tb = 0, te = 0, on = 0;
  for (const i of instances) { if (i.online) on++; const s = i.stats || {}; tq += s.queries_total ?? 0; tb += s.blocked_total ?? 0; te += s.upstream_errors ?? 0; }
  $("d-queries").textContent = fmt(tq);
  $("d-blocked").textContent = fmt(tb);
  $("d-errors").textContent = fmt(te);
  $("d-online").textContent = on;
  $("d-total").textContent = instances.length;
  $("d-blockrate").textContent = tq ? (tb / tq * 100).toFixed(1) + "%" : "0%";
  renderDashInstances();
  if (on === 0) { /* still try chart from global stats */ }
  fetchChart();
}

function renderDashInstances() {
  const el = $("d-instances");
  const list = instances.slice().sort((a, b) => (a.id || "").localeCompare(b.id || ""));
  if (!list.length) {
    el.innerHTML = `<div class="empty"><div class="empty-ic">${IC.inst}</div><h4>No instances yet</h4><p>Add your first blipd resolver to start filtering traffic.</p><button class="btn btn-primary" id="d-empty-add">+ Add Instance</button></div>`;
    $("d-empty-add").onclick = () => openInstanceModal();
    return;
  }
  el.innerHTML = list.map((i) => {
    const s = i.stats || {};
    const rate = s.queries_total ? (s.blocked_total / s.queries_total * 100).toFixed(0) : 0;
    return `<div class="row" style="padding:12px 20px; border-bottom:1px solid var(--hairline)">
      <span class="dot ${i.online ? "on" : "off"}"></span>
      <div class="grow" style="min-width:0">
        <div style="font-weight:550">${esc(i.label || i.id)}</div>
        <div class="cell-sub mono" style="overflow:hidden;text-overflow:ellipsis">${esc(i.url || "")}</div>
      </div>
      <div class="num" style="text-align:right">
        <div style="font-variant-numeric:tabular-nums;font-weight:600">${fmt(s.queries_total ?? 0)}</div>
        <div class="cell-sub"><span class="meter"><i style="width:${Math.min(100, rate)}%"></i></span> ${rate}% blk</div>
      </div>
    </div>`;
  }).join("");
}

/* ---------- chart ---------- */
async function fetchChart() {
  const ctx = $("chart-queries");
  if (!ctx) return;
  const since = { "1h": "1h", "6h": "6h", "24h": "24h", "168h": "168h" }[chartRange] || "24h";
  const bucket = chartRange === "168h" ? "1h" : chartRange === "24h" ? "5m" : chartRange === "6h" ? "1m" : "10s";
  try {
    const res = await API(`/api/stats?bucket=${bucket}&since=${since}`);
    const stats = await res.json();
    if (!stats || !stats.length) return;
    const labels = stats.map((s) => new Date(s.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }));
    const tq = stats.map((s) => s.total_queries);
    const bq = stats.map((s) => s.blocked_queries);
    if (!chart) {
      Chart.defaults.color = "#7a8291";
      Chart.defaults.borderColor = "rgba(255,255,255,.06)";
      chart = new Chart(ctx.getContext("2d"), {
        type: "line",
        data: {
          labels,
          datasets: [
            { label: "Total", data: tq, borderColor: "#4f8cff", backgroundColor: cgrad(ctx, "79,140,255"), fill: true, tension: .35, pointRadius: 0, borderWidth: 2 },
            { label: "Blocked", data: bq, borderColor: "#f76b6b", backgroundColor: cgrad(ctx, "247,107,107"), fill: true, tension: .35, pointRadius: 0, borderWidth: 2 },
          ],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          interaction: { mode: "index", intersect: false },
          animation: { duration: 300 },
          plugins: { legend: { labels: { boxWidth: 10, boxHeight: 10, usePointStyle: true, padding: 18 } }, tooltip: { backgroundColor: "#181b22", borderColor: "rgba(255,255,255,.1)", borderWidth: 1, titleColor: "#e7eaf0", bodyColor: "#a6adbb", padding: 12 } },
          scales: {
            x: { grid: { color: "rgba(255,255,255,.04)" }, ticks: { maxTicksLimit: 8, maxRotation: 0 } },
            y: { beginAtZero: true, grid: { color: "rgba(255,255,255,.04)" }, ticks: { precision: 0 } },
          },
        },
      });
    } else {
      chart.data.labels = labels;
      chart.data.datasets[0].data = tq;
      chart.data.datasets[1].data = bq;
      chart.update("none");
    }
  } catch (e) { /* chart is best-effort */ }
}
function cgrad(ctx, rgb) {
  const g = ctx.createLinearGradient(0, 0, 0, 300);
  g.addColorStop(0, `rgba(${rgb},.18)`);
  g.addColorStop(1, `rgba(${rgb},0)`);
  return g;
}

/* ---------- live events (SSE) ---------- */
function connectSSE() {
  if (sse) return;
  try {
    const src = new EventSource("/api/events");
    sse = src;
    src.onopen = () => { $("ev-live").className = "badge on"; };
    src.onmessage = (m) => {
      let e; try { e = JSON.parse(m.data); } catch { return; }
      pushEvent(e);
    };
    src.onerror = () => { $("ev-live").textContent = "reconnecting"; $("ev-live").className = "badge warn"; };
  } catch { /* ignore */ }
}

let eventBuffer = [];
function pushEvent(e) {
  eventBuffer.unshift(e);
  eventBuffer = eventBuffer.slice(0, 60);
  if (current === "instances") renderEvents();
}
function renderEvents() {
  const el = $("d-events");
  if (!eventBuffer.length) {
    el.innerHTML = `<div class="empty"><div class="empty-ic">${IC.dash}</div><h4>Waiting for traffic</h4><p>Block / pass events will stream here live.</p></div>`;
    return;
  }
  el.innerHTML = eventBuffer.map((e) => {
    const kind = e.type === "block" ? { b: 'badge err', ic: IC.block } : e.type === "pass" ? { b: 'badge on', ic: IC.query } : { b: "badge accent", ic: IC.shield };
    return `<li><span class="t">${new Date(e.at).toLocaleTimeString()}</span>
      <span class="badge ${kind.b}">${e.type}</span>
      <div class="grow" style="min-width:0">
        <div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--mono)">${esc(e.domain || e.msg || e.type)}</div>
        <div class="cell-sub">${esc(e.instance || e.instance_id || "")}${e.client ? " · " + esc(e.client) : ""}</div>
      </div></li>`;
  }).join("");
}

/* ---------- instances ---------- */
function renderInstances() {
  const tb = $("inst-tbody");
  const f = ($("inst-filter")?.value || "").toLowerCase();
  const list = instances.filter((i) => !f || (i.id + " " + (i.label || "") + " " + (i.url || "")).toLowerCase().includes(f));
  $("inst-count").textContent = list.length + " of " + instances.length;
  if (!list.length) {
    tb.innerHTML = instances.length
      ? `<tr class="empty-row"><td colspan="8"><div class="empty"><div class="empty-ic">${IC.query}</div><h4>No matching instances</h4><p>Try a different filter.</p></div></td></tr>`
      : `<tr class="empty-row"><td colspan="8"><div class="empty"><div class="empty-ic">${IC.inst}</div><h4>No instances yet</h4><p>Add your first blipd resolver to get started.</p><button class="btn btn-primary" id="inst-empty-add">+ Add Instance</button></div></td></tr>`;
    const b = $("inst-empty-add"); if (b) b.onclick = openInstanceModal;
    return;
  }
  tb.innerHTML = list.map((i) => {
    const s = i.stats || {};
    const ping = i.ping_avg_ms ? i.ping_avg_ms.toFixed(0) + "ms" : "—";
    return `<tr>
      <td>
        <div class="cell-main"><span class="dot ${i.online ? "on" : "off"}"></span>${esc(i.label || i.id)}</div>
        <div class="cell-sub mono">${esc(i.id)}</div>
      </td>
      <td><span class="status-pill ${i.online ? "on" : "off"}">${i.online ? "online" : "offline"}</span></td>
      <td class="num">${fmt(s.queries_total ?? 0)}</td>
      <td class="num"><span style="color:${s.blocked_total ? "var(--red)" : "inherit"}">${fmt(s.blocked_total ?? 0)}</span></td>
      <td class="num">${fmt(s.cached ?? 0)}</td>
      <td class="num mono">${ping}</td>
      <td><span class="badge ${i.adopted ? "on" : "off"}">${i.adopted ? "adopted" : "pending"}</span></td>
      <td>
        <div class="row-actions">
          <button class="icon-btn" data-act="policies" data-id="${esc(i.id)}" title="Policies">${IC.shield}</button>
          <button class="icon-btn" data-act="edit" data-id="${esc(i.id)}" title="Edit label">${IC.edit}</button>
          <button class="icon-btn" data-act="remove" data-id="${esc(i.id)}" title="Remove">${IC.trash}</button>
        </div>
      </td>
    </tr>`;
  }).join("");
}

function openInstanceModal() { $("inst-modal-title").textContent = "Add Instance"; $("i-save").textContent = "Add Instance"; $("i-save").dataset.mode = "add"; ["i-id","i-label","i-url","i-token","i-claim"].forEach((x) => $(x).value = ""); show("modal-instance"); }

async function saveInstance() {
  const body = { id: $("i-id").value.trim(), label: $("i-label").value.trim(), url: $("i-url").value.trim(), token: $("i-token").value, claim: $("i-claim").value.trim() };
  if (!body.id || !body.url) return toast("id and url are required", "err");
  try {
    await API("/api/instances", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    hide("modal-instance");
    toast("instance added");
    if (body.claim) {
      try { await API("/api/instances/" + encodeURIComponent(body.id) + "/adopt", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code: body.claim }) }); toast("adopted " + body.id); }
      catch (e) { toast("adoption failed: " + e.message, "err"); }
    }
    refresh();
  } catch (e) { toast("add failed: " + e.message, "err"); }
}

async function editLabel(id) {
  const i = instances.find((x) => x.id === id); if (!i) return;
  const label = prompt("Label for " + id + ":", i.label || i.id);
  if (label == null || !label.trim()) return;
  try {
    await API("/api/instances/" + encodeURIComponent(id) + "/label", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ label: label.trim() }) });
    toast("label updated"); refresh();
  } catch (e) { toast("failed: " + e.message, "err"); }
}

function confirmRemove(id) {
  confirmDialog(`Remove instance <b>${esc(id)}</b>?`, "This removes it from the fleet. Its blipd process is not stopped.", async () => {
    try { await API("/api/instances/" + encodeURIComponent(id), { method: "DELETE" }); toast("removed " + id); refresh(); }
    catch (e) { toast("remove failed: " + e.message, "err"); }
  });
}

/* ---------- queries ---------- */
let qState = { action: "", filter: "", inst: "" };
async function renderQueries() {
  const tb = $("q-tbody");
  const sinceQ = "&since=24h&limit=300";
  try {
    const res = await API("/api/queries?instance=" + encodeURIComponent(qState.inst) + sinceQ);
    const rows = await res.json();
    const list = rows.filter((r) => {
      if (!r.domain) return false;
      if (qState.filter && !(r.domain + " " + r.client + " " + r.instance).toLowerCase().includes(qState.filter.toLowerCase())) return false;
      if (qState.action && (r.action || "").toUpperCase() !== qState.action) return false;
      return true;
    });
    propsInstanceOptions();
    $("q-count").textContent = list.length + " entries (shown)";
    if (!list.length) {
      tb.innerHTML = `<tr class="empty-row"><td colspan="6"><div class="empty"><div class="empty-ic">${IC.query}</div><h4>No queries</h4><p>Nothing matched in the last 24 hours.</p></div></td></tr>`;
      return;
    }
    tb.innerHTML = list.map((r) => {
      const action = (r.action || "").toUpperCase();
      const isBlock = action === "BLOCK";
      const inst = instances.find((i) => (i.label || i.id) === r.instance);
      const actionLabel = isBlock ? "Blocked" : action === "PASS" ? "Allowed" : esc(action || "—");
      const actionBadge = isBlock ? "err" : action === "PASS" ? "on" : "";
      return `<tr class="${isBlock ? "q-row-block" : ""}">
        <td class="q-time"><span class="t" data-t="${esc(r.timestamp)}" title="${esc(r.timestamp)}">…</span></td>
        <td class="q-domain">
          <span class="q-globe">${IC.globe}</span>
          <span class="mono q-dom" title="${esc(r.domain)}">${esc(r.domain)}</span>
          <button class="icon-btn q-copy" data-copy="${esc(r.domain)}" title="Copy domain">${IC.copy}</button>
        </td>
        <td><span class="badge badge-action ${actionBadge}">${isBlock ? IC.block : action === "PASS" ? IC.arrow : ""}${actionLabel}</span></td>
        <td class="q-client"><span class="q-cicon">${IC.device}</span><span class="mono" title="${esc(r.client)}">${esc(r.client)}</span></td>
        <td class="q-ips">${ipsHtml(r.ips)}</td>
        <td class="q-inst"><span class="dot ${inst && inst.online ? "on" : "off"}"></span>${esc(inst ? (inst.label || inst.id) : r.instance)}</td>
      </tr>`;
    }).join("");
    tb.querySelectorAll(".t").forEach((t) => { t.textContent = timeAgo(t.dataset.t); });
  } catch (e) {
    tb.innerHTML = `<tr class="empty-row"><td colspan="6"><div class="empty"><div class="empty-ic">${IC.warn}</div><h4>Query log unavailable</h4><p>${esc(e.message)}</p></div></td></tr>`;
  }
}
function propsInstanceOptions() {
  const sel = $("q-instance");
  const cur = sel.value;
  const labels = [...new Set(instances.map((i) => i.label || i.id || ""))].filter(Boolean);
  sel.innerHTML = `<option value="">All instances</option>` + labels.map((l) => `<option value="${esc(l)}" ${l === cur ? "selected" : ""}>${esc(l)}</option>`).join("");
}

function ipsHtml(ips) {
  const list = ips || [];
  if (!list.length) return `<span class="q-ips-empty">—</span>`;
  const shown = list.slice(0, 2);
  const extra = list.length - shown.length;
  return shown.map((ip) => `<span class="q-chip" data-copy="${esc(ip)}" title="Copy ${esc(ip)}">${esc(ip)}</span>`).join("") +
    (extra > 0 ? `<span class="q-chip-more" title="${esc(list.join(", "))}">+${extra}</span>` : "");
}

async function copyText(s) {
  try {
    if (navigator.clipboard?.writeText) { await navigator.clipboard.writeText(s); }
    else {
      const ta = document.createElement("textarea");
      ta.value = s; ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      document.execCommand("copy"); ta.remove();
    }
    toast("copied " + s);
  } catch { toast("copy failed", "err"); }
}

/* ---------- blocklist ---------- */
let polCache = {};
async function loadBlocklist() {
  try { const r = await API("/api/blocklist"); const d = await r.json(); blDomains = d.domains || []; renderBlocklist(); } catch (e) {}
}
function renderBlocklist() {
  const f = ($("bl-filter")?.value || "").toLowerCase();
  const list = blDomains.filter((d) => !f || d.includes(f));
  $("bl-count").textContent = blDomains.length;
  const ul = $("bl-list");
  if (!list.length) {
    ul.innerHTML = `<div class="empty"><div class="empty-ic">${IC.block}</div><h4>Nothing blocked</h4><p>Add a domain or import a list like oisd.nl.</p></div>`;
    return;
  }
  ul.innerHTML = list.map((d) => `<li><span class="mono grow">${esc(d)}</span><button class="icon-btn" data-rm="${esc(d)}" title="Remove">${IC.trash}</button></li>`).join("");
  ul.querySelectorAll("[data-rm]").forEach((b) => b.onclick = async () => {
    try { await API("/api/blocklist", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: b.dataset.rm }) }); toast("removed " + b.dataset.rm); loadBlocklist(); }
    catch (e) { toast("remove failed", "err"); }
  });
}

async function renderPolicies() {
  const tb = $("pol-tbody");
  if (!instances.length) {
    tb.innerHTML = `<tr class="empty-row"><td colspan="3"><div class="empty"><div class="empty-ic">${IC.block}</div><h4>No instances to scope policies</h4><p>Policies filter DNS per-network on a blipd instance.</p></div></td></tr>`;
    return;
  }
  tb.innerHTML = instances.map((i) => `<tr>
    <td><span class="dot ${i.online?"on":"off"}"></span> ${esc(i.label || i.id)}</td>
    <td class="cell-sub" id="pol-sum-${esc(i.id)}">—</td>
    <td style="text-align:right"><button class="btn btn-sm btn-ghost" data-policies="${esc(i.id)}">${IC.shield} Manage</button></td>
  </tr>`).join("");
  tb.querySelectorAll("[data-policies]").forEach((b) => b.onclick = () => openPolicyModal(b.dataset.policies));
  // fetch summaries async
  for (const i of instances) {
    try {
      const r = await API("/api/instances/" + encodeURIComponent(i.id) + "/policies");
      const d = await r.json();
      polCache[i.id] = d;
      const el = $("pol-sum-" + i.id);
      if (el) {
        const ids = [ ...(d.default && d.default.id ? [`<span class="tag">${esc(d.default.id)}*</span>`] : []), ...(d.policies||[]).map((p) => `<span class="tag">${esc(p.id)}</span>`) ];
        el.innerHTML = ids.length ? `<span class="pill-list">${ids.join("")}</span>` : "default only";
      }
    } catch {}
  }
}

let polInstance = null, polEditing = null;
async function openPolicyModal(id) {
  polInstance = id; polEditing = null;
  $("pol-inst").textContent = id;
  $("pol-list").classList.remove("hidden");
  $("pol-edit").classList.add("hidden");
  $("p-save").classList.add("hidden");
  $("pol-back").style.display = "none";
  $("pol-new").style.display = "";
  const tb = $("pol-list-tbody");
  let d = polCache[id];
  if (!d) { try { const r = await API("/api/instances/" + encodeURIComponent(id) + "/policies"); d = await r.json(); polCache[id] = d; } catch (e) {} }
  d = d || { default: {}, policies: [] };
  const rows = [...(d.default && d.default.id ? [d.default] : []), ...(d.policies || [])];
  tb.innerHTML = rows.length ? rows.map((p) => `<tr>
    <td style="font-weight:600">${esc(p.id)}${d.default && p.id === d.default.id ? ' <span class="badge accent">default</span>' : ""}</td>
    <td class="mono" style="font-size:12px">${esc((p.networks||[]).join(", ") || "all")}</td>
    <td class="mono" style="font-size:12px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc((p.block||[]).slice(0,3).join(", "))}${(p.block||[]).length>3?"…":""}</td>
    <td><span class="badge">${esc(p.block_action||"-")}</span></td>
    <td><button class="icon-btn" data-pedit="${esc(p.id)}" data-pdef="${d.default && p.id===d.default.id?1:0}" title="Edit">${IC.edit}</button></td>
  </tr>`).join("") : `<tr class="empty-row"><td colspan="5"><div class="empty"><div class="empty-ic">${IC.set}</div><h4>No policies</h4><p>Queries fall through to the instance default.</p></div></td></tr>`;
  tb.querySelectorAll("[data-pedit]").forEach((b) => b.onclick = () => editPolicy(id, b.dataset.pedit, b.dataset.pdef === "1"));
  show("modal-policy");
}

function newPolicy() {
  if (!polInstance) return;
  polEditing = null;
  $("pol-list").classList.add("hidden");
  $("pol-edit").classList.remove("hidden");
  $("p-save").classList.remove("hidden");
  $("pol-back").style.display = "";
  $("pol-new").style.display = "none";
  $("p-id").value = ""; $("p-networks").value = ""; $("p-block").value = ""; $("p-allow").value = ""; $("p-action").value = "nxdomain"; $("p-upstream").value = ""; $("p-log").checked = true;
}
function editPolicy(inst, pid, isDefault) {
  const d = polCache[inst]; if (!d) return;
  const p = isDefault ? d.default : (d.policies||[]).find((x) => x.id === pid);
  if (!p) return;
  newPolicy();
  if (isDefault) { $("p-id").value = ""; $("p-id").disabled = true; } else { $("p-id").value = p.id; $("p-id").disabled = false; }
  $("p-networks").value = (p.networks||[]).join(" ");
  $("p-block").value = (p.block||[]).join("\n");
  $("p-allow").value = (p.allow||[]).join("\n");
  $("p-action").value = p.block_action || "nxdomain";
  $("p-upstream").value = p.upstream || "";
  $("p-log").checked = p.log !== false;
  polEditing = pid;
  $("pol-back").onclick = () => { openPolicyModal(polInstance); };
  polEditDefault = !!isDefault;
}
let polEditDefault = false;
async function savePolicy() {
  if (!polInstance) return;
  const p = {
    id: polEditDefault ? (polCache[polInstance]?.default?.id || "default") : $("p-id").value.trim(),
    networks: ($("p-networks").value.match(/\S+/g) || []),
    block: $("p-block").value.split("\n").map((s) => s.trim()).filter(Boolean),
    allow: $("p-allow").value.split("\n").map((s) => s.trim()).filter(Boolean),
    block_action: $("p-action").value,
    log: $("p-log").checked,
    upstream: $("p-upstream").value.trim(),
  };
  if (!p.id) return toast("policy id required", "err");
  try {
    await API("/api/instances/" + encodeURIComponent(polInstance) + "/policy", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(p) });
    toast("policy saved"); delete polCache[polInstance]; openPolicyModal(polInstance); refresh();
  } catch (e) { toast("save failed: " + e.message, "err"); }
}

/* ---------- settings ---------- */
function parseUpstreamSpec(str) {
  return (String(str || "").match(/\S+/g) || []).map((tok, i) => {
    let spec = tok, prio = i + 1;
    if (tok.includes("|")) { const p = parseInt(tok.split("|")[1], 10); if (p > 0) prio = p; spec = tok.split("|")[0]; }
    let type = "udp", addr = spec;
    if (spec.startsWith("udp://")) addr = spec.slice(6);
    else if (spec.startsWith("https://")) { type = "doh"; addr = spec.slice(8); }
    else if (spec.startsWith("doh://")) { type = "doh"; addr = spec.slice(6); }
    return { type, addr, prio };
  });
}
function serializeUpstreams(rows) {
  const specs = [];
  for (const row of rows) {
    const addr = (row.addr || "").trim();
    if (!addr) continue;
    specs.push((row.type === "doh" ? "https://" : "udp://") + addr + "|" + (row.prio > 0 ? row.prio : 1));
  }
  return specs.join(" ");
}
function upstreamRow(u) {
  const row = document.createElement("div");
  row.className = "row up-row";
  const ph = u.type === "doh" ? "1.1.1.1/dns-query" : "1.1.1.1:53";
  row.innerHTML = `
    <select class="select up-type" style="width:104px">
      <option value="udp" ${u.type === "doh" ? "" : "selected"}>UDP</option>
      <option value="doh" ${u.type === "doh" ? "selected" : ""}>DoH / HTTPS</option>
    </select>
    <input class="input grow up-addr" placeholder="${ph}" value="${esc(u.addr)}"/>
    <input class="input up-prio" type="number" min="1" title="Priority — lower = higher priority" style="width:72px" value="${u.prio || ""}"/>
    <button class="icon-btn up-del" title="Remove">${IC.trash}</button>`;
  row.querySelector(".up-del").onclick = () => row.remove();
  return row;
}
function renderUpstreamList(list) {
  const wrap = $("s-upstream-list");
  wrap.innerHTML = "";
  for (const u of list) wrap.appendChild(upstreamRow(u));
  if (!list.length) wrap.innerHTML = `<div class="hint" style="padding:2px 0 6px">No upstreams configured — instances use their compiled default.</div>`;
}
function collectUpstreams() {
  return [...document.querySelectorAll("#s-upstream-list .up-row")].map((row) => ({
    type: row.querySelector(".up-type").value,
    addr: row.querySelector(".up-addr").value,
    prio: parseInt(row.querySelector(".up-prio").value, 10) || 0,
  }));
}
let savedDefaultPolicy = null; // current default policy from the online instance
async function refreshSettings() {
  $("s-ctrl-ver").textContent = "blipc";
  $("s-inst-count").textContent = instances.length + (instances.some((i) => i.online) ? " (" + instances.filter((i) => i.online).length + " online)" : "");
  // populate upstream from first online instance default policy
  try {
    const online = instances.find((i) => i.online);
    if (online) {
      const r = await API("/api/instances/" + encodeURIComponent(online.id) + "/policies");
      const d = await r.json();
      savedDefaultPolicy = d.default || { id: "default" };
      renderUpstreamList(parseUpstreamSpec(savedDefaultPolicy.upstream));
    }
  } catch {}
}

/* ---------- confirm dialog ---------- */
let _cfOk = null;
function confirmDialog(title, msg, onOk) {
  $("cf-title").textContent = title;
  $("cf-msg").innerHTML = msg;
  _cfOk = onOk;
  show("modal-confirm");
}
$("cf-ok").onclick = () => { hide("modal-confirm"); if (_cfOk) _cfOk(); };

/* ---------- modal helpers ---------- */
function show(id) { $(id).classList.remove("hidden"); }
function hide(id) { $(id).classList.add("hidden"); }
document.querySelectorAll("[data-close]").forEach((b) => b.onclick = () => hide(b.dataset.close));

/* ---------- wiring ---------- */
/* nav + global clicks */
renderNav();
renderEvents();

/* sidebar toggle */
$("sidebar-toggle").onclick = () => document.body.classList.toggle("sidebar-collapsed");

/* logout */
$("logout-btn").onclick = async () => {
  try { await fetch("/api/logout", { method: "POST" }); } catch (e) {}
  location.href = "/login";
};

/* initial route */
const initial = (location.pathname.replace(/\/+$/, "") || "/").replace(/^\//, "");
go(NAV.some((n) => n.id === initial) ? initial : "dashboard", false);

/* popstate */
window.addEventListener("popstate", () => {
  const p = (location.pathname.replace(/\/+$/, "") || "/").replace(/^\//, "");
  go(NAV.some((n) => n.id === p) ? p : "dashboard", false);
});

/* add instance */
$("add-instance-btn").onclick = openInstanceModal;
$("i-save").onclick = saveInstance;
$("inst-filter").addEventListener("input", renderInstances);

/* instance row actions (event delegation) */
$("inst-tbody").addEventListener("click", (e) => {
  const b = e.target.closest("[data-act]"); if (!b) return;
  const id = b.dataset.id;
  const act = b.dataset.act;
  if (act === "policies") openPolicyModal(id);
  else if (act === "edit") editLabel(id);
  else if (act === "remove") confirmRemove(id);
});

/* queries */
$("q-filter").addEventListener("input", (e) => { qState.filter = e.target.value; renderQueries(); });
$("q-instance").addEventListener("change", (e) => { qState.inst = e.target.value; renderQueries(); });
$("q-refresh").onclick = renderQueries;
$("q-tbody").addEventListener("click", (e) => {
  const c = e.target.closest("[data-copy]"); if (!c) return;
  copyText(c.dataset.copy);
});
document.querySelectorAll("#q-action-seg button").forEach((b) => b.onclick = () => {
  document.querySelectorAll("#q-action-seg button").forEach((x) => x.classList.remove("active"));
  b.classList.add("active");
  qState.action = b.dataset.a;
  renderQueries();
});

/* chart range */
document.querySelectorAll("#chart-range button").forEach((b) => b.onclick = () => {
  document.querySelectorAll("#chart-range button").forEach((x) => x.classList.remove("active"));
  b.classList.add("active");
  chartRange = b.dataset.r;
  fetchChart();
});

/* blocklist */
$("bl-add").onclick = async () => {
  const d = ($("bl-add-input").value || "").trim();
  if (!d) return toast("enter a domain", "err");
  try { await API("/api/blocklist", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: d }) }); toast("added " + d); $("bl-add-input").value = ""; loadBlocklist(); }
  catch (e) { toast("add failed: " + e.message, "err"); }
};
$("bl-add-input").addEventListener("keydown", (e) => { if (e.key === "Enter") $("bl-add").click(); });
$("bl-import-url").onclick = async () => {
  const u = ($("bl-url-input").value || "").trim();
  if (!u) return toast("URL required", "err");
  const st = $("bl-import-status"); st.textContent = "fetching…";
  try {
    const r = await API("/api/blocklist/import-url", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: u }) });
    const d = await r.json();
    st.innerHTML = `Loaded <b>${fmt(d.count)}</b> domains.`;
    toast("imported " + fmt(d.count) + " domains"); $("bl-url-input").value = ""; loadBlocklist();
  } catch (e) { st.textContent = "failed: " + e.message; toast("import failed: " + e.message, "err"); }
};
$("bl-url-input").addEventListener("keydown", (e) => { if (e.key === "Enter") $("bl-import-url").click(); });
$("bl-filter").addEventListener("input", renderBlocklist);
$("bl-export").onclick = () => window.open("/api/blocklist/export", "_blank");
$("bl-clear").onclick = () => {
  confirmDialog("Clear entire blocklist?", "This removes every blocked domain. This cannot be undone.", async () => {
    let n = 0;
    try {
      for (const d of blDomains) { await API("/api/blocklist", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: d }) }); n++; }
      toast("cleared " + n + " domains"); loadBlocklist();
    } catch (e) { toast("clear failed", "err"); }
  });
};

/* policies modal */
$("pol-new").onclick = newPolicy;
$("p-save").onclick = savePolicy;

/* settings */
$("s-up-add").onclick = () => {
  const prios = collectUpstreams().map((r) => r.prio).filter((p) => p > 0);
  $("s-upstream-list").appendChild(upstreamRow({ type: "udp", addr: "", prio: (prios.length ? Math.max(...prios) + 1 : 1) }));
};
$("s-save-upstream").onclick = async () => {
  const up = serializeUpstreams(collectUpstreams());
  const online = instances.find((i) => i.online);
  if (!online) return toast("no online instance to configure", "err");
  const body = { id: "default", networks: [], block: [], allow: [], block_action: "nxdomain", log: true, ...(savedDefaultPolicy || {}), upstream: up };
  try {
    await API("/api/instances/" + encodeURIComponent(online.id) + "/policy", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    toast("default upstream saved on " + online.id);
  } catch (e) { toast("save failed: " + e.message, "err"); }
};
$("s-fetch").onclick = async () => {
  const u = ($("s-bl-url").value || "").trim();
  if (!u) return toast("enter a URL", "err");
  try { await API("/api/blocklist/import-url", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: u }) }); toast("blocklist fetched"); loadBlocklist(); }
  catch (e) { toast("failed: " + e.message, "err"); }
};

/* settings link from dashboard/overview */
document.querySelectorAll("[data-goto]").forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); go(a.dataset.goto); }));

/* ---------- live polling ---------- */
loadBlocklist();
connectSSE();
refresh();
refreshSettings();
pollTimer = setInterval(() => { if (current === "dashboard" || current === "instances" || current === "queries") refresh(); }, 5000);
setInterval(() => { fetchChart(); }, 60000); // refresh chart periodically
