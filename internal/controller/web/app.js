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
  x: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18M6 6l12 12"/></svg>',
};

/* ---------- routing ---------- */
const NAV = [
  { id: "dashboard", label: "Dashboard", icon: IC.dash, group: "Overview" },
  { id: "queries", label: "Query Log", icon: IC.query, group: "Overview" },
  { id: "clients", label: "Clients", icon: IC.device, group: "Overview" },
  { id: "instances", label: "Instances", icon: IC.inst, group: "DNS" },
  { id: "blocklist", label: "Blocklists", icon: IC.block, group: "DNS" },
  { id: "filters", label: "DNS Filters", icon: IC.shield, group: "DNS" },
  { id: "settings", label: "Settings", icon: IC.set, group: "System" },
];
const TITLES = {
  dashboard: ["Dashboard", "Fleet throughput &amp; health"],
  queries: ["Query Log", "Live DNS resolution history"],
  "upstream-errors": ["Upstream Errors", "Failed upstream requests and when they happened"],
  clients: ["Clients", "Who is querying this resolver"],
  instances: ["Instances", "Managed blipd resolvers"],
  blocklist: ["Blocklists", "Global blocked domains and list sources"],
  filters: ["DNS Filters", "Per-instance policies and scope rules"],
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
  if (page === "blocklist" || page === "filters") loadBlocklist();
  if (page === "filters") renderPolicies();
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
let blAllowed = [];
let blSourceStats = [];
let blAutoHours = 0;
let blNextUpdate = null;
let chart = null;
let chartRange = "1d";
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
    else if (current === "upstream-errors") renderUpstreamErrors();
    else if (current === "clients") renderClients();
    else if (current === "filters") renderPolicies();
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
// d-range maps a dropdown value to a backend `since` window and chart bucket.
const STAT_RANGES = {
  "1h":  { since: "1h",  bucket: "10s", label: "1 hour" },
  "1d":  { since: "24h", bucket: "5m",  label: "1 day" },
  "1w":  { since: "168h", bucket: "1h", label: "1 week" },
  "1mo": { since: "720h", bucket: "6h", label: "1 month" },
};

// Dashboard totals come from blipc's persisted stats samples (SQLite), so they
// survive blipd/blipc restarts. renderDashboard only updates live status;
// fetchStats loads the range-scoped numbers, per-instance breakdown and chart.
async function renderDashboard() {
  const on = instances.filter((i) => i.online).length;
  $("d-online").textContent = on;
  $("d-total").textContent = instances.length;
  fetchStats();
}

function renderDashInstances(perInstance) {
  const el = $("d-instances");
  const list = instances.slice().sort((a, b) => (a.id || "").localeCompare(b.id || ""));
  if (!list.length) {
    el.innerHTML = `<div class="empty"><div class="empty-ic">${IC.inst}</div><h4>No instances yet</h4><p>Add your first blipd resolver to start filtering traffic.</p><button class="btn btn-primary" id="d-empty-add">+ Add Instance</button></div>`;
    $("d-empty-add").onclick = () => openInstanceModal();
    return;
  }
  el.innerHTML = list.map((i) => {
    const pi = (perInstance && perInstance[i.id]) || {};
    const rate = pi.queries ? (pi.blocked / pi.queries * 100).toFixed(0) : 0;
    return `<div class="row" style="padding:12px 20px; border-bottom:1px solid var(--hairline)">
      <span class="dot ${i.online ? "on" : "off"}"></span>
      <div class="grow" style="min-width:0">
        <div style="font-weight:550">${esc(i.label || i.id)}</div>
        <div class="cell-sub mono" style="overflow:hidden;text-overflow:ellipsis">${esc(i.url || "")}</div>
      </div>
      <div class="num" style="text-align:right">
        <div style="font-variant-numeric:tabular-nums;font-weight:600">${fmt(pi.queries ?? 0)}</div>
        <div class="cell-sub"><span class="meter"><i style="width:${Math.min(100, rate)}%"></i></span> ${rate}% blk</div>
      </div>
    </div>`;
  }).join("");
}

/* ---------- chart ---------- */
async function fetchStats() {
  const ctx = $("chart-queries");
  const rng = STAT_RANGES[chartRange] || STAT_RANGES["1d"];
  try {
    const res = await API(`/api/stats?bucket=${rng.bucket}&since=${rng.since}`);
    const d = await res.json();
    if (!d || !d.series) return;
    $("d-queries").textContent = fmt(d.total_queries ?? 0);
    $("d-blocked").textContent = fmt(d.blocked_queries ?? 0);
    $("d-errors").textContent = fmt(d.upstream_errors ?? 0);
    $("d-blockrate").textContent = d.total_queries ? (d.blocked_queries / d.total_queries * 100).toFixed(1) + "%" : "0%";
    $("d-range-hint").textContent = rng.label;
    renderDashInstances(d.per_instance);
    if (!ctx) return;
    const stats = d.series;
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
      ? `<tr class="empty-row"><td colspan="9"><div class="empty"><div class="empty-ic">${IC.query}</div><h4>No matching instances</h4><p>Try a different filter.</p></div></td></tr>`
      : `<tr class="empty-row"><td colspan="9"><div class="empty"><div class="empty-ic">${IC.inst}</div><h4>No instances yet</h4><p>Add your first blipd resolver to get started.</p><button class="btn btn-primary" id="inst-empty-add">+ Add Instance</button></div></td></tr>`;
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
      <td>${i.config_synced ? '<span class="badge on">synced</span>' : (i.online ? '<span class="badge warn">pending</span>' : '<span class="badge off">—</span>')}</td>
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
      if (qState.filter && !(r.domain + " " + r.client + " " + (r.name || "") + " " + r.instance).toLowerCase().includes(qState.filter.toLowerCase())) return false;
      if (qState.action && (r.action || "").toUpperCase() !== qState.action) return false;
      return true;
    });
    propsInstanceOptions();
    $("q-count").textContent = list.length + " entries (shown)";
    if (!list.length) {
      tb.innerHTML = `<tr class="empty-row"><td colspan="7"><div class="empty"><div class="empty-ic">${IC.query}</div><h4>No queries</h4><p>Nothing matched in the last 24 hours.</p></div></td></tr>`;
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
        <td class="q-client">${clientCellHtml(r)}</td>
        <td class="q-ips">${ipsHtml(r.ips)}</td>
        <td class="q-lat">${latencyHtml(r)}</td>
        <td class="q-inst"><span class="dot ${inst && inst.online ? "on" : "off"}"></span>${esc(inst ? (inst.label || inst.id) : r.instance)}</td>
      </tr>`;
    }).join("");
    tb.querySelectorAll(".t").forEach((t) => { t.textContent = timeAgo(t.dataset.t); });
  } catch (e) {
    tb.innerHTML = `<tr class="empty-row"><td colspan="7"><div class="empty"><div class="empty-ic">${IC.warn}</div><h4>Query log unavailable</h4><p>${esc(e.message)}</p></div></td></tr>`;
  }
}

// latencyHtml renders the answer latency and a cache badge for a query row.
function latencyHtml(r) {
  const dur = (r.duration_us == null) ? null : Number(r.duration_us);
  const lat = dur == null ? "—" : dur < 1000 ? dur + "µs" : (dur / 1000).toFixed(1) + "ms";
  const badge = r.cached ? `<span class="badge badge-action on" title="Served from cache">cache</span>` : "";
  return badge + `<span class="muted mono" title="${dur == null ? "no timing data" : dur + " µs"}">${lat}</span>`;
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

/* ---------- upstream errors ---------- */
let ueState = { inst: "", since: "24h" };
function propsUeInstanceOptions() {
  const sel = $("ue-instance");
  const cur = sel.value;
  const labels = [...new Set(instances.map((i) => i.label || i.id || ""))].filter(Boolean);
  sel.innerHTML = `<option value="">All instances</option>` + labels.map((l) => `<option value="${esc(l)}" ${l === cur ? "selected" : ""}>${esc(l)}</option>`).join("");
}
async function renderUpstreamErrors() {
  const tb = $("ue-tbody");
  propsUeInstanceOptions();
  try {
    const res = await API(`/api/upstream-errors?instance=${encodeURIComponent(ueState.inst)}&since=${ueState.since}&limit=200`);
    const d = await res.json();
    const rows = d.errors || [];
    $("ue-count").textContent = fmt(d.total ?? 0) + " errors";
    if (!rows.length) {
      tb.innerHTML = `<tr class="empty-row"><td colspan="6"><div class="empty"><div class="empty-ic">${IC.warn}</div><h4>No upstream errors</h4><p>Nothing failed in the selected range.</p></div></td></tr>`;
      return;
    }
    tb.innerHTML = rows.map((r) => {
      const inst = instances.find((i) => (i.label || i.id) === r.instance);
      return `<tr>
        <td class="q-domain"><span class="mono q-dom" title="${esc(r.message)}">${esc(r.message)}</span></td>
        <td><span class="mono">${esc(r.domain)}</span></td>
        <td class="num">${fmt(r.count)}</td>
        <td class="q-time"><span class="t" data-t="${esc(r.first_seen)}" title="${esc(r.first_seen)}">…</span></td>
        <td class="q-time"><span class="t" data-t="${esc(r.last_seen)}" title="${esc(r.last_seen)}">…</span></td>
        <td class="q-inst"><span class="dot ${inst && inst.online ? "on" : "off"}"></span>${esc(inst ? (inst.label || inst.id) : r.instance)}</td>
      </tr>`;
    }).join("");
    tb.querySelectorAll(".t").forEach((t) => { t.textContent = timeAgo(t.dataset.t); });
  } catch (e) {
    tb.innerHTML = `<tr class="empty-row"><td colspan="6"><div class="empty"><div class="empty-ic">${IC.warn}</div><h4>Upstream errors unavailable</h4><p>${esc(e.message)}</p></div></td></tr>`;
  }
}

/* ---------- clients ---------- */
let cState = { inst: "" };
let rnState = { client: "", kind: "" };
function clientCellHtml(r) {
  const name = r.name ? esc(r.name) : "";
  const raw = `<span class="mono" title="${esc(r.client)}">${esc(r.client)}</span>`;
  return `<span class="q-cicon">${IC.device}</span>` + (name
    ? `<span class="q-cname">${name}</span><span class="faint q-craw">${raw}</span>`
    : raw);
}
function clientRowHtml(r) {
  const rate = r.queries > 0 ? Math.round(100 * r.blocked / r.queries) : 0;
  return `<tr>
    <td class="q-client">${clientCellHtml(r)}</td>
    <td class="q-name">${r.name ? esc(r.name) : '<span class="faint">—</span>'}</td>
    <td class="q-count">${fmt(r.queries)}</td>
    <td class="q-count">${fmt(r.blocked)}</td>
    <td class="q-count">${rate}%</td>
    <td class="q-time"><span class="t" data-t="${esc(r.last_seen)}" title="${esc(r.last_seen)}">…</span></td>
    <td class="q-rename"><button class="icon-btn" data-rename="${esc(r.client)}" data-kind="${r.kind}" title="Rename client">${IC.edit}</button></td>
  </tr>`;
}
async function renderClients() {
  try {
    const res = await API("/api/clients?instance=" + encodeURIComponent(cState.inst) + "&since=24h&limit=250");
    const rows = await res.json();
    propsCInstanceOptions();
    const ips = rows.filter((r) => r.kind === "ip");
    const clients = rows.filter((r) => r.kind !== "ip");
    $("c-ip-count").textContent = ips.length + " (24h)";
    $("c-client-count").textContent = clients.length + " (24h)";
    renderClientRows($("c-ip-tbody"), ips, 7, "No origin IPs", "Nothing queried this resolver in the last 24 hours.");
    renderClientRows($("c-client-tbody"), clients, 7, "No DoH clients", "No request included a /dns-query/{client-id} path.");
  } catch (e) {
    renderClientErr($("c-ip-tbody"), e.message);
    renderClientErr($("c-client-tbody"), e.message);
  }
}
function renderClientRows(tb, rows, cols, title, msg) {
  if (!rows.length) {
    tb.innerHTML = `<tr class="empty-row"><td colspan="${cols}"><div class="empty"><div class="empty-ic">${IC.device}</div><h4>${title}</h4><p>${msg}</p></div></td></tr>`;
    return;
  }
  tb.innerHTML = rows.map(clientRowHtml).join("");
  tb.querySelectorAll(".t").forEach((t) => { t.textContent = timeAgo(t.dataset.t); });
}
function renderClientErr(tb, msg) {
  tb.innerHTML = `<tr class="empty-row"><td colspan="7"><div class="empty"><div class="empty-ic">${IC.warn}</div><h4>Clients unavailable</h4><p>${esc(msg)}</p></div></td></tr>`;
}
function propsCInstanceOptions() {
  const sel = $("c-instance");
  const cur = sel.value;
  const labels = [...new Set(instances.map((i) => i.label || i.id || ""))].filter(Boolean);
  sel.innerHTML = `<option value="">All instances</option>` + labels.map((l) => `<option value="${esc(l)}" ${l === cur ? "selected" : ""}>${esc(l)}</option>`).join("");
}
function openRename(client, kind) {
  rnState.client = client;
  rnState.kind = kind;
  $("rn-title").textContent = kind === "ip" ? "Rename Origin IP" : "Rename Client";
  $("rn-raw").innerHTML = `<span class="badge ${kind === "ip" ? "" : "accent"}">${kind === "ip" ? "IP" : "client"}</span> <span class="mono">${esc(client)}</span>`;
  $("rn-input").value = "";
  show("modal-rename");
  $("rn-input").focus();
}
async function saveRename() {
  const name = $("rn-input").value.trim();
  try {
    await API("/api/client-names", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client: rnState.client, name }),
    });
    hide("modal-rename");
    toast(name ? `renamed ${rnState.client} → ${name}` : `cleared name for ${rnState.client}`);
    renderClients();
  } catch (e) { toast("rename failed: " + e.message, "err"); }
}

/* ---------- blocklist ---------- */
let polCache = {};
let blSources = [];
let blStatus = { running: false, domains: 0 };
let blStatusTimer = null;
async function loadBlocklist() {
  try {
    const r = await API("/api/blocklist?limit=2000");
    const d = await r.json();
    blDomains = d.domains || [];
    blAllowed = d.allowed || [];
    if (Array.isArray(d.sources)) blSources = d.sources.slice();
    if (d.status) blStatus = d.status;
    blSourceStats = (d.status && d.status.source_stats) || [];
    blAutoHours = (d.status && d.status.auto_update_hours) || 0;
    blNextUpdate = (d.status && d.status.next_update) || null;
    renderBlocklist();
    renderAllowList();
    renderSources();
    renderBlStatus();
    if (blStatus.running) startBlStatusPoll();
  } catch (e) {}
}
function renderBlocklist() {
  const f = ($("bl-filter")?.value || "").toLowerCase();
  const list = blDomains.filter((d) => !f || d.includes(f));
  $("bl-count").textContent = fmt(blDomains.length);
  const ul = $("bl-list");
  if (!list.length) {
    ul.innerHTML = `<div class="empty"><div class="empty-ic">${IC.block}</div><h4>No custom blocked domains</h4><p>Domains added as Block are stored separately from the list sources and are never overwritten.</p></div>`;
    return;
  }
  ul.innerHTML = list.map((d) => `<li><span class="mono grow">${esc(d)}</span><button class="icon-btn" data-rm="${esc(d)}" title="Remove">${IC.trash}</button></li>`).join("");
  ul.querySelectorAll("[data-rm]").forEach((b) => b.onclick = async () => {
    try { await API("/api/blocklist", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: b.dataset.rm }) }); toast("removed " + b.dataset.rm); loadBlocklist(); }
    catch (e) { toast("remove failed", "err"); }
  });
}
function renderAllowList() {
  const ul = $("bl-list-allow");
  const cnt = $("bl-count-allow");
  if (!ul) return;
  const f = ($("bl-filter-allow")?.value || "").toLowerCase();
  const list = blAllowed.filter((d) => !f || d.includes(f));
  if (cnt) cnt.textContent = fmt(blAllowed.length);
  if (!list.length) {
    ul.innerHTML = `<div class="empty"><div class="empty-ic">${IC.shield}</div><h4>No custom allowed domains</h4><p>Domains added as Allow are never blocked, even if a list source contains them.</p></div>`;
    return;
  }
  ul.innerHTML = list.map((d) => `<li><span class="mono grow">${esc(d)}</span><button class="icon-btn" data-rm-allow="${esc(d)}" title="Remove">${IC.trash}</button></li>`).join("");
  ul.querySelectorAll("[data-rm-allow]").forEach((b) => b.onclick = async () => {
    try { await API("/api/blocklist", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: b.dataset.rmAllow, allow: true }) }); toast("removed " + b.dataset.rmAllow); loadBlocklist(); }
    catch (e) { toast("remove failed", "err"); }
  });
}
function renderSources() {
  const tb = $("bl-src-tbody");
  if (tb) {
    if (!blSources.length) {
      tb.innerHTML = `<tr class="empty-row"><td colspan="5"><div class="empty"><div class="empty-ic">${IC.block}</div><h4>No sources</h4><p>Add a list URL (AdBlock Plus or hosts format) above and hit Update now.</p></div></td></tr>`;
    } else {
      const byUrl = {};
      blSourceStats.forEach((s) => byUrl[s.url] = s);
      tb.innerHTML = blSources.map((u) => {
        const s = byUrl[u] || {};
        const n = s.domains || 0;
        const err = s.error || "";
        const upd = s.last_update ? relTime(s.last_update) : "—";
        return `<tr>
          <td class="mono" style="font-size:12px">${esc(u)}</td>
          <td>${n ? fmt(n) : "—"}</td>
          <td class="cell-sub">${upd}</td>
          <td>${err ? `<span class="badge err" title="${esc(err)}">error</span>` : n ? `<span class="badge on">ok</span>` : `<span class="badge">new</span>`}</td>
          <td style="text-align:right"><button class="icon-btn" data-rm-src="${esc(u)}" title="Remove source">${IC.x}</button></td>
        </tr>`;
      }).join("");
    }
    tb.querySelectorAll("[data-rm-src]").forEach((b) => b.onclick = () => removeSource(b.dataset.rmSrc));
  }
  const sel = $("s-bl-sources");
  if (sel) {
    sel.innerHTML = blSources.length
      ? blSources.map((u) => `<div class="row" style="gap:8px"><span class="mono grow" title="${esc(u)}">${esc(u)}</span></div>`).join("")
      : `<span class="hint">No sources. Add them on the Blocklists page.</span>`;
  }
  const cnt = $("bl-src-count");
  if (cnt) cnt.textContent = blSources.length ? `${blSources.length} source${blSources.length > 1 ? "s" : ""}` : "0";
  const ah = $("bl-auto-hours");
  if (ah) ah.value = blAutoHours || 0;
}
function renderBlStatus() {
  const st = $("bl-import-status");
  const badge = $("s-blsync");
  if (st) {
    if (blStatus.running) {
      const n = blStatus.source_total || blStatus.sources?.length || 1;
      st.innerHTML = `<b>Syncing…</b> ${blStatus.source_done || 0}/${n} ${esc(blStatus.current_url || "")} · <b>${fmt(blStatus.domains)}</b> domains`;
    } else if (blStatus.last_update) {
      const errs = (blStatus.errors || []).filter(Boolean).length;
      let txt = `${blSources.length} source${blSources.length === 1 ? "" : "s"} · <b>${fmt(blStatus.domains)}</b> domains · updated ${esc(new Date(blStatus.last_update).toLocaleTimeString())}`;
      if (blNextUpdate) txt += ` · auto next ${esc(new Date(blNextUpdate).toLocaleString())}`;
      st.innerHTML = txt + (errs ? ` · <span style="color:var(--danger)">${errs} error${errs > 1 ? "s" : ""}</span>` : "");
    } else {
      st.innerHTML = "No sources yet. Add list URLs (AdBlock Plus or hosts format) and hit Update now.";
    }
  }
  if (badge) {
    if (blStatus.running) { badge.textContent = "syncing…"; badge.classList.add("accent"); }
    else if (blSources.length) { badge.textContent = `${blSources.length} src · ${fmt(blStatus.domains)}${blAutoHours ? " · " + blAutoHours + "h" : ""}`; badge.classList.remove("accent"); }
    else { badge.textContent = "off"; badge.classList.remove("accent"); }
  }
  renderBlLog();
}
function renderBlLog() {
  const el = $("bl-log");
  if (!el) return;
  const lines = blStatus.log || [];
  if (!lines.length) {
    el.innerHTML = blStatus.running
      ? `<div class="term-empty">starting…</div>`
      : `<div class="term-empty">Press "Update now" to watch a live import.</div>`;
    return;
  }
  const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
  el.innerHTML = lines.map((l) => {
    const cls = /failed|error/i.test(l) ? "t-err" : /ok:|merged|persisted|distributed|finished/.test(l) ? "t-ok" : "";
    return `<div class="${cls}">${esc(l)}</div>`;
  }).join("");
  if (atBottom) el.scrollTop = el.scrollHeight;
}
function removeSource(u) {
  blSources = blSources.filter((s) => s !== u);
  renderSources();
}
function startBlStatusPoll() {
  if (blStatusTimer) return;
  blStatusTimer = setInterval(async () => {
    try {
      const r = await API("/api/blocklist/status");
      const d = await r.json();
      blStatus = d;
      renderBlStatus();
      if (!d.running) { clearInterval(blStatusTimer); blStatusTimer = null; loadBlocklist(); }
    } catch (e) {}
  }, 1000);
}
async function updateBlocklist() {
  const urls = blSources.filter((u) => u.trim());
  if (!urls.length) return toast("add at least one source URL", "err");
  const st = $("bl-import-status");
  st.innerHTML = "<b>Syncing…</b>";
  try {
    await API("/api/blocklist/sources", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ urls }) });
    toast("fetching blocklist sources");
    startBlStatusPoll();
  } catch (e) { st.textContent = "failed: " + e.message; toast("update failed: " + e.message, "err"); }
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
let savedDefaultPolicy = null; // fleet default policy held by blipc
let savedOverrides = {};       // sparse per-instance overrides keyed by instance id
let scopeState = "default";    // "default" or an instance id

// DoH plain-HTTP editor state
let savedFleetDoH = "";        // fleet-wide plain-HTTP DoH address ("" = off)
let dohScopeState = "default"; // "default" or an instance id

// Rate-limit editor state
let savedRLQPS = 0;             // fleet-wide per-client QPS (0 = off)
let rlScopeState = "default";   // "default" or an instance id
function renderRlScopeSelect() {
  const sel = $("s-rl-scope");
  sel.innerHTML = "";
  const opt = (v, label) => {
    const o = document.createElement("option");
    o.value = v; o.textContent = label; sel.appendChild(o);
  };
  opt("default", "Fleet-wide default");
  for (const i of instances) {
    const has = savedOverrides[i.id] && savedOverrides[i.id].rate_limit_qps != null;
    opt(i.id, "instance: " + (i.label || i.id) + (has ? " (custom)" : ""));
  }
  if (!instances.some((i) => i.id === rlScopeState)) rlScopeState = "default";
  sel.value = rlScopeState;
}
function loadRlEditor() {
  renderRlScopeSelect();
  const qpsIn = $("s-rl-qps");
  const cur = $("s-rl-cur");
  const badge = $("s-rl-badge");
  const hint = $("s-rl-scope-hint");
  const hasOverride = (id) => savedOverrides[id] && savedOverrides[id].rate_limit_qps != null;
  if (rlScopeState === "default") {
    badge.textContent = "fleet-wide";
    badge.className = "badge accent";
    qpsIn.value = savedRLQPS > 0 ? savedRLQPS : "";
    cur.textContent = savedRLQPS === 0 ? "off" : (savedRLQPS + " qps");
    hint.textContent = "Applies to every instance that doesn't have its own override.";
  } else {
    badge.textContent = "instance";
    badge.className = "badge purple";
    const o = savedOverrides[rlScopeState];
    const set = hasOverride(rlScopeState);
    const q = set ? o.rate_limit_qps : null;
    qpsIn.value = q != null && q > 0 ? q : "";
    cur.textContent = set ? (q === 0 ? "off" : (q + " qps")) : "inherits fleet default";
    hint.textContent = "Blank = inherit the fleet-wide default.";
  }
}

function renderDoHScopeSelect() {
  const sel = $("s-doh-scope");
  sel.innerHTML = "";
  const opt = (v, label) => {
    const o = document.createElement("option");
    o.value = v; o.textContent = label; sel.appendChild(o);
  };
  opt("default", "Fleet-wide default");
  for (const i of instances) {
    const has = savedOverrides[i.id] && savedOverrides[i.id].doh_http_addr;
    opt(i.id, "instance: " + (i.label || i.id) + (has ? " (custom)" : ""));
  }
  if (!instances.some((i) => i.id === dohScopeState)) dohScopeState = "default";
  sel.value = dohScopeState;
}

function loadDoHEditor() {
  renderDoHScopeSelect();
  const badge = $("s-doh-badge");
  const plainCb = $("s-doh-plain");
  const addrIn = $("s-doh-addr");
  const hint = $("s-doh-scope-hint");
  if (dohScopeState === "default") {
    badge.textContent = "fleet-wide";
    badge.className = "badge accent";
    const on = savedFleetDoH !== "";
    plainCb.checked = on;
    addrIn.disabled = !on;
    addrIn.value = on ? savedFleetDoH : "";
    hint.textContent = "Enables a plain-HTTP DoH listener in addition to DoH over HTTPS.";
  } else {
    badge.textContent = "instance";
    badge.className = "badge purple";
    const o = savedOverrides[dohScopeState];
    const addr = o && o.doh_http_addr;
    const has = addr !== undefined && addr !== null;
    plainCb.checked = !!has;
    addrIn.disabled = !has;
    addrIn.value = has ? (addr || "") : "";
    hint.textContent = "Unchecked = inherit the fleet-wide default.";
  }
}

function renderScopeSelect() {
  const sel = $("s-scope");
  sel.innerHTML = "";
  const opt = (v, label) => {
    const o = document.createElement("option");
    o.value = v; o.textContent = label; sel.appendChild(o);
  };
  opt("default", "Fleet-wide default");
  for (const i of instances) {
    opt(i.id, "instance: " + (i.label || i.id) + (savedOverrides[i.id] ? " (custom)" : ""));
  }
  if (!instances.some((i) => i.id === scopeState)) scopeState = "default";
  sel.value = scopeState;
}

function loadScopeEditor() {
  renderScopeSelect();
  const badge = $("s-scope-badge");
  if (scopeState === "default") {
    badge.textContent = "fleet-wide";
    badge.className = "badge accent";
    renderUpstreamList(parseUpstreamSpec(savedDefaultPolicy.upstream));
    $("s-scope-hint").textContent = "Applies to every instance that doesn't have its own override.";
  } else {
    badge.textContent = "instance";
    badge.className = "badge purple";
    const o = savedOverrides[scopeState];
    renderUpstreamList(parseUpstreamSpec(o && o.upstream));
    $("s-scope-hint").textContent = "Only for this instance. Fields you leave unset inherit the fleet-wide default.";
  }
}

async function refreshSettings() {
  $("s-ctrl-ver").textContent = "blipc";
  $("s-inst-count").textContent = instances.length + (instances.some((i) => i.online) ? " (" + instances.filter((i) => i.online).length + " online)" : "");
  // The fleet config lives on blipc (default policy + sparse per-instance
  // overrides) and is distributed to the instances.
  try {
    const r = await API("/api/settings");
    const d = await r.json();
    savedDefaultPolicy = d.default_policy || { id: "default" };
    savedOverrides = d.instance_overrides || {};
    // fleet-wide plain-HTTP DoH address ("" = off)
    savedFleetDoH = (d.doh_http_addr != null && d.doh_http_addr !== undefined) ? (d.doh_http_addr || "") : "";
    savedRLQPS = (d.rate_limit_qps != null && d.rate_limit_qps !== undefined) ? Number(d.rate_limit_qps || 0) : 0;
    // carry over any per-instance doh_http_addr not already surfaced
    loadScopeEditor();
    loadDoHEditor();
    loadRlEditor();
    $("s-up-status").textContent = "";
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
const validPage = (id) => NAV.some((n) => n.id === id) || id === "upstream-errors";
const initial = (location.pathname.replace(/\/+$/, "") || "/").replace(/^\//, "");
go(validPage(initial) ? initial : "dashboard", false);

/* popstate */
window.addEventListener("popstate", () => {
  const p = (location.pathname.replace(/\/+$/, "") || "/").replace(/^\//, "");
  go(validPage(p) ? p : "dashboard", false);
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

/* upstream errors */
$("ue-instance").addEventListener("change", (e) => { ueState.inst = e.target.value; renderUpstreamErrors(); });
$("ue-range").addEventListener("change", (e) => { ueState.since = e.target.value; renderUpstreamErrors(); });
$("ue-refresh").onclick = renderUpstreamErrors;
$("q-tbody").addEventListener("click", (e) => {
  const c = e.target.closest("[data-copy]"); if (!c) return;
  copyText(c.dataset.copy);
});
// setQueryAction updates the query-log action filter ("" = all, "PASS",
// "BLOCK") and the highlighted segment button, then re-renders. Used by the
// segment buttons and by dashboard links that deep-link into a filtered view.
function setQueryAction(action) {
  qState.action = action;
  document.querySelectorAll("#q-action-seg button").forEach((x) => x.classList.toggle("active", x.dataset.a === action));
  renderQueries();
}
document.querySelectorAll("#q-action-seg button").forEach((b) => b.onclick = () => setQueryAction(b.dataset.a));

/* clients */
$("c-instance").addEventListener("change", (e) => { cState.inst = e.target.value; renderClients(); });
$("c-refresh").onclick = renderClients;
["c-ip-tbody", "c-client-tbody"].forEach((id) => $(id).addEventListener("click", (e) => {
  const b = e.target.closest("[data-rename]"); if (!b) return;
  openRename(b.dataset.rename, b.dataset.kind);
}));
$("rn-save").onclick = saveRename;
$("rn-input").addEventListener("keydown", (e) => { if (e.key === "Enter") saveRename(); });

/* chart range */
$("d-range").addEventListener("change", (e) => {
  chartRange = e.target.value;
  fetchStats();
});

/* blocklist */
let blMode = "block";
document.querySelectorAll("#bl-mode-seg button").forEach((b) => b.onclick = () => {
  document.querySelectorAll("#bl-mode-seg button").forEach((x) => x.classList.remove("active"));
  b.classList.add("active");
  blMode = b.dataset.mode;
  $("bl-add-input").placeholder = blMode === "allow" ? "whitelist a domain…" : "domain.example.com";
});
$("bl-add").onclick = async () => {
  const d = ($("bl-add-input").value || "").trim();
  if (!d) return toast("enter a domain", "err");
  try { await API("/api/blocklist", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: d, allow: blMode === "allow" }) }); toast(blMode === "allow" ? "allowed " + d : "added " + d); $("bl-add-input").value = ""; loadBlocklist(); }
  catch (e) { toast("add failed: " + e.message, "err"); }
};
$("bl-add-input").addEventListener("keydown", (e) => { if (e.key === "Enter") $("bl-add").click(); });
$("bl-url-input").addEventListener("keydown", (e) => { if (e.key === "Enter") $("bl-url-add").click(); });
$("bl-url-add").onclick = () => {
  const u = ($("bl-url-input").value || "").trim();
  if (!u) return toast("enter a source URL", "err");
  if (!/^https?:\/\//i.test(u)) return toast("URL must start with http(s)://", "err");
  if (blSources.includes(u)) return toast("source already added", "err");
  blSources.push(u);
  $("bl-url-input").value = "";
  renderSources();
};
$("bl-update").onclick = updateBlocklist;
$("bl-log-clear").onclick = async () => {
  try { await API("/api/blocklist/clear-log", { method: "POST" }); blStatus.log = []; renderBlLog(); }
  catch (e) { toast("clear failed", "err"); }
};
$("bl-auto-save").onclick = async () => {
  const h = parseInt(($("bl-auto-hours") || {}).value ?? "0", 10);
  if (isNaN(h) || h < 0) return toast("enter hours (0 = off)", "err");
  try {
    await API("/api/blocklist/sources", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ urls: blSources.filter((u) => u.trim()), auto_update_hours: h }) });
    blAutoHours = h;
    toast(h ? `auto-update every ${h}h` : "auto-update off");
    loadBlocklist();
  } catch (e) { toast("save failed: " + e.message, "err"); }
};
$("bl-filter").addEventListener("input", renderBlocklist);
$("bl-filter-allow").addEventListener("input", renderAllowList);
$("bl-export").onclick = () => window.open("/api/blocklist/export", "_blank");
$("bl-clear").onclick = () => {
  confirmDialog("Clear entire blocklist?", "This removes every blocked domain, drops all sources, and deletes custom domains. This cannot be undone.", async () => {
    try {
      await API("/api/blocklist/sources", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ urls: [], clear_manual: true }) });
      blSources = [];
      toast("cleared blocklist"); loadBlocklist();
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
  const st = $("s-up-status");
  st.textContent = "saving…";
  let body, msg;
  if (scopeState === "default") {
    body = { default_policy: { id: "default", networks: [], block: [], allow: [], block_action: "nxdomain", log: true, ...(savedDefaultPolicy || {}), upstream: up } };
    msg = "fleet default upstream saved";
  } else {
    body = { scope: "instance", instance: scopeState, override: up ? { upstream: up } : {} };
    msg = "instance override saved";
  }
  try {
    const r = await API("/api/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    if (scopeState === "default") {
      savedDefaultPolicy = body.default_policy;
    } else if (up) {
      savedOverrides[scopeState] = { upstream: up };
    } else {
      delete savedOverrides[scopeState];
    }
    const applied = d.applied || {};
    const ids = Object.keys(applied);
    const ok = ids.filter((k) => applied[k] === "ok").length;
    const failed = ids.filter((k) => applied[k] !== "ok");
    st.textContent = ids.length ? `saved on blipc · pushed to ${ok}/${ids.length} instance${ids.length > 1 ? "s" : ""}` + (failed.length ? ` · errors: ${failed.join(", ")}` : "") : "saved on blipc · no instance to push to yet";
    toast(msg + (ids.length ? ` (${ok}/${ids.length})` : ""));
    renderScopeSelect();
  } catch (e) { st.textContent = ""; toast("save failed: " + e.message, "err"); }
};
$("s-scope").addEventListener("change", (e) => { scopeState = e.target.value; loadScopeEditor(); });

/* DoH editor wiring */
$("s-doh-scope").addEventListener("change", (e) => { dohScopeState = e.target.value; loadDoHEditor(); });
$("s-doh-plain").addEventListener("change", (e) => {
  const plainCb = $("s-doh-plain");
  const addrIn = $("s-doh-addr");
  if (plainCb.checked && !addrIn.value) addrIn.value = "0.0.0.0:8445";
  addrIn.disabled = !plainCb.checked;
});
$("s-rl-scope").addEventListener("change", (e) => {
  rlScopeState = e.target.value;
  loadRlEditor();
});
function rlQpsForSave() {
  const v = $("s-rl-qps").value.trim();
  return v === "" ? 0 : Number(v);
}
$("s-save-rl").onclick = async () => {
  const st = $("s-rl-status");
  st.textContent = "saving…";
  const qps = rlQpsForSave();
  let body, msg;
  if (rlScopeState === "default") {
    body = { rate_limit_qps: qps };
    msg = qps === 0 ? "fleet rate limit disabled" : "fleet rate limit saved";
  } else {
    body = { scope: "instance", instance: rlScopeState, rate_limit_qps: qps };
    msg = qps === 0 ? "instance rate limit override cleared" : "instance rate limit override saved";
  }
  try {
    const r = await API("/api/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    const applied = d.applied || {};
    const ids = Object.keys(applied);
    const ok = ids.filter((k) => applied[k] === "ok").length;
    const failed = ids.filter((k) => applied[k] !== "ok");
    st.textContent = ids.length ? "saved on blipc · pushed to " + ok + "/" + ids.length + " instance" + (ids.length > 1 ? "s" : "") + (failed.length ? " · errors: " + failed.join(", ") : "") : "saved on blipc · no instance to push to yet";
    toast(msg + (ids.length ? " (" + ok + "/" + ids.length + ")" : ""));
    if (rlScopeState === "default") {
      savedRLQPS = qps;
    } else {
      const o = savedOverrides[rlScopeState];
      if (qps === 0) {
        if (o) delete o.rate_limit_qps;
        if (!o || Object.keys(o).length === 0) delete savedOverrides[rlScopeState];
      } else {
        if (!o) savedOverrides[rlScopeState] = { rate_limit_qps: qps };
        else o.rate_limit_qps = qps;
      }
    }
    loadRlEditor();
  } catch (e) { st.textContent = ""; toast("save failed: " + e.message, "err"); }
};
function dohAddrForSave() {
  const plainCb = $("s-doh-plain");
  const addrIn = $("s-doh-addr");
  if (!plainCb.checked) return "";
  return (addrIn.value || "").trim();
}
$("s-save-doh").onclick = async () => {
  const st = $("s-doh-status");
  st.textContent = "saving…";
  let body, msg;
  const addr = dohAddrForSave();
  if (dohScopeState === "default") {
    body = { doh_http_addr: addr };
    msg = addr ? "fleet DoH saved" : "fleet DoH disabled";
  } else {
    body = { scope: "instance", instance: dohScopeState, doh_http_addr: addr };
    msg = addr ? "instance DoH override saved" : "instance DoH override cleared";
  }
  try {
    const r = await API("/api/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    const applied = d.applied || {};
    const ids = Object.keys(applied);
    const ok = ids.filter((k) => applied[k] === "ok").length;
    const failed = ids.filter((k) => applied[k] !== "ok");
    st.textContent = ids.length ? `saved on blipc · pushed to ${ok}/${ids.length} instance${ids.length > 1 ? "s" : ""}` + (failed.length ? ` · errors: ${failed.join(", ")}` : "") : "saved on blipc · no instance to push to yet";
    toast(msg + (ids.length ? ` (${ok}/${ids.length})` : ""));
    if (dohScopeState === "default") {
      savedFleetDoH = addr;
    } else {
      const o = savedOverrides[dohScopeState];
      if (addr) {
        if (!o) savedOverrides[dohScopeState] = { doh_http_addr: addr };
        else o.doh_http_addr = addr;
      } else if (o) {
        delete o.doh_http_addr;
      }
    }
    loadDoHEditor();
  } catch (e) { st.textContent = ""; toast("save failed: " + e.message, "err"); }
};
$("s-fetch").onclick = async () => {
  const urls = blSources.filter((u) => u.trim());
  if (!urls.length) return toast("no blocklist sources configured", "err");
  try { await API("/api/blocklist/sources", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ urls }) }); toast("fetching blocklist sources"); startBlStatusPoll(); }
  catch (e) { toast("failed: " + e.message, "err"); }
};
$("s-reset-stats").onclick = () => {
  confirmDialog("Reset statistics?", "Clears all aggregated statistics and charts on the dashboard. Live per-instance counters are unaffected. This cannot be undone.", async () => {
    try {
      await API("/api/maintenance", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: "reset_stats" }) });
      toast("statistics reset");
      if (current === "dashboard") fetchStats();
    } catch (e) { toast("reset failed: " + e.message, "err"); }
  });
};
$("s-clear-querylog").onclick = () => {
  confirmDialog("Clear query logs?", "Removes every entry from the query log. This cannot be undone.", async () => {
    try {
      await API("/api/maintenance", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: "clear_query_log" }) });
      toast("query log cleared");
      if (current === "queries") refresh();
    } catch (e) { toast("clear failed: " + e.message, "err"); }
  });
};

/* settings link from dashboard/overview */
document.querySelectorAll("[data-goto]").forEach((a) => a.addEventListener("click", (e) => {
  e.preventDefault();
  if (a.dataset.gotoAction !== undefined) setQueryAction(a.dataset.gotoAction);
  go(a.dataset.goto);
}));

/* ---------- live polling ---------- */
loadBlocklist();
connectSSE();
refresh();
refreshSettings();
pollTimer = setInterval(() => { if (current === "dashboard" || current === "instances" || current === "queries" || current === "upstream-errors") refresh(); }, 5000);
setInterval(() => { if (current === "dashboard") fetchStats(); }, 60000); // refresh chart/stats periodically
