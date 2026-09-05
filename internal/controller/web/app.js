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
const validDate = (t) => t && new Date(t).getFullYear() > 2000;
// fmtQPS formats an average query rate with a sensible number of decimals so
// small fleets show a real number (0.05 qps) instead of rounding to 0.
const fmtQPS = (v) => {
  if (!(v > 0)) return "0";
  if (v >= 100) return v.toFixed(0);
  if (v >= 1) return v.toFixed(1);
  return v.toFixed(2);
};
const timeAgo = (t) => {
  if (!t) return "—";
  const s = (Date.now() - new Date(t).getTime()) / 1000;
  if (s < 60) return Math.max(0, Math.round(s)) + "s ago";
  if (s < 3600) return Math.round(s / 60) + "m ago";
  if (s < 86400) return Math.round(s / 3600) + "h ago";
  return Math.round(s / 86400) + "d ago";
};
const relTime = (t) => (t ? new Date(t).toLocaleString() : "—");
// fmtLat formats a microsecond duration into a human-friendly latency string.
// Sub-millisecond values show as µs; millisecond and second values get a decimal.
const fmtLat = (us) => {
  if (!(us > 0)) return "—";
  if (us < 1000) return Math.round(us) + "µs";
  if (us < 1000000) return (us / 1000).toFixed(1) + "ms";
  return (us / 1000000).toFixed(1) + "s";
};

/* ---------- relative-time ticking ---------- */
// Recomputes every live relative-time label (.t[data-t]) on a 1s tick so the
// "…s/min/h ago" text and the absolute date/time hover tooltip stay fresh
// without needing to Refresh, as long as those rows are rendered.
let clockTimer = null;
function tickRelativeTimes() {
  document.querySelectorAll(".t[data-t]").forEach((t) => {
    const ts = t.dataset.t;
    if (!ts) return;
    t.textContent = timeAgo(ts);
    t.title = relTime(ts);
  });
}
function startClock() {
  if (clockTimer) return;
  tickRelativeTimes();
  clockTimer = setInterval(tickRelativeTimes, 1000);
}

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
  info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4m0-4h.01"/></svg>',
  arrow: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14m-6-6 6 6-6 6"/></svg>',
  globe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.8 5.7 3.8 9S14.5 18.4 12 21c-2.5-2.6-3.8-5.7-3.8-9S9.5 5.6 12 3z"/></svg>',
  device: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="4" width="20" height="13" rx="2"/><path d="M8 21h8M12 17v4"/></svg>',
  refresh: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-2.6-6.4"/><path d="M21 3v6h-6"/></svg>',
  x: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18M6 6l12 12"/></svg>',
  power: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18.4 6.6a9 9 0 1 1-12.8 0"/><path d="M12 2v10"/></svg>',
  cache: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5"/><path d="M3 12c0 1.7 4 3 9 3s9-1.3 9-3"/></svg>',
};

/* ---------- routing ---------- */
const NAV = [
  { id: "dashboard", label: "Dashboard", icon: IC.dash, group: "Overview" },
  { id: "queries", label: "Query Log", icon: IC.query, group: "Overview" },
  { id: "cache-stats", label: "Cache Stats", icon: IC.cache, group: "Overview" },
  { id: "clients", label: "Clients", icon: IC.device, group: "Overview" },
  { id: "instances", label: "Instances", icon: IC.inst, group: "DNS" },
  { id: "blocklist", label: "Blocklists", icon: IC.block, group: "DNS" },
  { id: "filters", label: "DNS Filters", icon: IC.shield, group: "DNS" },
  { id: "upstream", label: "Upstream", icon: IC.globe, group: "DNS" },
  { id: "records", label: "Local Records", icon: IC.set, group: "DNS" },
  { id: "settings", label: "Settings", icon: IC.set, group: "System" },
  { id: "ha", label: "High Availability", icon: IC.shield, group: "System" },
];
const TITLES = {
  dashboard: ["Dashboard", "Fleet throughput &amp; health"],
  queries: ["Query Log", "Live DNS resolution history"],
  "cache-stats": ["Cache Stats", "Cache hit rate and in-memory domain counts"],
  "upstream-errors": ["Upstream Errors", "Failed upstream requests and when they happened"],
  clients: ["Clients", "Who is querying this resolver"],
  instances: ["Instances", "Managed blipd resolvers"],
  blocklist: ["Blocklists", "Global blocked domains and list sources"],
  filters: ["DNS Filters", "Per-instance policies and scope rules"],
  upstream: ["Upstream &amp; Conditional Forwarding", "Named resolvers and per-suffix forwarding routes"],
  records: ["Local Records", "Static DNS records answered locally before forwarding"],
  settings: ["Settings", "Controller configuration"],
  ha: ["High Availability", "LAN keepalived / VRRP failover"],
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
  if (page !== "blocklist" && blStatusTimer) { clearInterval(blStatusTimer); blStatusTimer = null; }
  refresh();
  if (page === "instances") renderEvents();
  if (page === "settings" || page === "upstream") refreshSettings();
  if (page === "ha") loadHighAvailability();
  if (page === "blocklist" || page === "filters") loadBlocklist();
  if (page === "records") loadRecords();
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
// Poll timer for the controller self-update badge (Settings → About).
// Declared with the other top-level state: refreshSettings() (invoked by the
// initial go() route below) reaches it via loadControllerUpdate(), so it must
// be initialized before that call — `let` is in the temporal dead zone until
// its declaration executes.
let ctrlUpdateTimer = null;

/* ---------- data refresh ---------- */
async function refresh() {
  try {
    const res = await API("/api/instances");
    instances = await res.json();
    updateConn();  if (current === "dashboard") renderDashboard();
    	else if (current === "instances") renderInstances();

     	else if (current === "queries") refreshQueryTop();
     	else if (current === "records") renderRecords();
     	else if (current === "cache-stats") renderCacheStats();
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
  "1h":  { since: "1h",   bucket: "10s", label: "1 hour",  dates: false },
  "1d":  { since: "24h",  bucket: "5m",  label: "1 day",   dates: false },
  "1w":  { since: "168h", bucket: "1h",  label: "1 week",  dates: true },
  "1mo": { since: "720h", bucket: "6h",  label: "1 month", dates: true },
};

// Dashboard totals come from blipc's persisted stats samples (SQLite), so they
// survive blipd/blipc restarts. renderDashboard only updates live status;
// fetchStats loads the range-scoped numbers, per-instance breakdown and chart.
async function renderDashboard() {
  const on = instances.filter((i) => i.online).length;
  $("d-online").textContent = on;
  $("d-total").textContent = instances.length;
  // Fleet-wide refused count = sum of each instance's cumulative rate_limited
  // counter (cumulative since its last restart; tracked separately from the
  // resolved query totals so the limiter no longer pollutes QPS/cache stats).
  let refused = 0;
  for (const i of instances) {
    if (i.online && i.stats) {
      refused += Number(i.stats.rate_limited) || 0;
    }
  }
  $("d-refused").textContent = fmt(refused);
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

function renderTopDomains(domains) {
  const el = $("d-topdomains");
  const list = Array.isArray(domains) ? domains : [];
  if (!list.length) {
    el.innerHTML = `<div class="empty"><div class="empty-ic">${IC.globe}</div><h4>No queries yet</h4><p>Nothing resolved in this window.</p></div>`;
    return;
  }
  const max = list[0].queries || 1;
  el.innerHTML = list.map((d, i) => {
    const pct = Math.max(4, Math.round(d.queries / max * 100));
    const blocked = d.blocked > 0 ? `<span class="badge off" style="flex:none" title="blocked queries">${fmt(d.blocked)} blk</span>` : "";
    return `<li>
      <span class="mono" style="flex:none;width:22px;color:var(--faint);font-size:12px">${i + 1}</span>
      <div class="grow" style="min-width:0">
        <div style="font-family:var(--mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(d.domain)}">${esc(d.domain)}</div>
        <div class="cell-sub"><span class="meter"><i style="width:${pct}%"></i></span> <span class="muted">${fmt(d.queries)} queries</span></div>
      </div>
      ${blocked}
    </li>`;
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
    $("d-qps").textContent = fmtQPS(d.avg_qps);
    $("d-qps-range-hint").textContent = rng.label;
    $("d-range-hint").textContent = rng.label;
    renderDashInstances(d.per_instance);
    API(`/api/top-domains?since=${rng.since}&limit=10`)
      .then((r) => r.json())
      .then((t) => renderTopDomains(t.domains))
      .catch(() => { /* best-effort */ });
    if (!ctx) return;
    const gl = ctx.getContext("2d");
    const stats = d.series;
    const labels = stats.map((s) => fmtChartTick(new Date(s.timestamp), rng.dates));
    const tq = stats.map((s) => s.total_queries);
    const bq = stats.map((s) => s.blocked_queries);
    if (!chart) {
      Chart.defaults.color = "#7a8291";
      Chart.defaults.borderColor = "rgba(255,255,255,.06)";
      chart = new Chart(gl, {
        type: "line",
        data: {
          labels,
          datasets: [
            { label: "Total", data: tq, borderColor: "#4f8cff", backgroundColor: cgrad(gl, "79,140,255"), fill: true, tension: .35, pointRadius: 0, borderWidth: 2 },
            { label: "Blocked", data: bq, borderColor: "#f76b6b", backgroundColor: cgrad(gl, "247,107,107"), fill: true, tension: .35, pointRadius: 0, borderWidth: 2 },
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
// X-axis tick labels: time-of-day for short ranges, dates for week/month.
function fmtChartTick(d, dates) {
  if (!dates) return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return d.toLocaleDateString([], { weekday: "short", day: "numeric", month: "short" });
}

/* ---------- live events (SSE) ---------- */
let eventsRenderTimer = null;
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
  // Drop the bulky fields the event list never renders — the full
  // StatsResponse (with PerClient) and HealthResponse can each be
  // hundreds of KB on a busy resolver and would otherwise accumulate
  // in eventBuffer for the lifetime of the tab.
  e.stats = null;
  e.health = null;
  eventBuffer.unshift(e);
  eventBuffer = eventBuffer.slice(0, 60);
  // Throttle renders to at most once per 2 seconds: the SSE stream can
  // deliver many events per second (health polls + live queries), and
  // rebuilding innerHTML on every event causes GC pressure and retains
  // large DOM node graphs between renders.
  if (current !== "instances") return;
  if (eventsRenderTimer) clearTimeout(eventsRenderTimer);
  eventsRenderTimer = setTimeout(() => { renderEvents(); }, 2000);
}
function renderEvents() {
  const el = $("d-events");
  if (!eventBuffer.length) {
    el.innerHTML = `<div class="empty"><div class="empty-ic">${IC.dash}</div><h4>Waiting for traffic</h4><p>Block / pass events will stream here live.</p></div>`;
    return;
  }
  el.innerHTML = eventBuffer.map((e) => {
    const kind = e.type === "block" ? { b: 'badge err', ic: IC.block } : e.type === "pass" ? { b: 'badge on', ic: IC.query } : { b: "badge accent", ic: IC.shield };
    const resp = e.type === "pass" ? respSummary(e) : "";
    return `<li><span class="t">${new Date(e.at).toLocaleTimeString()}</span>
      <span class="badge ${kind.b}">${e.type}</span>
      <div class="grow" style="min-width:0">
        <div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--mono)">${esc(e.domain || e.msg || e.type)}</div>
        ${resp ? `<div class="cell-sub">${resp}</div>` : `<div class="cell-sub">${esc(e.instance || e.instance_id || "")}${e.client ? " · " + esc(e.client) : ""}</div>`}
      </div></li>`;
  }).join("");
}

// respSummary renders a short answer/cache summary for a pass event, reusing the
// same truncated chips as the query-log table so TXT/CNAME/MX/SRV are visible.
function respSummary(e) {
    const parts = [];
    if (e.cached) parts.push('cache');
    const ans = (e.answers && e.answers.length) ? e.answers : [];
    if (ans.length) {
        parts.push(ans.map((a) => a.type + ": " + a.data).join(", "));
    } else if (e.ips && e.ips.length) {
        parts.push(e.ips.slice(0, 2).join(", "));
    }
    const instance = e.instance || e.instance_id || "";
    return esc(parts.join(" · ") || (e.upstream || "")) + `${instance ? " · " + esc(instance) : ""}${e.client ? " · " + esc(e.client) : ""}`;
}

/* ---------- instances ---------- */
function renderInstances() {
  const tb = $("inst-tbody");
  const f = ($("inst-filter")?.value || "").toLowerCase();
  const list = instances.filter((i) => !f || (i.id + " " + (i.label || "") + " " + (i.url || "")).toLowerCase().includes(f)).sort((a, b) => (a.id || "").localeCompare(b.id || ""));
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
      <td>
        <span class="status-pill ${i.online ? "on" : "off"}">${i.online ? "online" : "offline"}</span>
        ${fleetUpdateJob.running && i.id === fleetUpdateJob.current ? '<span class="badge accent" title="This node is being updated by the serialized update job">updating…</span>' : (i.update_available ? '<span class="badge warn" title="Running ' + esc(i.health.version || 'unknown') + ' → ' + esc(i.latest_version || 'newer build') + ' available">update available</span>' : (i.online && i.health ? '<span class="badge on" title="Running ' + esc(i.health.version || 'unknown version') + '">up to date</span>' : ''))}
      </td>
      <td class="num">${fmt(s.queries_total ?? 0)}</td>
      <td class="num"><span style="color:${s.blocked_total ? "var(--red)" : "inherit"}">${fmt(s.blocked_total ?? 0)}</span></td>
      <td class="num">${fmt(s.cached ?? 0)}</td>
      <td class="num mono">${ping}</td>
      <td><span class="badge ${i.adopted ? "on" : "off"}">${i.adopted ? "adopted" : "pending"}</span></td>
      <td>${i.config_synced ? '<span class="badge on">synced</span>' : (i.online ? '<span class="badge warn">pending</span>' : '<span class="badge off">—</span>')}</td>
      <td>
        <div class="row-actions">
          <button class="icon-btn" data-act="restart" data-id="${esc(i.id)}" title="Restart blipd">${IC.refresh}</button>
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
  confirmDialog(`Remove instance ${id}?`, "This removes it from the fleet. Its blipd process is not stopped.", async () => {
    try { await API("/api/instances/" + encodeURIComponent(id), { method: "DELETE" }); toast("removed " + id); refresh(); }
    catch (e) { toast("remove failed: " + e.message, "err"); }
  });
}

/* ---------- queries ---------- */
let qState = { action: "", filter: "", inst: "", cached: "" };
// Paginated query-log state. The log is fetched 25 rows at a time, newest
// first, and appended on scroll. Filtering (text + action + instance) is done
// server-side so the total and the pages are consistent.
let qPage = { offset: 0, total: 0, ended: false, loading: false, rows: [] };
const QL_PAGE = 25;
let qlObserver = null;

function queryRowHtml(r) {
  const action = (r.action || "").toUpperCase();
  const isBlock = action === "BLOCK";
  const inst = instances.find((i) => (i.label || i.id) === r.instance);
  const actionLabel = isBlock ? "Blocked" : action === "PASS" ? "Allowed" : esc(action || "—");
  const actionBadge = isBlock ? "err" : action === "PASS" ? "on" : "";
  // info icon tooltip: request type (qtype) above the upstream/block source.
  const tipLabel = (r.q_type || "") + (r.q_type ? " · " : "") + (isBlock ? "Blocked by" : r.cached ? "Cache" : "Upstream");
  const tipValue = isBlock
    ? (r.blocklist || "blocklist")
    : r.cached ? "Served from cache" : (r.upstream || "unknown");
  return `<tr class="${isBlock ? "q-row-block" : ""}">
    <td class="q-time"><span class="t" data-t="${esc(r.timestamp)}" title="${esc(r.timestamp)}">…</span></td>
    <td class="q-domain">
      <span class="q-globe">${IC.globe}</span>
      <span class="mono q-dom" title="${esc(r.domain)}">${esc(r.domain)}</span>
      <span class="q-info" data-tipl="${esc(tipLabel)}" data-tipv="${esc(tipValue)}">${IC.info}</span>
      <button class="icon-btn q-copy" data-copy="${esc(r.domain)}" title="Copy domain">${IC.copy}</button>
    </td>
    <td><span class="badge badge-action ${actionBadge}">${isBlock ? IC.block : action === "PASS" ? IC.arrow : ""}${actionLabel}</span></td>
    <td class="q-client">${clientCellHtml(r)}</td>
    <td class="q-ips">${resolvedHtml(r)}</td>
    <td class="q-lat">${latencyHtml(r)}</td>
    <td class="q-inst"><span class="dot ${inst && inst.online ? "on" : "off"}"></span>${esc(inst ? (inst.label || inst.id) : r.instance)}</td>
  </tr>`;
}

async function renderQueries() {
  const tb = $("q-tbody");
  qTip.hide();
  qPage = { offset: 0, total: 0, ended: false, loading: false, rows: [] };
  propsInstanceOptions();
  await fetchQueryPage(tb);
}

async function fetchQueryPage(tb) {
  if (qPage.loading || qPage.ended || qPage.total > 0 && qPage.rows.length >= qPage.total) return;
  qPage.loading = true;
  const base = "/api/queries?instance=" + encodeURIComponent(qState.inst)
    + "&action=" + encodeURIComponent(qState.action)
    + "&cached=" + encodeURIComponent(qState.cached)
    + "&filter=" + encodeURIComponent(qState.filter)
    + "&since=24h&offset=" + qPage.offset + "&limit=" + QL_PAGE;
  try {
    const res = await API(base);
    const d = await res.json();
    const page = Array.isArray(d.entries) ? d.entries : [];
    qPage.total = Number(d.total) || 0;
    qPage.offset += page.length;
    qPage.rows = qPage.rows.concat(page);
    qPage.ended = page.length < QL_PAGE || qPage.rows.length >= qPage.total;
    renderQueryRows(tb);
  } catch (e) {
    tb.innerHTML = `<tr class="empty-row"><td colspan="7"><div class="empty"><div class="empty-ic">${IC.warn}</div><h4>Query log unavailable</h4><p>${esc(e.message)}</p></div></td></tr>`;
    qPage.ended = true;
  } finally {
    qPage.loading = false;
  }
  observeQuerySentinel();
}

function renderQueryRows(tb) {
  if (!qPage.rows.length) {
    tb.innerHTML = `
      <tr class="empty-row"><td colspan="7"><div class="empty"><div class="empty-ic">${IC.query}</div><h4>No queries</h4><p>Nothing matched in the last 24 hours.</p></div></td></tr>
      <tr id="q-sentinel"><td colspan="7"></td></tr>`;
    return;
  }
  const rows = qPage.rows.map((r) => queryRowHtml(r)).join("");
  const count = qPage.total > 0 ? qPage.total : qPage.rows.length;
  $("q-count").textContent = qPage.rows.length + " of " + count + " entries loaded";
  tb.innerHTML = rows + `<tr id="q-sentinel"><td colspan="7"></td></tr>`;
  tb.querySelectorAll(".t").forEach((t) => { t.textContent = timeAgo(t.dataset.t); });
}

// Observe the sentinel <tr> at the bottom of the table; when it scrolls into
// view, fetch the next page (classic infinite scroll).
function observeQuerySentinel() {
  if (qlObserver) qlObserver.disconnect();
  const sentinel = $("q-sentinel");
  if (!sentinel || qPage.ended || (qPage.total > 0 && qPage.rows.length >= qPage.total)) return;
  qlObserver = new IntersectionObserver((entries) => {
    if (entries[0].isIntersecting) fetchQueryPage($("q-tbody"));
  });
  qlObserver.observe(sentinel);
}

// Refresh the newest page of the query log only when the user hasn't scrolled
// into history; otherwise leave them where they are (manual Refresh resets).
function refreshQueryTop() {
  if (qPage.offset > QL_PAGE) return;
  renderQueries();
}

// debounce: delay a call until `ms` has elapsed since the last invocation.
function debounce(fn, ms) {
  let t = null;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
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

// trunc keeps a string under a max length, appending "…" when it is longer.
const trunc = (s, n) => { const str = String(s); return str.length > n ? str.slice(0, n - 1) + "…" : str; };
// RESOLVED_MAX caps how many characters each chip in the resolved/answer cell
// may show, so long TXT/AAAA/etc. values don't blow out the row width.
const RESOLVED_MAX = 75;

function ipsHtml(ips) {
  const list = ips || [];
  if (!list.length) return `<span class="q-ips-empty">—</span>`;
  const shown = list.slice(0, 2);
  const extra = list.length - shown.length;
  return shown.map((ip) => `<span class="q-chip" data-copy="${esc(ip)}" title="Copy ${esc(ip)}">${esc(ip)}</span>`).join("") +
    (extra > 0 ? `<span class="q-chip-more" title="${esc(list.join(", "))}">+${extra}</span>` : "");
}

// resolvedHtml renders the "Resolved IP" cell. Prefers the full answers list
// (so TXT/CNAME/MX/SRV etc. are visible, not just A/AAAA), but falls back to
// the legacy ips field for older persisted rows. TTL (seconds) is shown when
// present (omitted for 0/unknown, and never on blocked answers). Only the first
// answer is shown as a chip; remaining answers are collapsed into a single
// "+N" badge whose hover tooltip lists all of them.
function resolvedHtml(r) {
  const ans = r.answers && r.answers.length ? r.answers : [];
  const ips = r.ips || [];
  const isBlock = (r.action || "").toUpperCase() === "BLOCK";
  const parts = ans.length
    ? ans.map((a) => {
        const label = a.type + ": " + a.data;
        if (isBlock || !a.ttl) return label;
        return label + " (" + a.ttl + "s)";
      })
    : ips.map((ip) => ip);
  if (!parts.length) return `<span class="q-ips-empty">—</span>`;
  const shown = parts.slice(0, 1);
  const rest = parts.slice(1);
  const shownHtml = shown.map((p) => `<span class="q-chip" title="${esc(p)}">${esc(trunc(p, RESOLVED_MAX))}</span>`).join("");
  const moreHtml = !rest.length
    ? ""
    : `<span class="q-chip-more" title="${esc(rest.join(" · "))}">+${rest.length}</span>`;
  return shownHtml + moreHtml;
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

/* ---------- local records ---------- */
let savedRecords = [];     // fleet-wide local DNS records
let rEditIndex = -1;       // -1 = adding, >=0 = editing an existing record

function recordTypeLabel(t) { return t || "A"; }
function recordValuePlaceholder(t) {
  return t === "A" ? "192.168.1.100" :
         t === "AAAA" ? "2001:db8::1" :
         t === "CNAME" ? "target.example.com" : "value";
}

function renderRecords() {
  const tb = $("r-tbody");
  $("r-count").textContent = savedRecords.length + (savedRecords.length === 1 ? " record" : " records");
  if (!savedRecords.length) {
    tb.innerHTML = `<tr class="empty-row"><td colspan="5"><div class="empty"><div class="empty-ic">${IC.set}</div><h4>No local records</h4><p>Click "Add Record" to create a static DNS entry answered locally before forwarding.</p></div></td></tr>`;
    return;
  }
  tb.innerHTML = savedRecords.map((r, i) => {
    const t = recordTypeLabel(r.type);
    return `<tr>
      <td><span class="mono">${esc(r.domain)}</span></td>
      <td>${t}</td>
      <td><span class="mono">${esc(r.value)}</span></td>
      <td class="num mono">${r.ttl > 0 ? r.ttl : "—"}</td>
      <td>
        <div class="row-actions">
          <button class="icon-btn" data-r-act="edit" data-r-i="${i}" title="Edit">${IC.edit}</button>
          <button class="icon-btn" data-r-act="del" data-r-i="${i}" title="Delete">${IC.trash}</button>
        </div>
      </td>
    </tr>`;
  }).join("");
}

async function saveRecords() {
  const st = $("r-save-status");
  st.textContent = "saving…";
  try {
    const r = await API("/api/records", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ records: savedRecords }) });
    const d = await r.json();
    const applied = d.applied || {};
    const ids = Object.keys(applied);
    const ok = ids.filter((k) => applied[k] === "ok").length;
    const failed = ids.filter((k) => applied[k] !== "ok");
    st.textContent = ids.length ? `saved on blipc · pushed to ${ok}/${ids.length} instance${ids.length > 1 ? "s" : ""}` + (failed.length ? ` · errors: ${failed.map((k) => k + ": " + applied[k]).join(", ")}` : "") : "saved on blipc · no instance to push to yet";
    toast("records saved" + (ids.length ? ` (${ok}/${ids.length})` : ""));
    st.textContent = "";
  } catch (e) { st.textContent = ""; toast("save failed: " + e.message, "err"); }
}

function openRecordModal(idx) {
  const modal = $("modal-record");
  const inputs = { domain: $("r-domain"), type: $("r-type"), value: $("r-value"), ttl: $("r-ttl") };
  if (idx >= 0) {
    rEditIndex = idx;
    $("r-modal-title").textContent = "Edit Record";
    const r = savedRecords[idx];
    inputs.domain.value = r.domain;
    inputs.type.value = r.type || "A";
    inputs.value.value = r.value;
    inputs.ttl.value = r.ttl > 0 ? r.ttl : "";
  } else {
    rEditIndex = -1;
    $("r-modal-title").textContent = "Add Record";
    inputs.domain.value = "";
    inputs.type.value = "A";
    inputs.value.value = "";
    inputs.ttl.value = "";
  }
  show("modal-record");
}

function saveRecord() {
  const domain = ($("r-domain").value || "").trim();
  const typ = $("r-type").value;
  const value = ($("r-value").value || "").trim();
  const ttlStr = $("r-ttl").value.trim();
  if (!domain || !value) {
    toast("domain and value are required", "err");
    return;
  }
  const ttl = ttlStr === "" ? 0 : Math.max(0, parseInt(ttlStr, 10));
  const rec = { domain, type: typ, value, ttl };
  if (rEditIndex >= 0) {
    savedRecords[rEditIndex] = rec;
  } else {
    savedRecords = [...savedRecords, rec];
  }
  hide("modal-record");
  renderRecords();
  saveRecords();
}

$("r-type").addEventListener("change", () => {
  // Reset the value placeholder to guide the user for the selected type.
  const v = $("r-value");
  if (!v.value) v.placeholder = recordValuePlaceholder($("r-type").value);
});

$("r-add-btn").onclick = () => openRecordModal(-1);
$("r-save").onclick = saveRecord;
async function loadRecords() {
  try {
    const res = await API("/api/records");
    const d = await res.json();
    savedRecords = (d.records || []).map((r) => ({ ...r }));
    renderRecords();
  } catch (e) { toast("failed to load records: " + e.message, "err"); }
}
$("r-refresh").onclick = loadRecords;
$("r-tbody").addEventListener("click", (e) => {
  const b = e.target.closest("[data-r-act]");
  if (!b) return;
  const i = parseInt(b.dataset.rI, 10);
  if (b.dataset.rAct === "edit") openRecordModal(i);
  else if (b.dataset.rAct === "del") {
    confirmDialog("Delete record?", `Remove ${savedRecords[i].domain} (${savedRecords[i].type})?`, () => {
      savedRecords = savedRecords.filter((_, k) => k !== i);
      renderRecords();
      saveRecords();
    });
  }
});

/* ---------- cache stats ---------- */
let csState = { since: "24h", page: 0 };
const CS_PAGE = 25;
async function renderCacheStats() {
  try {
    const res = await API(`/api/cache-stats?since=${csState.since}&limit=${CS_PAGE}&offset=${csState.page * CS_PAGE}`);
    const d = await res.json();
    const total = d.total || { queries: 0, cached_queries: 0, percent_cached: 0, avg_cached_us: 0, avg_fetched_us: 0 };
    const hint = "resolved (non-blocked) queries · last " + csState.since;
    $("cs-hint").textContent = hint;
    $("cs-pct").textContent = total.queries ? total.percent_cached.toFixed(1) + "%" : "—";
    $("cs-cached").textContent = total.queries ? fmt(total.cached_queries) + " / " + fmt(total.queries) : "—";
    const cachedMs = total.avg_cached_us ? fmtLat(total.avg_cached_us) : null;
    const fetchedMs = total.avg_fetched_us ? fmtLat(total.avg_fetched_us) : null;
    $("cs-latency").textContent = cachedMs || fetchedMs ? (cachedMs || "—") + " / " + (fetchedMs || "—") : "—";
    $("cs-latency-sub").textContent = "cached / fresh";
    let live = 0, limit = 0;
    for (const i of instances) {
      live += Number(i.stats && i.stats.cached) || 0;
      limit += Number(i.stats && i.stats.cache_size) || 0;
    }
    $("cs-live").textContent = fmt(live);
    $("cs-limit").textContent = limit ? fmt(limit) : "unlimited";
    const tb = $("cs-tbody");
    const per = d.per_instance || {};
    const keys = Object.keys(per);
    if (!keys.length) {
      tb.innerHTML = `<tr class="empty-row"><td colspan="7"><div class="empty"><div class="empty-ic">${IC.cache}</div><h4>No data yet</h4><p>No resolved queries in this window.</p></div></td></tr>`;
    } else {
    let rows = "";
    for (const id of keys) {
      const c = per[id];
      const is = instances.find((x) => x.id === id || (x.label || "") === id);
      const label = (is && is.label) || id;
      const liveN = Number(is && is.stats && is.stats.cached) || 0;
      const limitN = Number(is && is.stats && is.stats.cache_size) || 0;
      const pct = c.queries ? c.percent_cached.toFixed(1) + "%" : "—";
      const cMs = c.avg_cached_us ? fmtLat(c.avg_cached_us) : "—";
      const fMs = c.avg_fetched_us ? fmtLat(c.avg_fetched_us) : "—";
      rows += `<tr>
        <td>${esc(label)}</td>
        <td class="num">${fmt(liveN)}${limitN ? " / " + fmt(limitN) : ""}</td>
        <td class="num">${fmt(c.cached_queries)}</td>
        <td class="num">${fmt(c.queries)}</td>
        <td class="num">${pct}</td>
        <td class="num mono">${cMs}</td>
        <td class="num mono">${fMs}</td>
      </tr>`;
    }
    tb.innerHTML = rows;
    }
    renderTopCachedDomains(d.top_cached || [], d.top_cached_total || 0);
  } catch (e) {
    $("cs-tbody").innerHTML = `<tr class="empty-row"><td colspan="7"><div class="empty"><div class="empty-ic">${IC.warn}</div><h4>Cache stats unavailable</h4><p>${esc(e.message)}</p></div></td></tr>`;
  }
}

/* ---------- cache stats: top cached domains ---------- */
function renderTopCachedDomains(list, total) {
  const tb = $("cs-top-cached-tbody");
  if (!list.length) {
    tb.innerHTML = `<tr class="empty-row"><td colspan="5"><div class="empty"><div class="empty-ic">${IC.cache}</div><h4>No data yet</h4><p>No resolved queries in this window.</p></div></td></tr>`;
  } else {
    let rows = "";
    for (const d of list) {
      const rate = d.hit_rate.toFixed(0) + "%";
      const ms = d.avg_cached_us ? fmtLat(d.avg_cached_us) : "—";
      rows += `<tr>
        <td>${esc(d.domain)}</td>
        <td class="num">${fmt(d.cache_hits)}</td>
        <td class="num">${fmt(d.cache_misses)}</td>
        <td class="num">${rate}</td>
        <td class="num mono">${ms}</td>
      </tr>`;
    }
    tb.innerHTML = rows;
  }
  const totalPages = total > 0 ? Math.ceil(total / CS_PAGE) : 1;
  const page = csState.page;
  const info = total > 0 ? `Showing ${page * CS_PAGE + 1}–${Math.min((page + 1) * CS_PAGE, total)} of ${fmt(total)}` : "No domains";
  $("cs-pages").textContent = info;
  $("cs-prev").disabled = page === 0;
  $("cs-next").disabled = page >= totalPages - 1;
}

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
let blDisabled = new Set();
let blStatus = { running: false, domains: 0 };
let blStatusTimer = null;
const BL_PAGE_SIZE = 100;
let blPage = 0;
let blAllowPage = 0;
async function loadBlocklist() {
  try {
    const r = await API("/api/blocklist?limit=2000");
    const d = await r.json();
    blDomains = d.domains || [];
    blAllowed = d.allowed || [];
    if (Array.isArray(d.sources)) blSources = d.sources.slice();
    if (d.status) blStatus = d.status;
    blDisabled = new Set((d.status && d.status.disabled) || []);
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
    renderPager("bl-pager", list, 0, blPage, (p) => { blPage = p; renderBlocklist(); });
    return;
  }
  const pages = Math.ceil(list.length / BL_PAGE_SIZE);
  if (blPage >= pages) blPage = pages - 1;
  const start = blPage * BL_PAGE_SIZE;
  ul.innerHTML = list.slice(start, start + BL_PAGE_SIZE).map((d) => `<li><span class="mono grow">${esc(d)}</span><button class="icon-btn" data-rm="${esc(d)}" title="Remove">${IC.trash}</button></li>`).join("");
  ul.querySelectorAll("[data-rm]").forEach((b) => b.onclick = async () => {
    try { await API("/api/blocklist", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: b.dataset.rm }) }); toast("removed " + b.dataset.rm); loadBlocklist(); }
    catch (e) { toast("remove failed", "err"); }
  });
  renderPager("bl-pager", list, pages, blPage, (p) => { blPage = p; renderBlocklist(); });
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
    renderPager("bl-pager-allow", list, 0, blAllowPage, (p) => { blAllowPage = p; renderAllowList(); });
    return;
  }
  const pages = Math.ceil(list.length / BL_PAGE_SIZE);
  if (blAllowPage >= pages) blAllowPage = pages - 1;
  const start = blAllowPage * BL_PAGE_SIZE;
  ul.innerHTML = list.slice(start, start + BL_PAGE_SIZE).map((d) => `<li><span class="mono grow">${esc(d)}</span><button class="icon-btn" data-rm-allow="${esc(d)}" title="Remove">${IC.trash}</button></li>`).join("");
  ul.querySelectorAll("[data-rm-allow]").forEach((b) => b.onclick = async () => {
    try { await API("/api/blocklist", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: b.dataset.rmAllow, allow: true }) }); toast("removed " + b.dataset.rmAllow); loadBlocklist(); }
    catch (e) { toast("remove failed", "err"); }
  });
  renderPager("bl-pager-allow", list, pages, blAllowPage, (p) => { blAllowPage = p; renderAllowList(); });
}
function renderPager(elId, list, pages, cur, goto) {
  const el = $(elId);
  if (!el) return;
  if (pages <= 1) { el.style.display = "none"; el.innerHTML = ""; return; }
  el.style.display = "flex";
  el.innerHTML = `<span class="pager-info">${fmt(list.length)} domain${list.length === 1 ? "" : "s"} · page ${cur + 1} of ${pages}</span><span class="pager-btns"><button data-pg="prev" ${cur === 0 ? "disabled" : ""}>← Prev</button><button data-pg="next" ${cur >= pages - 1 ? "disabled" : ""}>Next →</button></span>`;
  el.querySelector("[data-pg='prev']").onclick = () => { if (cur > 0) goto(cur - 1); };
  el.querySelector("[data-pg='next']").onclick = () => { if (cur < pages - 1) goto(cur + 1); };
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
        const off = blDisabled.has(u);
        const status = off ? `<span class="badge">disabled</span>`
          : err ? `<span class="badge err" title="${esc(err)}">error</span>`
          : n ? `<span class="badge on"><span class="dot on"></span>active</span>`
          : `<span class="badge">new</span>`;
        return `<tr${off ? ` class="bl-src-off"` : ""}>
          <td>
            <div class="bl-src-name">
              <span class="bl-src-fav">${IC.globe}</span>
              <span class="mono" title="${esc(u)}">${esc(u)}</span>
            </div>
            ${err ? `<div class="cell-sub bl-src-err">${esc(err)}</div>` : ""}
          </td>
          <td class="num"><span class="bl-src-domains">${n ? fmt(n) : "—"}</span></td>
          <td class="cell-sub">${upd}</td>
          <td>${status}</td>
          <td style="text-align:right">
            <label class="switch" title="${off ? "Enable source" : "Disable source"}">
              <input type="checkbox" data-tgl-src="${esc(u)}" ${off ? "" : "checked"}/><i></i>
            </label>
            <button class="icon-btn" data-rm-src="${esc(u)}" title="Remove source" style="width:28px;height:28px">${IC.x}</button>
          </td>
        </tr>`;
      }).join("");
    }
    tb.querySelectorAll("[data-tgl-src]").forEach((b) => b.onchange = () => toggleSource(b.dataset.tglSrc));
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
  const enabled = blSources.length - blDisabled.size;

  const sd = $("bl-stat-domains");
  if (sd) sd.textContent = fmt(blStatus.domains || 0);
  const ss = $("bl-stat-sources");
  if (ss) ss.textContent = blSources.length;
  const sss = $("bl-stat-sources-sub");
  if (sss) sss.textContent = `${enabled} enabled${blDisabled.size ? ` · ${blDisabled.size} disabled` : ""}`;
  const su = $("bl-stat-updated");
  if (su) su.textContent = validDate(blStatus.last_update) ? relTime(blStatus.last_update) : "—";
  const sus = $("bl-stat-updated-sub");
  if (sus) sus.textContent = validDate(blStatus.last_update) ? new Date(blStatus.last_update).toLocaleString() : "no updates yet";
  const sn = $("bl-stat-next");
  if (sn) sn.textContent = validDate(blNextUpdate) ? relTime(blNextUpdate) : "—";
  const sns = $("bl-stat-next-sub");
  if (sns) sns.textContent = blAutoHours ? `every ${blAutoHours}h` : "auto-update off";

  const bar = $("bl-import-bar-fill");
  const bwrap = $("bl-import-progress");
  const btxt = $("bl-import-bar-text");
  if (blStatus.running) {
    if (bwrap) bwrap.style.display = "flex";
    const n = blStatus.source_total || blSources.length || 1;
    const done = blStatus.source_done || 0;
    if (bar) bar.style.width = Math.min(100, Math.round((done / n) * 100)) + "%";
    if (btxt) btxt.textContent = `${done}/${n} sources${blStatus.current_url ? " · " + esc(blStatus.current_url) : ""}`;
  } else if (bwrap) {
    bwrap.style.display = "none";
  }

  if (st) {
    if (blStatus.running) {
      st.innerHTML = `<b>Syncing…</b> ${blStatus.source_done || 0}/${blStatus.source_total || blSources.length || 1} ${esc(blStatus.current_url || "")} · <b>${fmt(blStatus.domains)}</b> domains`;
    } else if (validDate(blStatus.last_update)) {
      const errs = (blStatus.errors || []).filter(Boolean).length;
      let txt = `${fmt(blStatus.domains)} domains · updated ${esc(new Date(blStatus.last_update).toLocaleTimeString())}`;
      if (validDate(blNextUpdate)) txt += ` · auto next ${esc(new Date(blNextUpdate).toLocaleString())}`;
      st.innerHTML = txt + (errs ? ` · <span style="color:var(--red)">${errs} error${errs > 1 ? "s" : ""}</span>` : "");
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
  blDisabled.delete(u);
  renderSources();
}
async function toggleSource(u) {
  const enable = blDisabled.has(u);
  try {
    await API("/api/blocklist/source", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: u, enabled: enable }) });
    if (enable) blDisabled.delete(u); else blDisabled.add(u);
    toast(enable ? "source enabled — re-importing" : "source disabled — re-importing");
    renderSources();
    startBlStatusPoll();
  } catch (e) { toast("failed to toggle source: " + e.message, "err"); }
}
function startBlStatusPoll() {
  if (blStatusTimer) return;
  blStatusTimer = setInterval(async () => {
    if (current !== "blocklist") return;
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
/* ---------- upstream editor (named servers + conditional forwarding) ---------- */
// A server is {name, address, priority}. priority 0 = route-only (never part
// of the automatic rotation); 1+ = auto-failover order (lower first).
function serverRow(u) {
  const row = document.createElement("div");
  row.className = "row up-row";
  row.innerHTML = `
    <input class="input up-name" placeholder="name (e.g. quad9)" style="width:120px" value="${esc(u.name || "")}"/>
    <input class="input grow up-addr" placeholder="9.9.9.9 (udp:53) or https://1.1.1.1/dns-query" value="${esc(u.address || "")}"/>
    <input class="input up-prio" type="number" min="0" title="Priority — lower = higher priority; 0 = route-only" style="width:72px" value="${u.priority ?? ""}"/>
    <input class="input up-timeout" type="number" min="1" title="Seconds to wait before failing over to the next server (default 5)" style="width:72px" placeholder="5" value="${u.timeout_sec ?? ""}"/>
    <button class="icon-btn up-del" title="Remove">${IC.trash}</button>`;
  row.querySelector(".up-del").onclick = () => { row.remove(); refreshRouteServerOptions(); };
  return row;
}
function renderServerList(list) {
  const wrap = $("s-upstream-list");
  wrap.innerHTML = "";
  for (const u of list) wrap.appendChild(serverRow(u));
  if (!list.length) wrap.innerHTML = `<div class="hint" style="padding:2px 0 6px">No named resolvers — the automatic rotation is disabled.</div>`;
}
function collectServers() {
  return [...document.querySelectorAll("#s-upstream-list .up-row")].map((row) => ({
    name: row.querySelector(".up-name").value.trim(),
    address: row.querySelector(".up-addr").value.trim(),
    priority: parseInt(row.querySelector(".up-prio").value, 10) || 0,
    timeout_sec: parseInt(row.querySelector(".up-timeout").value, 10) || 0,
  })).filter((s) => s.address !== "");
}
// A route is {name, qname_suffix, server, client_cidr, disabled}. server
// references a named server by name; matching queries are forwarded to it.
// The leading checkbox is the enable/disable switch (a disabled route is kept
// but never matches queries).
function routeRow(r, serverOpts) {
  const row = document.createElement("div");
  row.className = "row cf-row";
  const opts = serverOpts.map((s) => `<option value="${esc(s.name)}" ${s.name === r.server ? "selected" : ""}>${esc(s.name || "server#" + s.address)}</option>`).join("");
  const extra = r.server && !serverOpts.some((s) => s.name === r.server) ? `<option value="${esc(r.server)}" selected>${esc(r.server)}</option>` : "";
  const fallback = opts ? "" : `<option value="">(add a server first)</option>`;
  const on = !r.disabled ? "checked" : "";
  row.innerHTML = `
    <input class="cf-on" type="checkbox" title="Enabled — off keeps the rule but it never matches" ${on} style="width:16px"/>
    <input class="input cf-name" placeholder="label" style="width:90px" value="${esc(r.name || "")}"/>
    <input class="input grow cf-suffix" placeholder=".corp." title="Query name suffix to match (trailing dot optional)" value="${esc(r.qname_suffix || "")}"/>
    <select class="select cf-server" style="width:150px">${extra}${opts}${fallback}</select>
    <input class="input cf-cidr" placeholder="10.0.0.0/8" title="Client source CIDR (blank = all clients)" style="width:120px" value="${esc(r.client_cidr || "")}"/>
    <button class="icon-btn cf-del" title="Remove">${IC.trash}</button>`;
  row.querySelector(".cf-del").onclick = () => row.remove();
  return row;
}
// defaultLocalPTRRoute is the built-in "local PTR forwarding" rule: reverse-DNS
// lookups forwarded to a local resolver (the operator picks it from the server
// dropdown). Seeded as a default rule, disabled, in the fleet-wide editor.
function defaultLocalPTRRoute() {
  return { name: "local-ptr", qname_suffix: ".in-addr.arpa.", server: "", client_cidr: "", disabled: true };
}
function renderRouteList(routes, serverOpts, seedDefault) {
  const wrap = $("s-cf-list");
  wrap.innerHTML = "";
  if (!routes.length && seedDefault) routes = [defaultLocalPTRRoute()];
  for (const r of routes) wrap.appendChild(routeRow(r, serverOpts));
  if (!routes.length) wrap.innerHTML = `<div class="hint" style="padding:2px 0 6px">No conditional-forwarding routes — matching queries use the automatic rotation.</div>`;
}
function collectRoutes() {
  return [...document.querySelectorAll("#s-cf-list .cf-row")].map((row) => ({
    name: row.querySelector(".cf-name").value.trim(),
    qname_suffix: row.querySelector(".cf-suffix").value.trim(),
    server: row.querySelector(".cf-server").value,
    client_cidr: row.querySelector(".cf-cidr").value.trim(),
    disabled: !row.querySelector(".cf-on").checked,
  })).filter((r) => r.qname_suffix !== "" || r.server !== "");
}
// refreshRouteServerOptions re-populates every conditional-forwarding server
// dropdown with the servers currently in the editor (after adding/removing a
// server row) so a newly added resolver shows up without a page refresh. Each
// route keeps its current selection; a referenced-but-deleted server is kept so
// the rule doesn't silently change.
function refreshRouteServerOptions() {
  const servers = collectServers();
  const options = servers.map((s) => `<option value="${esc(s.name)}">${esc(s.name || "server#" + s.address)}</option>`).join("");
  const fallback = options ? "" : `<option value="">(add a server first)</option>`;
  document.querySelectorAll("#s-cf-list .cf-row .cf-server").forEach((sel) => {
    const cur = sel.value;
    const extra = cur && !servers.some((s) => s.name === cur) ? `<option value="${esc(cur)}" selected>${esc(cur)}</option>` : "";
    sel.innerHTML = extra + options + fallback;
    sel.value = cur;
  });
}
let savedOverrides = {};       // sparse per-instance overrides keyed by instance id
let scopeState = "default";    // "default" or an instance id
let savedUpServers = [];       // fleet-wide default named servers
let savedUpRoutes = [];        // fleet-wide default conditional-forwarding routes
let savedUpBootstrap = [];     // fleet-wide default bootstrap DNS resolvers

// visibleUpServers/visibleUpRoutes/visibleUpBootstrap return what the editor
// should show for a scope: the fleet default at "default", otherwise only the
// instance's own override (blank = inherits the fleet default).
function visibleUpServers(scope) {
  if (scope === "default") return savedUpServers;
  const o = savedOverrides[scope];
  return Array.isArray(o && o.upstream_servers) ? o.upstream_servers : [];
}
function visibleUpRoutes(scope) {
  if (scope === "default") return savedUpRoutes;
  const o = savedOverrides[scope];
  return Array.isArray(o && o.upstream_routes) ? o.upstream_routes : [];
}
function visibleUpBootstrap(scope) {
  if (scope === "default") return savedUpBootstrap;
  const o = savedOverrides[scope];
  return Array.isArray(o && o.upstream_bootstrap) ? o.upstream_bootstrap : [];
}
// effectiveUpServers is the full pool an instance would run (override or fleet
// default) — used to populate the route-server dropdown.
function effectiveUpServers(scope) {
  if (scope === "default") return savedUpServers;
  const o = savedOverrides[scope];
  return Array.isArray(o && o.upstream_servers) ? o.upstream_servers : savedUpServers;
}
// upsertOverrideField updates one field of the local override mirror; an empty
// value clears the field (and the whole override when nothing is left).
function upsertOverrideField(id, field, value) {
  const o = { ...(savedOverrides[id] || {}) };
  if (value.length) o[field] = value;
  else delete o[field];
  if (Object.keys(o).length) savedOverrides[id] = o;
  else delete savedOverrides[id];
}

// ---- Bootstrap DNS editor ----
// A bootstrap resolver is just an address string: "1.1.1.1" (UDP) or
// "https://1.1.1.1/dns-query" (DoH). Used to resolve the hostname of a DoH
// upstream server before dialing it.
function bootstrapRow(b) {
  const row = document.createElement("div");
  row.className = "row up-row";
  row.innerHTML = `
    <input class="input grow boot-addr" placeholder="1.1.1.1 (udp:53) or https://1.1.1.1/dns-query" value="${esc(b.address || "")}"/>
    <button class="icon-btn boot-del" title="Remove">${IC.trash}</button>`;
  row.querySelector(".boot-del").onclick = () => row.remove();
  return row;
}
function renderBootstrapList(list) {
  const wrap = $("s-boot-list");
  wrap.innerHTML = "";
  for (const b of list) wrap.appendChild(bootstrapRow(b));
  if (!list.length) wrap.innerHTML = `<div class="hint" style="padding:2px 0 6px">No bootstrap resolvers — a DoH server hostname is resolved via the system resolver.</div>`;
}
function collectBootstrap() {
  return [...document.querySelectorAll("#s-boot-list .up-row")].map((row) => ({
    address: row.querySelector(".boot-addr").value.trim(),
  })).filter((b) => b.address !== "");
}


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

// Response-cache editor state
let savedCacheSize = 0;          // fleet-wide max cached responses (0 = unlimited)
let savedCacheWarm = 0;          // fleet-wide auto-refresh count (0 = off)
let savedCacheRegular = 0;       // fleet-wide regular-hold seconds for non-top entries (0 = record TTL)
let savedQLRetention = 720;      // how long query log entries are kept (hours)
let savedReleaseChannel = "stable";
let cacheScopeState = "default"; // "default" or an instance id
function renderCacheScopeSelect() {
  const sel = $("s-cache-scope");
  sel.innerHTML = "";
  const opt = (v, label) => {
    const o = document.createElement("option");
    o.value = v; o.textContent = label; sel.appendChild(o);
  };
  opt("default", "Fleet-wide default");
  for (const i of instances) {
    const o = savedOverrides[i.id] || {};
    const has = o.cache_size != null || o.cache_warm != null || o.cache_regular != null;
    opt(i.id, "instance: " + (i.label || i.id) + (has ? " (custom)" : ""));
  }
  if (!instances.some((i) => i.id === cacheScopeState)) cacheScopeState = "default";
  sel.value = cacheScopeState;
}
function cacheLiveTotal() {
  let t = 0;
  for (const i of instances) t += Number(i.stats && i.stats.cached) || 0;
  return t;
}
function loadCacheEditor() {
  renderCacheScopeSelect();
  const sizeIn = $("s-cache-size");
  const warmIn = $("s-cache-warm");
  const regularIn = $("s-cache-regular");
  const cur = $("s-cache-cur");
  const badge = $("s-cache-badge");
  const hint = $("s-cache-scope-hint");
  const hasOverride = (id) => { const o = savedOverrides[id] || {}; return o.cache_size != null || o.cache_warm != null || o.cache_regular != null; };
  if (cacheScopeState === "default") {
    badge.textContent = "fleet-wide";
    badge.className = "badge accent";
    sizeIn.value = savedCacheSize > 0 ? savedCacheSize : "";
    warmIn.value = savedCacheWarm > 0 ? savedCacheWarm : "";
    regularIn.value = savedCacheRegular > 0 ? savedCacheRegular : "";
    cur.textContent = cacheLiveTotal() ? cacheLiveTotal() + " entries cached now" : "nothing cached yet";
    hint.textContent = "Applies to every instance that doesn't have its own override.";
  } else {
    badge.textContent = "instance";
    badge.className = "badge purple";
    const o = savedOverrides[cacheScopeState] || {};
    const set = hasOverride(cacheScopeState);
    sizeIn.value = set && o.cache_size > 0 ? o.cache_size : "";
    warmIn.value = set && o.cache_warm > 0 ? o.cache_warm : "";
    regularIn.value = set && o.cache_regular > 0 ? o.cache_regular : "";
    cur.textContent = "Blank = inherit the fleet-wide default.";
    hint.textContent = "Only for this instance. Blank fields inherit the fleet-wide default.";
  }
}

function renderDoHScopeSelect() {  const sel = $("s-doh-scope");
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
  const cfBadge = $("s-cf-badge");
  const bootBadge = $("s-boot-badge");
  const hint = $("s-scope-hint");
  const cfHint = $("s-cf-hint");
  const upHint = $("s-up-hint");
  const bootHint = $("s-boot-hint");
  if (scopeState === "default") {
    badge.textContent = "fleet-wide";
    badge.className = "badge accent";
    cfBadge.textContent = "fleet-wide";
    cfBadge.className = "badge accent";
    bootBadge.textContent = "fleet-wide";
    bootBadge.className = "badge accent";
    hint.textContent = "Applies to every instance that doesn't have its own override.";
    cfHint.textContent = "Matching queries are forwarded to the named server. Routes reference the servers above; a default disabled local-PTR rule is pre-seeded for you.";
    upHint.textContent = "priority 1+ servers form the automatic failover rotation; priority 0 servers are used only by conditional-forwarding routes.";
    bootHint.textContent = "Resolve the hostname of a DoH server above through these resolvers before dialing it. Each can be UDP (\"1.1.1.1\") or DoH (\"https://1.1.1.1/dns-query\").";
    renderServerList(savedUpServers);
    renderRouteList(savedUpRoutes, savedUpServers, true);
    renderBootstrapList(savedUpBootstrap);
  } else {
    badge.textContent = "instance";
    badge.className = "badge purple";
    cfBadge.textContent = "instance";
    cfBadge.className = "badge purple";
    bootBadge.textContent = "instance";
    bootBadge.className = "badge purple";
    hint.textContent = "Only for this instance. Fields you leave blank inherit the fleet-wide default.";
    cfHint.textContent = "Only for this instance. Blank = inherit the fleet-wide default.";
    upHint.textContent = "Blank = inherit the fleet-wide server pool.";
    bootHint.textContent = "Only for this instance. Blank = inherit the fleet-wide bootstrap resolvers.";
    const o = savedOverrides[scopeState] || {};
    renderServerList(Array.isArray(o.upstream_servers) ? o.upstream_servers : []);
    const routes = Array.isArray(o.upstream_routes) ? o.upstream_routes : [];
    renderRouteList(routes, effectiveUpServers(scopeState));
    renderBootstrapList(Array.isArray(o.upstream_bootstrap) ? o.upstream_bootstrap : []);
  }
}

async function refreshSettings() {
  loadControllerUpdate();
  $("s-inst-count").textContent = instances.length + (instances.some((i) => i.online) ? " (" + instances.filter((i) => i.online).length + " online)" : "");
  // The fleet config lives on blipc (default policy + sparse per-instance
  // overrides) and is distributed to the instances.
  try {
    const r = await API("/api/settings");
    const d = await r.json();
    savedOverrides = d.instance_overrides || {};
    // fleet-wide plain-HTTP DoH address ("" = off)
    savedFleetDoH = (d.doh_http_addr != null && d.doh_http_addr !== undefined) ? (d.doh_http_addr || "") : "";
    savedRLQPS = (d.rate_limit_qps != null && d.rate_limit_qps !== undefined) ? Number(d.rate_limit_qps || 0) : 0;
    savedCacheSize = (d.cache_size != null && d.cache_size !== undefined) ? Number(d.cache_size || 0) : 0;
    savedCacheWarm = (d.cache_warm != null && d.cache_warm !== undefined) ? Number(d.cache_warm || 0) : 0;
    savedCacheRegular = (d.cache_regular != null && d.cache_regular !== undefined) ? Number(d.cache_regular || 0) : 0;
    savedQLRetention = (d.query_log_retention_hours != null && d.query_log_retention_hours !== undefined) ? Number(d.query_log_retention_hours || 720) : 720;
    savedReleaseChannel = d.release_channel === "dev" ? "dev" : "stable";
    loadReleaseEditor();
    // fleet-wide local DNS records
    savedRecords = (d.records || []).map((r) => ({ ...r }));
    // fleet-wide default upstream pool + conditional-forwarding routes + bootstrap
    savedUpServers = Array.isArray(d.upstream_servers) ? d.upstream_servers : [];
    savedUpRoutes = Array.isArray(d.upstream_routes) ? d.upstream_routes : [];
    savedUpBootstrap = Array.isArray(d.upstream_bootstrap) ? d.upstream_bootstrap : [];
    // carry over any per-instance doh_http_addr not already surfaced
    loadScopeEditor();
    loadDoHEditor();
    loadRlEditor();
    loadCacheEditor();
    loadQLEditor();
    $("s-up-status").textContent = "";
  } catch {}
}

/* ---------- confirm dialog ---------- */
let _cfOk = null;
function confirmDialog(title, msg, onOk) {
  $("cf-title").textContent = title;
  $("cf-msg").textContent = msg;
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
$("update-instances-btn").onclick = () => {
  confirmDialog("Update all instances?", "Instances will update one at a time. Each node must return online before the next node is touched; the job stops on failure.", async () => {
    const b = $("update-instances-btn");
    b.disabled = true;
    b.textContent = "Updating…";
    try {
      const r = await API("/api/instances/update", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ channel: savedReleaseChannel }) });
      const d = await r.json();
      fleetUpdateJob = d;
      toast(`serialized update started (${d.channel || savedReleaseChannel})`, "ok");
      if (current === "instances") renderInstances();
      pollUpdateJob();
    } catch (e) { toast("update failed: " + e.message, "err"); }
    finally { b.disabled = false; b.textContent = "Update all"; }
  });
};

let updatePollTimer = null;
let fleetUpdateJob = { running: false, current: "" };
async function pollUpdateJob() {
  if (updatePollTimer) clearTimeout(updatePollTimer);
  try {
    const r = await API("/api/instances/update");
    const d = await r.json();
    fleetUpdateJob = d;
    const b = $("update-instances-btn");
    if (d.running) {
      b.disabled = true;
      b.textContent = d.current ? `Updating ${d.current}…` : "Updating…";
      if (current === "instances") renderInstances();
      updatePollTimer = setTimeout(pollUpdateJob, 3000);
      return;
    }
    if (d.error) toast("serialized update stopped: " + d.error, "err");
    else if (d.finished_at) toast(`serialized update complete (${d.completed}/${d.total})`, "ok");
    b.disabled = false;
    b.textContent = "Update all";
    refresh();
  } catch (e) {
    updatePollTimer = setTimeout(pollUpdateJob, 5000);
  }
}
$("i-save").onclick = saveInstance;
$("inst-filter").addEventListener("input", renderInstances);

/* instance row actions (event delegation) */
$("inst-tbody").addEventListener("click", (e) => {
  const b = e.target.closest("[data-act]"); if (!b) return;
  const id = b.dataset.id;
  const act = b.dataset.act;
  if (act === "policies") openPolicyModal(id);
  else if (act === "edit") editLabel(id);
  else if (act === "restart") restartInstance(id);
  else if (act === "remove") confirmRemove(id);
});

async function restartInstance(id) {
  const i = instances.find((x) => x.id === id); if (!i) return;
  confirmDialog(`Restart ${i.label || i.id}?`, "blipd on this node will restart; DNS served by it drops for a few seconds. Use HA for zero-downtime.", async () => {
    try {
      await API("/api/instances/restart", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id }) });
      toast("restarting " + (i.label || i.id) + "…");
      setTimeout(refresh, 1500);
    } catch (e) { toast("restart failed: " + e.message, "err"); }
  });
}

/* queries */
$("q-filter").addEventListener("input", debounce((e) => { qState.filter = e.target.value; renderQueries(); }, 300));
$("q-instance").addEventListener("change", (e) => { qState.inst = e.target.value; renderQueries(); });
$("q-refresh").onclick = renderQueries;

/* upstream errors */
$("ue-instance").addEventListener("change", (e) => { ueState.inst = e.target.value; renderUpstreamErrors(); });
$("ue-range").addEventListener("change", (e) => { ueState.since = e.target.value; renderUpstreamErrors(); });
$("ue-refresh").onclick = renderUpstreamErrors;
$("ue-clear").onclick = () => {
  const scope = ueState.inst ? ` for "${ueState.inst}"` : "";
  confirmDialog("Clear upstream errors?", `Removes the recorded upstream failures${scope}. This cannot be undone.`, async () => {
    try {
      await API("/api/maintenance", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: "clear_upstream_errors", instance: ueState.inst }) });
      toast("upstream errors cleared");
      renderUpstreamErrors();
    } catch (e) { toast("clear failed: " + e.message, "err"); }
  });
};

/* cache stats */
$("cs-range").addEventListener("change", (e) => { csState.since = e.target.value; csState.page = 0; renderCacheStats(); });
$("cs-prev").addEventListener("click", () => { if (csState.page > 0) { csState.page--; renderCacheStats(); } });
$("cs-next").addEventListener("click", () => { csState.page++; renderCacheStats(); });
$("q-tbody").addEventListener("click", (e) => {
  const c = e.target.closest("[data-copy]"); if (!c) return;
  copyText(c.dataset.copy);
});
// Query-log info tooltip: a floating panel (appended to <body> so it is not
// clipped by the table's scroll container) that shows which upstream answered
// a query or which list blocked it when hovering the info icon on a row.
const qTip = (() => {
  const el = document.createElement("div");
  el.className = "q-tip";
  el.style.display = "none";
  document.body.appendChild(el);
  const hide = () => { el.style.display = "none"; };
  const show = (trigger) => {
    const label = trigger.dataset.tipl || "";
    const value = trigger.dataset.tipv || "";
    if (!label && !value) return hide();
    el.innerHTML = `${label ? `<div class="q-tip-l">${esc(label)}</div>` : ""}<div class="q-tip-v">${esc(value)}</div>`;
    const r = trigger.getBoundingClientRect();
    el.style.display = "block";
    const w = el.offsetWidth, h = el.offsetHeight;
    let x = r.left + r.width / 2 - w / 2;
    x = Math.max(8, Math.min(x, window.innerWidth - w - 8));
    let y = r.bottom + 8;
    if (y + h > window.innerHeight - 8) y = r.top - h - 8;
    el.style.left = x + "px";
    el.style.top = y + "px";
  };
  $("q-tbody").addEventListener("mouseover", (e) => {
    const t = e.target.closest(".q-info");
    if (t) { show(t); return; }
    hide();
  });
  $("q-tbody").addEventListener("mouseout", (e) => {
    if (!e.target.closest(".q-info")) hide();
  });
  return { hide };
})();
// setQueryAction updates the query-log action filter ("" = all, "PASS",
// "BLOCK") and the highlighted segment button, then re-renders. Used by the
// segment buttons and by dashboard links that deep-link into a filtered view.
function setQueryAction(action) {
  qState.action = action;
  document.querySelectorAll("#q-action-seg button").forEach((x) => x.classList.toggle("active", x.dataset.a === action));
  renderQueries();
}
document.querySelectorAll("#q-action-seg button").forEach((b) => b.onclick = () => setQueryAction(b.dataset.a));
$("q-cached").addEventListener("change", (e) => { qState.cached = e.target.value; renderQueries(); });

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
$("bl-filter").addEventListener("input", () => { blPage = 0; renderBlocklist(); });
$("bl-filter-allow").addEventListener("input", () => { blAllowPage = 0; renderAllowList(); });
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

function loadReleaseEditor() {
  const sel = $("s-release-channel");
  const badge = $("s-release-badge");
  if (!sel) return;
  sel.value = savedReleaseChannel;
  if (badge) badge.textContent = savedReleaseChannel === "dev" ? "dev" : "stable";
  loadControllerUpdate();
}

/* ---------- settings tabs (Query Log / DNS / About) ---------- */
(function () {
  const paneOf = {
    "Query Log": "ql", "Reset & destroy": "ql",
    "DoH (DNS over HTTPS)": "dns", "Rate Limit": "dns", "Cache": "dns",
    "Release Channel": "about", "Controller Update": "about", "About": "about"
  };
  const tabs = Array.from(document.querySelectorAll("#settings-tabs .settings-tab"));
  const panels = Array.from(document.querySelectorAll("#view-settings .panel"));
  panels.forEach((p) => {
    const h = p.querySelector("h3");
    if (h) p.dataset.pane = paneOf[h.textContent.trim()] || "dns";
  });
  function apply() {
    const active = document.querySelector("#settings-tabs .settings-tab.active");
    const cur = (active && active.dataset.settingsTab) || "ql";
    panels.forEach((p) => { p.style.display = p.dataset.pane === cur ? "" : "none"; });
  }
  tabs.forEach((b) => b.addEventListener("click", () => {
    tabs.forEach((x) => x.classList.toggle("active", x === b));
    apply();
  }));
  apply();
})();

async function loadControllerUpdate() {
  if (ctrlUpdateTimer) clearTimeout(ctrlUpdateTimer);
  const badge = $("s-ctrl-up-badge");
  const status = $("s-ctrl-up-status");
  const btn = $("s-update-ctrl");
  try {
    const r = await API("/api/update");
    const d = await r.json();
    const st = d.status || {};
    const v = (d.version || "");
    if (st.running) {
      badge.textContent = "updating";
      badge.className = "badge warn";
      btn.disabled = true;
      status.textContent = st.message || "building…";
      ctrlUpdateTimer = setTimeout(loadControllerUpdate, 3000);
      return;
    }
    if (st.last_error) {
      badge.textContent = "update failed";
      badge.className = "badge err";
      status.textContent = st.last_error;
    } else {
      const sha = (v.match(/\+([0-9a-f]{7,})/) || [])[1];
      badge.textContent = sha ? "up to date" : "unknown build";
      badge.className = "badge on";
      status.textContent = "";
      $("s-ctrl-ver").textContent = sha ? v : "blipc";
    }
    btn.disabled = false;
  } catch (e) {
    ctrlUpdateTimer = setTimeout(loadControllerUpdate, 5000);
  }
}

$("s-update-ctrl").onclick = async () => {
  const btn = $("s-update-ctrl");
  const status = $("s-ctrl-up-status");
  btn.disabled = true;
  status.textContent = "starting…";
  try {
    await API("/api/update?channel=" + encodeURIComponent(savedReleaseChannel), { method: "POST" });
    status.textContent = "";
    loadControllerUpdate();
  } catch (e) {
    status.textContent = e.message;
    btn.disabled = false;
  }
};


$("s-save-release").onclick = async () => {
  const channel = $("s-release-channel").value;
  const st = $("s-release-status");
  st.textContent = "saving…";
  try {
    const r = await API("/api/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ release_channel: channel }) });
    const d = await r.json();
    savedReleaseChannel = d.release_channel === "dev" ? "dev" : "stable";
    loadReleaseEditor();
    st.textContent = "saved";
    toast("release channel set to " + savedReleaseChannel);
  } catch (e) { st.textContent = ""; toast("release channel save failed: " + e.message, "err"); }
};

/* policies modal */
$("pol-new").onclick = newPolicy;
$("p-save").onclick = savePolicy;

/* settings */
$("s-up-add").onclick = () => {
  const prios = collectServers().map((s) => s.priority).filter((p) => p > 0);
  $("s-upstream-list").appendChild(serverRow({ name: "", address: "", priority: (prios.length ? Math.max(...prios) + 1 : 1) }));
  // Keep the conditional-forwarding dropdowns in sync so the new server is
  // selectable immediately, without a page refresh.
  refreshRouteServerOptions();
};
$("s-save-upstream").onclick = async () => {
  const servers = collectServers();
  const st = $("s-up-status");
  st.textContent = "saving…";
  let body, msg;
  if (scopeState === "default") {
    body = { upstream_servers: servers };
    msg = servers.length ? "fleet upstream servers saved" : "fleet upstream servers cleared";
  } else {
    body = { scope: "instance", instance: scopeState, upstream_servers: servers };
    msg = servers.length ? "instance upstream servers saved" : "instance upstream servers cleared (inherits fleet)";
  }
  try {
    const r = await API("/api/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    if (scopeState === "default") savedUpServers = servers;
    else upsertOverrideField(scopeState, "upstream_servers", servers);
    const applied = d.applied || {};
    const ids = Object.keys(applied);
    const ok = ids.filter((k) => applied[k] === "ok").length;
    const failed = ids.filter((k) => applied[k] !== "ok");
    st.textContent = ids.length ? `saved on blipc · pushed to ${ok}/${ids.length} instance${ids.length > 1 ? "s" : ""}` + (failed.length ? ` · errors: ${failed.map((k) => k + ": " + applied[k]).join(", ")}` : "") : "saved on blipc · no instance to push to yet";
    toast(msg + (ids.length ? ` (${ok}/${ids.length})` : ""));
    renderScopeSelect();
  } catch (e) { st.textContent = ""; toast("save failed: " + e.message, "err"); }
};
$("s-cf-add").onclick = () => {
  $("s-cf-list").appendChild(routeRow({ name: "", qname_suffix: "", server: "", client_cidr: "" }, effectiveUpServers(scopeState)));
};
$("s-save-cf").onclick = async () => {
  const routes = collectRoutes();
  const st = $("s-cf-status");
  st.textContent = "saving…";
  let body, msg;
  if (scopeState === "default") {
    body = { upstream_routes: routes };
    msg = routes.length ? "fleet conditional forwarding saved" : "fleet conditional forwarding cleared";
  } else {
    body = { scope: "instance", instance: scopeState, upstream_routes: routes };
    msg = routes.length ? "instance conditional forwarding saved" : "instance conditional forwarding cleared (inherits fleet)";
  }
  try {
    const r = await API("/api/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    if (scopeState === "default") savedUpRoutes = routes;
    else upsertOverrideField(scopeState, "upstream_routes", routes);
    const applied = d.applied || {};
    const ids = Object.keys(applied);
    const ok = ids.filter((k) => applied[k] === "ok").length;
    const failed = ids.filter((k) => applied[k] !== "ok");
    st.textContent = ids.length ? `saved on blipc · pushed to ${ok}/${ids.length} instance${ids.length > 1 ? "s" : ""}` + (failed.length ? ` · errors: ${failed.map((k) => k + ": " + applied[k]).join(", ")}` : "") : "saved on blipc · no instance to push to yet";
    toast(msg + (ids.length ? ` (${ok}/${ids.length})` : ""));
    renderScopeSelect();
  } catch (e) { st.textContent = ""; toast("save failed: " + e.message, "err"); }
};
$("s-scope").addEventListener("change", (e) => { scopeState = e.target.value; loadScopeEditor(); });

$("s-boot-add").onclick = () => {
  $("s-boot-list").appendChild(bootstrapRow({ address: "" }));
};
$("s-save-boot").onclick = async () => {
  const bootstrap = collectBootstrap();
  const st = $("s-boot-status");
  st.textContent = "saving…";
  let body, msg;
  if (scopeState === "default") {
    body = { upstream_bootstrap: bootstrap };
    msg = bootstrap.length ? "fleet bootstrap DNS saved" : "fleet bootstrap DNS cleared";
  } else {
    body = { scope: "instance", instance: scopeState, upstream_bootstrap: bootstrap };
    msg = bootstrap.length ? "instance bootstrap DNS saved" : "instance bootstrap DNS cleared (inherits fleet)";
  }
  try {
    const r = await API("/api/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    if (scopeState === "default") savedUpBootstrap = bootstrap;
    else upsertOverrideField(scopeState, "upstream_bootstrap", bootstrap);
    const applied = d.applied || {};
    const ids = Object.keys(applied);
    const ok = ids.filter((k) => applied[k] === "ok").length;
    const failed = ids.filter((k) => applied[k] !== "ok");
    st.textContent = ids.length ? `saved on blipc · pushed to ${ok}/${ids.length} instance${ids.length > 1 ? "s" : ""}` + (failed.length ? ` · errors: ${failed.map((k) => k + ": " + applied[k]).join(", ")}` : "") : "saved on blipc · no instance to push to yet";
    toast(msg + (ids.length ? ` (${ok}/${ids.length})` : ""));
    renderScopeSelect();
  } catch (e) { st.textContent = ""; toast("save failed: " + e.message, "err"); }
};

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
    st.textContent = ids.length ? "saved on blipc · pushed to " + ok + "/" + ids.length + " instance" + (ids.length > 1 ? "s" : "") + (failed.length ? " · errors: " + failed.map((k) => k + ": " + applied[k]).join(", ") : "") : "saved on blipc · no instance to push to yet";
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
$("s-cache-scope").addEventListener("change", (e) => {
  cacheScopeState = e.target.value;
  loadCacheEditor();
});
function cacheValuesForSave() {
  const size = $("s-cache-size").value.trim();
  const warm = $("s-cache-warm").value.trim();
  const regular = $("s-cache-regular").value.trim();
  return { size: size === "" ? null : Math.max(0, Number(size)), warm: warm === "" ? null : Math.max(0, Number(warm)), regular: regular === "" ? null : Math.max(0, Number(regular)) };
}
$("s-save-cache").onclick = async () => {
  const st = $("s-cache-status");
  st.textContent = "saving…";
  const { size, warm, regular } = cacheValuesForSave();
  const isDefault = cacheScopeState === "default";
  const body = isDefault ? {} : { scope: "instance", instance: cacheScopeState };
  if (size != null) body.cache_size = size;
  if (warm != null) body.cache_warm = warm;
  if (regular != null) body.cache_regular = regular;
  try {
    const r = await API("/api/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    const applied = d.applied || {};
    const ids = Object.keys(applied);
    const ok = ids.filter((k) => applied[k] === "ok").length;
    const failed = ids.filter((k) => applied[k] !== "ok");
    st.textContent = ids.length ? "saved on blipc · pushed to " + ok + "/" + ids.length + " instance" + (ids.length > 1 ? "s" : "") + (failed.length ? " · errors: " + failed.map((k) => k + ": " + applied[k]).join(", ") : "") : "saved on blipc · no instance to push to yet";
    toast("cache settings saved" + (ids.length ? " (" + ok + "/" + ids.length + ")" : ""));
    const o = savedOverrides[cacheScopeState] || {};
    if (isDefault) {
      savedCacheSize = size != null ? size : savedCacheSize;
      savedCacheWarm = warm != null ? warm : savedCacheWarm;
      savedCacheRegular = regular != null ? regular : savedCacheRegular;
    } else {
      if (size != null) { if (size > 0) o.cache_size = size; else delete o.cache_size; }
      if (warm != null) { if (warm > 0) o.cache_warm = warm; else delete o.cache_warm; }
      if (regular != null) { if (regular > 0) o.cache_regular = regular; else delete o.cache_regular; }
      if (Object.keys(o).length) savedOverrides[cacheScopeState] = o;
      else delete savedOverrides[cacheScopeState];
    }
    loadCacheEditor();
  } catch (e) { st.textContent = ""; toast("save failed: " + e.message, "err"); }
};
$("s-cache-purge").onclick = async () => {
  const t = cacheLiveTotal();
  confirmDialog("Purge cache?", "Drops every cached response on every instance in the fleet. The cache refills as clients query again." + (t ? " Currently " + t + " entries across the fleet." : ""), async () => {
    try {
      const r = await API("/api/cache/purge", { method: "POST" });
      const d = await r.json();
      const applied = d.applied || {};
      const ids = Object.keys(applied);
      const ok = ids.filter((k) => applied[k] === "ok").length;
      const failed = ids.filter((k) => applied[k] !== "ok");
      $("s-cache-status").textContent = "purged " + (d.purged || 0) + " entries across " + ok + "/" + ids.length + " instance" + (ids.length > 1 ? "s" : "") + (failed.length ? " · errors: " + failed.map((k) => k + ": " + applied[k]).join(", ") : "");
      toast("cache purged (" + (d.purged || 0) + " entries)");
      loadCacheEditor();
    } catch (e) { toast("purge failed: " + e.message, "err"); }
  });
};

function loadQLEditor() {
  const sel = $("s-ql-retention");
  if (![24, 168, 720, 4320, 8760].includes(savedQLRetention)) savedQLRetention = 720;
  sel.value = String(savedQLRetention);
}
$("s-save-ql").onclick = async () => {
  const st = $("s-ql-status");
  st.textContent = "saving…";
  const hours = Number($("s-ql-retention").value);
  try {
    await API("/api/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ query_log_retention_hours: hours }) });
    savedQLRetention = hours;
    st.textContent = "saved";
    toast("query log retention saved");
    loadQLEditor();
    setTimeout(() => { st.textContent = ""; }, 3000);
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
    st.textContent = ids.length ? `saved on blipc · pushed to ${ok}/${ids.length} instance${ids.length > 1 ? "s" : ""}` + (failed.length ? ` · errors: ${failed.map((k) => k + ": " + applied[k]).join(", ")}` : "") : "saved on blipc · no instance to push to yet";
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
if ($("s-fetch")) $("s-fetch").onclick = async () => {
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
initHA();
loadBlocklist();
connectSSE();
refresh();
startClock();
refreshSettings();
pollTimer = setInterval(() => { if (current === "dashboard" || current === "instances" || current === "cache-stats" || current === "upstream-errors") refresh(); }, 5000);
setInterval(() => { if (current === "dashboard") fetchStats(); }, 60000); // refresh chart/stats periodically

/* ---------- cleanup on unload ---------- */
// Close the SSE stream and clear timers when the page is unloaded or the
// user navigates away — otherwise the EventSource can outlive the page
// in some browsers (especially bfcache) and retain references to large
// event objects and closures.
window.addEventListener("beforeunload", () => {
  if (pollTimer) clearInterval(pollTimer);
  if (clockTimer) clearInterval(clockTimer);
  if (eventsRenderTimer) clearTimeout(eventsRenderTimer);
  if (updatePollTimer) clearTimeout(updatePollTimer);
  if (ctrlUpdateTimer) clearTimeout(ctrlUpdateTimer);
  if (blStatusTimer) clearInterval(blStatusTimer);
  if (sse) sse.close();
});
