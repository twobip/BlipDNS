// BlipDNS Controller — SPA
const TOKEN = new URLSearchParams(location.search).get("token") || "";
const AUTH = TOKEN ? "Bearer " + TOKEN : "";

const API = (path, opts = {}) =>
  fetch(path, {
    ...opts,
    headers: { ...(opts.headers || {}), Authorization: AUTH },
  }).then((r) => {
    if (!r.ok) throw new Error(r.status + " " + r.statusText);
    return r;
  });

const $ = (id) => document.getElementById(id);
const esc = (s) =>
  String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

function toast(msg, duration = 2600) {
  const t = document.createElement("div");
  t.className = "toast";
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), duration);
}

// ===== Routing =====
const ROUTES = {
  "/": "dashboard",
  "/dashboard": "dashboard",
  "/instances": "instances",
  "/queries": "queries",
  "/blocklist": "blocklist",
  "/stats": "stats",
  "/settings": "settings",
};

const PAGE_TITLES = {
  dashboard: "Dashboard",
  instances: "Instances",
  queries: "Queries",
  blocklist: "Blocklist",
  stats: "Stats",
  settings: "Settings",
};

const NAV_ITEMS = [
  { id: "dashboard", label: "Dashboard", icon: "📊" },
  { id: "instances", label: "Instances", icon: "🖥️" },
  { id: "queries", label: "Queries", icon: "🔍" },
  { id: "stats", label: "Stats", icon: "📈" },
  { id: "blocklist", label: "Blocklist", icon: "🚫" },
  { id: "settings", label: "Settings", icon: "⚙️" },
];

let currentPage = "dashboard";
let instances = [];
let chart = null;
let eventCount = 0;
let queryLog = [];
let blDomains = [];
let sse = null;

function getRoute() {
  const path = location.pathname.replace(/\/$/, "") || "/";
  return ROUTES[path] || "dashboard";
}

function renderNav() {
  const nav = $("nav");
  if (!nav) return;
  nav.innerHTML = "";
  for (const item of NAV_ITEMS) {
    const a = document.createElement("a");
    a.className = "nav-item" + (item.id === currentPage ? " active" : "");
    a.href = item.id === "dashboard" ? "/{{TOKEN}}" : "/" + item.id + "?token=" + encodeURIComponent(TOKEN);
    a.dataset.nav = item.id;
    a.innerHTML = `<span>${item.icon}</span><span>${item.label}</span>`;
    nav.appendChild(a);
  }
}

function navigate(tab) {
  const url = tab === "dashboard" ? "/{{TOKEN}}" : "/" + tab + "?token=" + encodeURIComponent(TOKEN);
  history.pushState({ page: tab }, "", url);
  showPage(tab);
}

function showPage(page) {
  currentPage = page;
  // Update nav
  document.querySelectorAll(".nav-item").forEach((a) => {
    a.classList.toggle("active", a.dataset.nav === page);
  });
  // Show view
  document.querySelectorAll(".view").forEach((v) => {
    v.classList.toggle("active", v.id === page + "-view");
  });
  // Update title
  const pt = $("page-title");
  if (pt) pt.textContent = PAGE_TITLES[page] || "Dashboard";
  // Page-specific actions
  if (page === "stats" && !sse) connectSSE();
  if (page !== "stats" && sse) {
    sse.close();
    sse = null;
  }
  refresh();
}

// ===== Init =====
renderNav();

document.querySelectorAll(".nav-item").forEach((a) => {
  a.addEventListener("click", (e) => {
    e.preventDefault();
    navigate(a.dataset.nav);
  });
});

// Sidebar toggle
const sbToggle = $("sidebar-toggle");
const sbToggleTop = $("sidebar-toggle-top");
const toggleSidebar = () => document.body.classList.toggle("sidebar-collapsed");
if (sbToggle) sbToggle.onclick = toggleSidebar;
if (sbToggleTop) sbToggleTop.onclick = toggleSidebar;

// Popstate (back/forward)
window.addEventListener("popstate", () => {
  const page = getRoute();
  showPage(page);
});

// ===== Connection status =====
function updateConn(list) {
  const conn = $("conn");
  if (!conn) return;
  const online = list.filter((i) => i.online).length;
  conn.textContent = online + "/" + list.length + " online";
  conn.className = "badge " + (online === list.length && list.length > 0 ? "on" : online > 0 ? "warn" : "off");
  const ss = $("sidebar-status");
  if (ss) ss.className = conn.className;
}

// ===== Refresh =====
async function refresh() {
  try {
    const list = await API("/api/instances").then((r) => r.json());
    instances = list;
    if (currentPage === "dashboard") renderDashboard(list);
    else if (currentPage === "instances") renderInstances(list);
    else if (currentPage === "queries") renderQueries();
    else if (currentPage === "blocklist") refreshBlocklist();
    else if (currentPage === "stats") renderStats(list);
    else if (currentPage === "settings") refreshSettings(list);
    updateConn(list);
  } catch (e) {
    const conn = $("conn");
    if (conn) {
      conn.textContent = "error";
      conn.className = "badge off";
    }
  }
}

// ===== Dashboard =====
async function renderDashboard(list) {
  let totalQ = 0, totalB = 0, totalE = 0, online = 0;
  for (const i of list) {
    if (i.online) online++;
    const s = i.stats || {};
    totalQ += s.queries_total ?? 0;
    totalB += s.blocked_total ?? 0;
    totalE += s.upstream_errors ?? 0;
  }
  setText("d-queries", totalQ.toLocaleString());
  setText("d-blocked", totalB.toLocaleString());
  setText("d-errors", totalE.toLocaleString());
  setText("d-online", online);
  setText("d-total", list.length);
  await fetchChart();
}

async function fetchChart() {
  try {
    const res = await API("/api/stats?bucket=5m&since=24h");
    const stats = await res.json();
    if (!stats || !stats.length) return;
    const labels = stats.map((s) => new Date(s.timestamp).toLocaleTimeString());
    const tq = stats.map((s) => s.total_queries);
    const bq = stats.map((s) => s.blocked_queries);
    const ctx = $("chart-queries");
    if (!ctx) return;
    if (!chart) {
      chart = new Chart(ctx.getContext("2d"), {
        type: "line",
        data: {
          labels,
          datasets: [
            { label: "Total", data: tq, borderColor: "#5b9cf6", backgroundColor: "rgba(91,156,246,.1)", fill: true, tension: .3, pointRadius: 0 },
            { label: "Blocked", data: bq, borderColor: "#f87171", backgroundColor: "rgba(248,113,113,.1)", fill: true, tension: .3, pointRadius: 0 },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 300 },
          scales: {
            x: { display: true, title: { display: true, text: "Time" } },
            y: { beginAtZero: true },
          },
        },
      });
    } else {
      chart.data.labels = labels;
      chart.data.datasets[0].data = tq;
      chart.data.datasets[1].data = bq;
      chart.update("none");
    }
  } catch (e) {}
}

// ===== Stats page =====
function renderStats(list) {
  let totalQ = 0, totalB = 0, totalE = 0, online = 0;
  for (const i of list) {
    if (i.online) online++;
    const s = i.stats || {};
    totalQ += s.queries_total ?? 0;
    totalB += s.blocked_total ?? 0;
    totalE += s.upstream_errors ?? 0;
  }
  setText("total-queries", totalQ.toLocaleString());
  setText("total-blocked", totalB.toLocaleString());
  setText("total-upstream-errors", totalE.toLocaleString());
  setText("online-instances", online);
  setText("total-instances", list.length);
}

// ===== Instances =====
function renderInstances(list) {
  const el = $("inst-cards");
  if (!el) return;
  el.innerHTML = "";
  const f = ($("inst-filter")?.value || "").toLowerCase();
  const filtered = list.filter((i) => {
    if (!f) return true;
    return (i.id + " " + (i.label || "") + " " + (i.url || "")).toLowerCase().includes(f);
  });
  if (!filtered.length) {
    el.innerHTML = '<div class="stat-card"><h3>No instances</h3><p class="sub">Add an instance from the controller or via the API.</p></div>';
    return;
  }
  for (const i of filtered) {
    const s = i.stats || {};
    const card = document.createElement("div");
    card.className = "instance-card";
    card.innerHTML = `
      <div class="card-head">
        <h3>${esc(i.label || i.id)} <span class="badge ${i.online ? "on" : "off"}">${i.online ? "online" : "offline"}</span></h3>
        <div class="menu-btn">
          <button class="icon-btn" data-menu="${esc(i.id)}" title="Actions">⋯</button>
          <div class="menu-dropdown hidden" data-menu-for="${esc(i.id)}">
            <button class="menu-item" data-action="policies" data-id="${esc(i.id)}">Policies</button>
            <button class="menu-item" data-action="reset-adopt" data-id="${esc(i.id)}">Reset Adoption</button>
            <button class="menu-item danger" data-action="remove" data-id="${esc(i.id)}">Remove Instance</button>
          </div>
        </div>
      </div>
      <p class="url">${esc(i.url)}</p>
      <div class="stat"><span>Queries</span><span>${s.queries_total ?? 0}</span></div>
      <div class="stat"><span>Blocked</span><span>${s.blocked_total ?? 0}</span></div>
      <div class="stat"><span>Upstream errs</span><span>${s.upstream_errors ?? 0}</span></div>
      <div class="stat"><span>Cache</span><span>${s.cached ?? 0}</span></div>
      <div class="stat"><span>Adopted</span><span class="badge ${i.adopted ? "on" : "off"}">${i.adopted ? "yes" : "no"}</span></div>
      ${i.ping_avg_ms ? `<div class="stat"><span>Ping avg</span><span>${i.ping_avg_ms.toFixed(1)} ms</span></div>` : ""}
    `;
    el.appendChild(card);
  }
}

// Instance menu
document.addEventListener("click", (e) => {
  const menuBtn = e.target.closest("[data-menu]");
  if (menuBtn) {
    const id = menuBtn.getAttribute("data-menu");
    const dropdown = document.querySelector(`[data-menu-for="${CSS.escape(id)}"]`);
    if (dropdown) {
      const isHidden = dropdown.classList.contains("hidden");
      document.querySelectorAll(".menu-dropdown:not(.hidden)").forEach((d) => d.classList.add("hidden"));
      if (isHidden) dropdown.classList.remove("hidden");
    }
    return;
  }
  if (!e.target.closest(".menu-dropdown") && !e.target.closest("[data-menu]")) {
    document.querySelectorAll(".menu-dropdown:not(.hidden)").forEach((d) => d.classList.add("hidden"));
  }
});

document.addEventListener("click", async (e) => {
  const item = e.target.closest(".menu-item");
  if (!item) return;
  const action = item.getAttribute("data-action");
  const id = item.getAttribute("data-id");
  if (!action || !id) return;
  const dropdown = document.querySelector(`[data-menu-for="${CSS.escape(id)}"]`);
  if (dropdown) dropdown.classList.add("hidden");

  if (action === "remove") {
    if (!confirm(`Remove instance ${id}? This cannot be undone.`)) return;
    try {
      await API("/api/instances/" + encodeURIComponent(id), { method: "DELETE" });
      toast("removed instance " + id);
      refresh();
    } catch (err) {
      toast("remove failed: " + err.message);
    }
  } else if (action === "reset-adopt") {
    if (!confirm(`Reset adoption for instance ${id}? blipd will need a new claim code on next start.`)) return;
    try {
      await API("/api/instances/" + encodeURIComponent(id) + "/adopt/reset", { method: "POST" });
      toast("adoption reset for " + id);
      refresh();
    } catch (err) {
      toast("reset failed: " + err.message);
    }
  } else if (action === "policies") {
    openPolicyModal(id);
  }
});

// ===== Add Instance Modal =====
const modal = $("modal");
const addBtn = $("add-instance-btn");
if (addBtn) addBtn.onclick = () => { if (modal) modal.classList.remove("hidden"); };
const iCancel = $("i-cancel");
if (iCancel) iCancel.onclick = () => { if (modal) modal.classList.add("hidden"); };
const iSave = $("i-save");
if (iSave) {
  iSave.onclick = async () => {
    const body = {
      id: $("i-id")?.value.trim(),
      label: $("i-label")?.value.trim(),
      url: $("i-url")?.value.trim(),
      token: $("i-token")?.value,
      claim: $("i-claim")?.value.trim(),
    };
    if (!body.id || !body.url) return toast("id and url required");
    try {
      await API("/api/instances", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      if (modal) modal.classList.add("hidden");
      toast("instance added");
      if (body.claim) {
        try {
          await API("/api/instances/" + encodeURIComponent(body.id) + "/adopt", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code: body.claim }),
          });
          toast("adopted " + body.id);
        } catch (e) {
          toast("adoption failed: " + e.message);
        }
      }
      refresh();
    } catch (e) { toast("add failed: " + e.message); }
  };
}

// ===== Policy Modal =====
const policyModal = $("policy-modal");
let policyInstanceId = null;
let policyEditId = null;

async function openPolicyModal(instanceId) {
  policyInstanceId = instanceId;
  policyEditId = null;
  $("policy-modal-title").textContent = "Instance Policies";
  // Load existing policies
  try {
    const resp = await API("/api/instances/" + encodeURIComponent(instanceId) + "/policies");
    const data = await resp.json();
    const defaultPolicy = data.default || {};
    const policies = data.policies || [];

    // Build policy list HTML
    let html = "";
    if (defaultPolicy.id) {
      html += `<div class="policy-item" data-pid="${esc(defaultPolicy.id)}">
        <div class="policy-info">
          <strong>${esc(defaultPolicy.id)}</strong> <span class="muted">(default)</span>
        </div>
        <div class="policy-actions">
          <button class="icon-btn" data-edit="${esc(defaultPolicy.id)}" title="Edit">✏️</button>
        </div>
      </div>`;
    }
    for (const p of policies) {
      html += `<div class="policy-item" data-pid="${esc(p.id)}">
        <div class="policy-info">
          <strong>${esc(p.id)}</strong>
          <span class="muted">${p.networks?.join(", ") || ""}</span>
        </div>
        <div class="policy-actions">
          <button class="icon-btn" data-edit="${esc(p.id)}" title="Edit">✏️</button>
          <button class="icon-btn danger" data-delete="${esc(p.id)}" title="Delete">🗑️</button>
        </div>
      </div>`;
    }
    $("policy-modal").querySelector(".policy-list").innerHTML = html;
    $("policy-modal").querySelector(".policy-list").classList.remove("hidden");
    $("policy-form").classList.add("hidden");
  } catch (e) {
    toast("failed to load policies: " + e.message);
  }
  if (policyModal) policyModal.classList.remove("hidden");
}

// ===== Blocklist =====
async function refreshBlocklist() {
  try {
    const r = await API("/api/blocklist");
    const d = await r.json();
    blDomains = d.domains || [];
    renderBlocklist();
  } catch (e) {}
}

function renderBlocklist() {
  const ul = $("blockList");
  if (!ul) return;
  const f = ($("bl-filter")?.value || "").toLowerCase();
  ul.innerHTML = "";
  const filtered = blDomains.filter((d) => !f || d.toLowerCase().includes(f));
  for (const d of filtered) {
    const li = document.createElement("li");
    li.innerHTML = `<span>${esc(d)}</span><button class="rm" data-rm="${esc(d)}" title="Remove">×</button>`;
    ul.appendChild(li);
  }
  const countEl = $("bl-count");
  if (countEl) countEl.textContent = blDomains.length + " domain" + (blDomains.length !== 1 ? "s" : "") + (f ? " (filtered)" : "");
  ul.querySelectorAll("[data-rm]").forEach((b) => {
    b.onclick = async () => {
      const domain = b.getAttribute("data-rm");
      try {
        await API("/api/blocklist", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain }) });
        toast("removed " + domain);
        refreshBlocklist();
      } catch (e) { toast("remove failed"); }
    };
  });
}

$("bl-add")?.addEventListener("click", async () => {
  const input = $("bl-add-input");
  const domain = input?.value.trim();
  if (!domain) return toast("domain required");
  try {
    await API("/api/blocklist", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain }) });
    toast("added " + domain);
    input.value = "";
    refreshBlocklist();
  } catch (e) { toast("add failed: " + e.message); }
});

$("bl-url-input")?.addEventListener("keydown", (e) => { if (e.key === "Enter") $("bl-import-url")?.click(); });
$("bl-import-url")?.addEventListener("click", async () => {
  const url = $("bl-url-input")?.value.trim();
  if (!url) return toast("URL required");
  const status = $("bl-import-status");
  if (status) status.textContent = "fetching…";
  try {
    const r = await API("/api/blocklist/import-url", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }) });
    const d = await r.json();
    if (status) status.textContent = "loaded " + d.count + " domains";
    toast("imported " + d.count + " domains");
    $("bl-url-input").value = "";
    refreshBlocklist();
  } catch (e) {
    if (status) status.textContent = "failed";
    toast("import failed: " + e.message);
  }
});

$("bl-filter")?.addEventListener("input", renderBlocklist);
$("bl-export")?.addEventListener("click", () => { window.open("/api/blocklist/export", "_blank"); });
$("bl-clear")?.addEventListener("click", async () => {
  if (!confirm("Remove ALL domains from the global blocklist?")) return;
  try {
    const r = await API("/api/blocklist");
    const d = await r.json();
    const domains = d.domains || [];
    for (const dom of domains) {
      await API("/api/blocklist", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: dom }) });
    }
    toast("cleared " + domains.length + " domains");
    refreshBlocklist();
  } catch (e) { toast("clear failed"); }
});

// ===== Queries =====
async function renderQueries() {
  const ul = $("query-log");
  if (!ul) return;
  ul.innerHTML = "";
  try {
    const entries = await API("/api/queries?limit=200").then((r) => r.json());
    queryLog = entries || [];
    renderQueryLog();
  } catch (e) {
    ul.innerHTML = '<li class="muted">Error loading query log</li>';
  }
}

function renderQueryLog() {
  const ul = $("query-log");
  if (!ul) return;
  const f = ($("q-filter")?.value || "").toLowerCase();
  const filtered = f
    ? queryLog.filter((e) => (e.domain + " " + (e.client || "")).toLowerCase().includes(f))
    : queryLog;
  ul.innerHTML = "";
  for (const e of filtered) {
    const li = document.createElement("li");
    const t = new Date(e.at).toLocaleTimeString();
    const cls = e.action === "BLOCK" ? "type-block" : "type-pass";
    li.innerHTML = `<span class="t">[${t}]</span> <strong>${esc(e.domain)}</strong> ← <span class="muted">${esc(e.client || "?")}</span> <span class="${cls}">${esc(e.action || "")}</span>`;
    ul.appendChild(li);
  }
  const countEl = $("q-count");
  if (countEl) countEl.textContent = filtered.length + " entries";
}

$("q-filter")?.addEventListener("input", renderQueryLog);

// ===== Settings =====
async function refreshSettings(list) {
  const input = $("s-upstream");
  if (!input) return;
  for (const i of list) {
    const s = i.stats;
    if (s && s.upstream) { input.value = s.upstream; return; }
  }
  input.value = "";
}

$("s-save")?.addEventListener("click", async () => {
  const upstream = $("s-upstream")?.value.trim();
  if (!upstream) return toast("upstream required");
  const list = await API("/api/instances").then((r) => r.json());
  const online = list.find((i) => i.online);
  if (!online) return toast("no online instances");
  try {
    await API("/api/instances/" + encodeURIComponent(online.id) + "/policy", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id: "default", upstream }) });
    toast("upstream saved");
    refresh();
  } catch (e) { toast("save failed: " + e.message); }
});

// ===== SSE (Stats page event stream) =====
function connectSSE() {
  const qs = TOKEN ? "?token=" + encodeURIComponent(TOKEN) : "";
  sse = new EventSource("/api/events" + qs);
  sse.onmessage = (ev) => {
    try { addEvent(JSON.parse(ev.data)); } catch {}
  };
  sse.onerror = () => {
    const c = $("conn");
    if (c) c.textContent = "reconnecting...";
  };
}

function addEvent(e) {
  eventCount++;
  const ec = $("event-count");
  if (ec) ec.textContent = eventCount + " events";
  const ul = $("events");
  if (!ul) return;
  const li = document.createElement("li");
  const time = new Date(e.at).toLocaleTimeString();
  const cls = "type-" + e.type;
  let text = "";
  if (e.type === "block") text = "BLOCK " + e.domain + " ← " + e.client;
  else if (e.type === "policy") text = "POLICY " + (e.msg || e.domain);
  else if (e.type === "health") text = "health ok";
  else text = e.type;
  li.innerHTML = `<span class="t">[${time}]</span><span class="${cls}">[${esc(e.instance)}]</span><span>${esc(text)}</span>`;
  ul.prepend(li);
  while (ul.children.length > 200) ul.removeChild(ul.lastChild);
}

// ===== Utils =====
function setText(id, val) {
  const el = $(id);
  if (el) el.textContent = val;
}

// ===== Init =====
showPage(getRoute());
refresh();
setInterval(refresh, 5000);
