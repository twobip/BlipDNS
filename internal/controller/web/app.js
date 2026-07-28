// BlipDNS Controller — dashboard JS
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

function toast(msg) {
  const t = document.createElement("div");
  t.className = "toast";
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2600);
}
function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
const $ = (id) => document.getElementById(id);

// --- Tab / page detection ---
// index.html is the SPA with sidebar-nav. Other pages (instances.html,
// stats.html, queries.html, blocklist.html, settings.html) are standalone
// pages that share app.js via <script src="app.js">.
function getPage() {
  const p = location.pathname.replace(/\.html$/, "");
  if (p === "/instances" || p === "/instances.html") return "instances";
  if (p === "/stats" || p === "/stats.html") return "stats";
  if (p === "/queries" || p === "/queries.html") return "queries";
  if (p === "/blocklist" || p === "/blocklist.html") return "blocklist";
  if (p === "/settings" || p === "/settings.html") return "settings";
  return "dashboard";
}
let currentPage = getPage();

// Separate page URLs for each tab (used when navigating from a standalone page)
const PAGE_URLS = {
  dashboard: "/",
  stats: "/stats.html",
  instances: "/instances.html",
  queries: "/queries.html",
  blocklist: "/blocklist.html",
  settings: "/settings.html",
};

// SPA view IDs (only on index.html)
const VIEW_MAP = {
  dashboard: "dashboard-view",
  instances: "instances-view",
  stats: "stats-view",
  queries: "queries-view",
  blocklist: "blocklist-view",
  settings: "settings-view",
};

const PAGE_TITLES = {
  dashboard: "Dashboard",
  stats: "Stats",
  instances: "Instances",
  queries: "Queries",
  blocklist: "Blocklist",
  settings: "Settings",
};

function switchTab(tab) {
  currentPage = tab;
  // Update active nav item
  document.querySelectorAll(".nav-item").forEach((a) => {
    a.classList.toggle("active", a.dataset.nav === tab);
  });
  // If we're on the SPA (index.html), switch views inline
  const viewId = VIEW_MAP[tab];
  const view = $(viewId);
  if (view) {
    document.querySelectorAll(".view").forEach((v) => v.classList.add("hidden"));
    view.classList.remove("hidden");
    const pt = $("page-title");
    if (pt) pt.textContent = PAGE_TITLES[tab] || "Dashboard";
    refresh();
  } else {
    // On a standalone page, navigate to the separate page
    const url = PAGE_URLS[tab];
    if (url) location.href = url + (TOKEN ? "?token=" + encodeURIComponent(TOKEN) : "");
  }
}
document.querySelectorAll(".nav-item").forEach((a) => {
  a.addEventListener("click", (e) => { e.preventDefault(); switchTab(a.dataset.nav); });
});

async function refresh() {
  try {
    const list = await API("/api/instances").then((r) => r.json());
    if (currentPage === "dashboard") renderDashboard(list);
    else if (currentPage === "instances") renderInstances(list.slice().sort(instanceSort));
    else if (currentPage === "blocklist") refreshBlocklist();
    else if (currentPage === "settings") refreshSettings(list);
    else if (currentPage === "stats") renderStats(list);
    else if (currentPage === "queries") renderQueries(list);
    updateConn(list);
  } catch (e) {
    const conn = $("conn");
    if (conn) { conn.textContent = "error"; conn.className = "badge off"; }
  }
}

function updateConn(list) {
  const conn = $("conn");
  if (!conn) return;
  const online = list.filter((i) => i.online).length;
  conn.textContent = online + "/" + list.length + " online";
  conn.className = "badge " + (online === list.length && list.length > 0 ? "on" : online > 0 ? "warn" : "off");
  const ss = $("sidebar-status");
  if (ss) ss.className = "badge " + conn.className.replace("badge ", "");
}

// --- Dashboard (index.html SPA) ---
async function renderDashboard(list) {
  let totalQ = 0, totalB = 0, totalE = 0, online = 0;
  for (const i of list) {
    if (i.online) online++;
    const s = i.stats || {};
    totalQ += s.queries_total ?? 0;
    totalB += s.blocked_total ?? 0;
    totalE += s.upstream_errors ?? 0;
  }
  // SPA element IDs
  setText("d-queries", totalQ.toLocaleString());
  setText("d-blocked", totalB.toLocaleString());
  setText("d-errors", totalE.toLocaleString());
  setText("d-instances", list.length);
  setText("d-online", online);
  await fetchChart();
}
let chart = null;
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
        options: { responsive: true, maintainAspectRatio: false, animation: { duration: 300 }, scales: { x: { display: true, title: { display: true, text: "Time" } }, y: { beginAtZero: true } } },
      });
    } else {
      chart.data.labels = labels;
      chart.data.datasets[0].data = tq;
      chart.data.datasets[1].data = bq;
      chart.update("none");
    }
  } catch (e) {}
}

// --- Stats page (stats.html) ---
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

// --- Queries page (queries.html) ---
let queryLog = [];
async function renderQueries(list) {
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
  const f = ($("f-domain")?.value || "").toLowerCase();
  const filtered = f
    ? queryLog.filter((e) => (e.domain + " " + (e.client || "")).toLowerCase().includes(f))
    : queryLog;
  ul.innerHTML = "";
  for (const e of filtered) {
    const li = document.createElement("li");
    const t = new Date(e.at).toLocaleTimeString();
    li.innerHTML = '<span class="t">[' + t + ']</span> <strong>' + esc(e.domain) + '</strong> ← <span class="muted">' + esc(e.client || "?") + '</span>';
    ul.appendChild(li);
  }
}
$("f-domain")?.addEventListener("input", renderQueryLog);

// --- Instance menus (three-dots dropdown) ---
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
  }
});

function instanceSort(a, b) {
  const idA = parseInt(a.id, 10);
  const idB = parseInt(b.id, 10);
  if (!isNaN(idA) && !isNaN(idB)) return idA - idB;
  return (a.id || "").localeCompare(b.id || "");
}

// --- Instances ---
// Handles both SPA (#inst-cards) and standalone page (#instances)
function renderInstances(list) {
  const el = $("inst-cards") || $("instances");
  if (!el) return;
  el.innerHTML = "";
  const f = ($("inst-filter")?.value || "").toLowerCase();
  const filtered = list.filter((i) => {
    if (!f) return true;
    return (i.id + " " + (i.label || "") + " " + (i.url || "")).toLowerCase().includes(f);
  });
  if (!filtered.length) {
    el.innerHTML = '<div class="card"><h3>No instances</h3><p class="sub">Add an instance from the controller or via the API.</p></div>';
    return;
  }
  for (const i of filtered) {
    const s = i.stats || {};
    const card = document.createElement("div");
    card.className = "card";
    card.innerHTML = `<div class="card-header">
      <h3>${esc(i.label || i.id)} <span class="badge ${i.online ? "on" : "off"}">${i.online ? "online" : "offline"}</span></h3>
      <div class="card-actions">
        <button class="icon-btn" data-menu="${esc(i.id)}" title="Actions">&#8942;</button>
      </div>
    </div>
    <div class="menu-dropdown hidden" data-menu-for="${esc(i.id)}">
      <button class="menu-item" data-action="reset-adopt" data-id="${esc(i.id)}">Reset Adoption</button>
      <button class="menu-item danger" data-action="remove" data-id="${esc(i.id)}">Remove Instance</button>
    </div>
    <p class="sub">${esc(i.url)}</p>
    <div class="stat"><span>Queries</span><span>${s.queries_total ?? 0}</span></div>
    <div class="stat"><span>Blocked</span><span>${s.blocked_total ?? 0}</span></div>
    <div class="stat"><span>Upstream errs</span><span>${s.upstream_errors ?? 0}</span></div>
    <div class="stat"><span>Cache</span><span>${s.cached ?? 0}</span></div>
    ${i.adopted ? '<div class="stat"><span>Adopted</span><span class="badge on">yes</span></div>' : '<div class="stat"><span>Adopted</span><span class="badge off">no</span></div>'}`;
    el.appendChild(card);
  }
  // Store last list for filter input (SPA only has #inst-filter)
  const cardsEl = $("inst-cards");
  if (cardsEl) cardsEl.dataset.lastList = JSON.stringify(list);
}
$("inst-filter")?.addEventListener("input", () => {
  const cardsEl = $("inst-cards");
  if (!cardsEl) return;
  const list = JSON.parse(cardsEl.dataset?.lastList || "[]");
  renderInstances(list.slice().sort(instanceSort));
});

// --- Blocklist ---
let blDomains = [];
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
    li.className = "blocklist-item";
    li.innerHTML = `<span>${esc(d)}</span><button class="remove" data-rm="${esc(d)}" title="Remove">&times;</button>`;
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

let bFileData = null;
$("bl-file-input")?.addEventListener("change", (e) => {
  const file = e.target.files[0];
  const btn = $("bl-import-file");
  const name = $("bl-import-status");
  if (btn) btn.disabled = !file;
  if (name) name.textContent = file ? file.name : "";
  if (!file) { bFileData = null; return; }
  const reader = new FileReader();
  reader.onload = () => { bFileData = reader.result; };
  reader.readAsText(file);
});

$("bl-import-file")?.addEventListener("click", async () => {
  if (!bFileData) return toast("no file loaded");
  const lines = bFileData.split("\n");
  const domains = [];
  for (const raw of lines) {
    let line = raw.trim();
    if (!line || line.startsWith("!")) continue;
    if (line.includes("$")) line = line.split("$")[0];
    if (line.startsWith("||")) { line = line.slice(2); if (line.includes("^")) line = line.split("^")[0]; }
    else if (line.startsWith("|")) { line = line.slice(1); if (line.includes("^")) line = line.split("^")[0]; }
    if (!line) continue;
    if (line.includes("://")) { try { const u = new URL(line); if (u.hostname) line = u.hostname; else continue; } catch { continue; } }
    if (line.includes(".") && !line.startsWith(".") && !line.endsWith(".")) {
      domains.push(line.toLowerCase().replace(/\.+$/, ""));
    }
  }
  if (!domains.length) return toast("no domains found");
  let added = 0;
  for (const d of domains) {
    try { await API("/api/blocklist", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: d }) }); added++; } catch (_) {}
  }
  toast("imported " + added + " domains from file");
  bFileData = null;
  const status = $("bl-import-status");
  if (status) status.textContent = "";
  const fbtn = $("bl-import-file");
  if (fbtn) fbtn.disabled = true;
  const finput = $("bl-file-input");
  if (finput) finput.value = "";
  refreshBlocklist();
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

// --- Settings ---
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

// --- Modal (instances.html add instance) ---
const modal = $("modal");
const addBtn = $("add-btn");
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
        await API("/api/instances/" + encodeURIComponent(body.id) + "/adopt", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ code: body.claim }),
        });
        toast("adopted " + body.id);
      }
      refresh();
    } catch (e) { toast("add failed: " + e.message); }
  };
}

// --- Events (Stats page SSE) ---
let eventCount = 0;
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
  li.innerHTML = '<span class="t">[' + time + ']</span><span class="' + cls + '">[' + esc(e.instance) + ']</span><span>' + esc(text) + "</span>";
  ul.prepend(li);
  while (ul.children.length > 200) ul.removeChild(ul.lastChild);
}

function connectSSE() {
  const qs = TOKEN ? "?token=" + encodeURIComponent(TOKEN) : "";
  const es = new EventSource("/api/events" + qs);
  es.onmessage = (ev) => {
    try { addEvent(JSON.parse(ev.data)); } catch {}
  };
  es.onerror = () => {
    const c = $("conn");
    if (c) c.textContent = "reconnecting...";
  };
}

// --- Init ---
// Sidebar toggle
const sbToggle = $("sidebar-toggle");
if (sbToggle) {
  sbToggle.onclick = () => {
    document.body.classList.toggle("sidebar-collapsed");
  };
}

refresh();
setInterval(refresh, 5000);
window.addEventListener("popstate", () => { currentPage = getPage(); refresh(); });

// Connect SSE on stats page
if (location.pathname.includes("stats")) {
  connectSSE();
}
