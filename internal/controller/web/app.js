// BlipDNS Controller — SPA dashboard
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

function getTab() {
  const p = location.pathname.replace(/\.html$/, "");
  if (p === "/blocklist") return "blocklist";
  if (p === "/instances") return "instances";
  if (p === "/settings") return "settings";
  if (p === "/" || p === "") return "dashboard";
  return "dashboard";
}
let currentTab = getTab();

function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll(".nav-item").forEach((a) => {
    a.classList.toggle("active", a.dataset.nav === tab);
  });
  document.querySelectorAll(".view").forEach((v) => v.classList.add("hidden"));
  const map = { dashboard: "dashboard-view", instances: "instances-view", blocklist: "blocklist-view", settings: "settings-view" };
  const el = document.getElementById(map[tab]);
  if (el) el.classList.remove("hidden");
  const titles = { dashboard: "Dashboard", instances: "Instances", blocklist: "Blocklist", settings: "Settings" };
  document.getElementById("page-title").textContent = titles[tab] || "Dashboard";
  const paths = { dashboard: "/", instances: "/instances", blocklist: "/blocklist", settings: "/settings" };
  history.pushState(null, "", paths[tab] || "/");
  refresh();
}
document.querySelectorAll(".nav-item").forEach((a) => {
  a.addEventListener("click", (e) => { e.preventDefault(); switchTab(a.dataset.nav); });
});

async function refresh() {
  try {
    const list = await API("/api/instances").then((r) => r.json());
    if (currentTab === "dashboard") renderDashboard(list);
    else if (currentTab === "instances") renderInstances(list.slice().sort(instanceSort));
    else if (currentTab === "blocklist") refreshBlocklist();
    else if (currentTab === "settings") refreshSettings(list);
    const online = list.filter((i) => i.online).length;
    const conn = document.getElementById("conn");
    conn.textContent = online + "/" + list.length + " online";
    conn.className = "badge " + (online === list.length && list.length > 0 ? "on" : online > 0 ? "warn" : "off");
    document.getElementById("sidebar-status").className = "badge " + conn.className.replace("badge ", "");
  } catch (e) {
    document.getElementById("conn").textContent = "error";
  }
}

// --- Dashboard ---
async function renderDashboard(list) {
  let totalQ = 0, totalB = 0, totalE = 0, online = 0;
  for (const i of list) {
    if (i.online) online++;
    const s = i.stats || {};
    totalQ += s.queries_total ?? 0;
    totalB += s.blocked_total ?? 0;
    totalE += s.upstream_errors ?? 0;
  }
  document.getElementById("d-queries").textContent = totalQ.toLocaleString();
  document.getElementById("d-blocked").textContent = totalB.toLocaleString();
  document.getElementById("d-errors").textContent = totalE.toLocaleString();
  document.getElementById("d-instances").textContent = list.length;
  document.getElementById("d-online").textContent = online;
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
    const ctx = document.getElementById("chart-queries").getContext("2d");
    if (!chart) {
      chart = new Chart(ctx, {
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

// --- Instance menus (three-dots dropdown) ---
document.addEventListener("click", (e) => {
  const menuBtn = e.target.closest("[data-menu]");
  if (menuBtn) {
    const id = menuBtn.getAttribute("data-menu");
    const dropdown = document.querySelector(`[data-menu-for="${CSS.escape(id)}"]`);
    if (dropdown) {
      const isHidden = dropdown.classList.contains("hidden");
      // Close all other menus first
      document.querySelectorAll(".menu-dropdown:not(.hidden)").forEach((d) => d.classList.add("hidden"));
      if (isHidden) {
        dropdown.classList.remove("hidden");
      }
    }
    return;
  }
  // Close menus when clicking outside
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
  // Close the menu
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

function renderInstances(list) {
  const el = document.getElementById("inst-cards");
  el.innerHTML = "";
  const f = (document.getElementById("inst-filter")?.value || "").toLowerCase();
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
  el.dataset.lastList = JSON.stringify(list);
}
document.getElementById("inst-filter")?.addEventListener("input", () => {
  const list = JSON.parse(document.querySelector("#inst-cards")?.dataset?.lastList || "[]");
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
  const ul = document.getElementById("blockList");
  if (!ul) return;
  const f = (document.getElementById("bl-filter")?.value || "").toLowerCase();
  ul.innerHTML = "";
  const filtered = blDomains.filter((d) => !f || d.toLowerCase().includes(f));
  for (const d of filtered) {
    const li = document.createElement("li");
    li.className = "blocklist-item";
    li.innerHTML = `<span>${esc(d)}</span><button class="remove" data-rm="${esc(d)}" title="Remove">&times;</button>`;
    ul.appendChild(li);
  }
  document.getElementById("bl-count").textContent = blDomains.length + " domain" + (blDomains.length !== 1 ? "s" : "") + (f ? " (filtered)" : "");
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

document.getElementById("bl-add")?.addEventListener("click", async () => {
  const input = document.getElementById("bl-add-input");
  const domain = input?.value.trim();
  if (!domain) return toast("domain required");
  try {
    await API("/api/blocklist", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain }) });
    toast("added " + domain);
    input.value = "";
    refreshBlocklist();
  } catch (e) { toast("add failed: " + e.message); }
});

document.getElementById("bl-url-input")?.addEventListener("keydown", (e) => { if (e.key === "Enter") document.getElementById("bl-import-url")?.click(); });
document.getElementById("bl-import-url")?.addEventListener("click", async () => {
  const url = document.getElementById("bl-url-input")?.value.trim();
  if (!url) return toast("URL required");
  const status = document.getElementById("bl-import-status");
  if (status) status.textContent = "fetching…";
  try {
    const r = await API("/api/blocklist/import-url", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }) });
    const d = await r.json();
    if (status) status.textContent = "loaded " + d.count + " domains";
    toast("imported " + d.count + " domains");
    document.getElementById("bl-url-input").value = "";
    refreshBlocklist();
  } catch (e) {
    if (status) status.textContent = "failed";
    toast("import failed: " + e.message);
  }
});

let bFileData = null;
document.getElementById("bl-file-input")?.addEventListener("change", (e) => {
  const file = e.target.files[0];
  const btn = document.getElementById("bl-import-file");
  const name = document.getElementById("bl-import-status");
  if (btn) btn.disabled = !file;
  if (name) name.textContent = file ? file.name : "";
  if (!file) { bFileData = null; return; }
  const reader = new FileReader();
  reader.onload = () => { bFileData = reader.result; };
  reader.readAsText(file);
});

document.getElementById("bl-import-file")?.addEventListener("click", async () => {
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
  document.getElementById("bl-import-status").textContent = "";
  document.getElementById("bl-import-file").disabled = true;
  document.getElementById("bl-file-input").value = "";
  refreshBlocklist();
});

document.getElementById("bl-filter")?.addEventListener("input", renderBlocklist);
document.getElementById("bl-export")?.addEventListener("click", () => { window.open("/api/blocklist/export", "_blank"); });
document.getElementById("bl-clear")?.addEventListener("click", async () => {
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
  const input = document.getElementById("s-upstream");
  if (!input) return;
  for (const i of list) {
    const s = i.stats;
    if (s && s.upstream) { input.value = s.upstream; return; }
  }
  input.value = "";
}
document.getElementById("s-save")?.addEventListener("click", async () => {
  const upstream = document.getElementById("s-upstream")?.value.trim();
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

// Init
refresh();
setInterval(refresh, 5000);
window.addEventListener("popstate", () => { currentTab = getTab(); switchTab(currentTab); });
