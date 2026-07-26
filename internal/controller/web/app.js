// BlipDNS Controller dashboard JS. Talks to the controller API and SSE feed.
const TOKEN = new URLSearchParams(location.search).get("token") || "";
const AUTH = TOKEN ? "Bearer " + TOKEN : "";

// Determine current tab from URL path (e.g., /instances, /queries, /settings)
function getTabFromPath() {
  const path = location.pathname;
  if (path === "/instances" || path === "/instances.html") return "instances";
  if (path === "/queries" || path === "/queries.html") return "queries";
  if (path === "/blocklist" || path === "/blocklist.html") return "blocklist";
  if (path === "/settings" || path === "/settings.html") return "settings";
  return "dashboard";
}

let currentTab = getTabFromPath();

function api(path, opts = {}) {
  return fetch(path, { ...opts, headers: { ...(opts.headers || {}), Authorization: AUTH } })
    .then((r) => {
      if (!r.ok) throw new Error(r.status + " " + r.statusText);
      return r;
    });
}

function toast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  setTimeout(() => t.classList.add("hidden"), 2500);
}

function esc(s) {
  return String(s)
    .replace(/&/g, "&")
    .replace(/</g, "<")
    .replace(/>/g, ">")
    .replace(/"/g, "\"")
    .replace(/'/g, "'");
}

function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll(".tab").forEach((a) => {
    a.classList.toggle("active", a.dataset.tab === tab);
  });
  document.getElementById("dashboard-view").classList.toggle("hidden", tab !== "dashboard");
  document.getElementById("instances-view").classList.toggle("hidden", tab !== "instances");
  document.getElementById("queries-view").classList.toggle("hidden", tab !== "queries");
  document.getElementById("blocklist-view").classList.toggle("hidden", tab !== "blocklist");
  document.getElementById("settings-view").classList.toggle("hidden", tab !== "settings");
  // Update URL without reload
  const paths = { dashboard: "/", instances: "/instances", queries: "/queries", blocklist: "/blocklist", settings: "/settings" };
  history.pushState(null, "", paths[tab] || "/");
  refresh();
}

async function refresh() {
  try {
    const list = await api("/api/instances").then((r) => r.json());
    if (currentTab === "dashboard") renderDashboard(list);
    else if (currentTab === "instances") renderInstances(list);
    else if (currentTab === "queries") refreshQueryLog();
    else if (currentTab === "blocklist") refreshBlocklist();
    else if (currentTab === "settings") refreshSettings(list);
    const conn = document.getElementById("conn");
    const online = list.filter((i) => i.online).length;
    conn.textContent = online + "/" + list.length + " online";
    const allOnline = online === list.length && list.length > 0;
    const someOnline = list.some((i) => i.online);
    conn.className = "badge " + (allOnline ? "on" : someOnline ? "warn" : "off");
  } catch (err) {
    document.getElementById("conn").textContent = "error";
  }
}

function renderDashboard(list) {
  let totalQueries = 0;
  let totalBlocked = 0;
  let totalUpstreamErrors = 0;
  let online = 0;
  for (const i of list) {
    if (i.online) online++;
    const s = i.stats || {};
    totalQueries += s.queries_total ?? 0;
    totalBlocked += s.blocked_total ?? 0;
    totalUpstreamErrors += s.upstream_errors ?? 0;
  }
  document.getElementById("total-queries").textContent = totalQueries.toLocaleString();
  document.getElementById("total-blocked").textContent = totalBlocked.toLocaleString();
  document.getElementById("total-upstream-errors").textContent = totalUpstreamErrors.toLocaleString();
  document.getElementById("online-instances").textContent = online;
  document.getElementById("total-instances").textContent = list.length;
  const onlineEl = document.getElementById("online-instances");
  const card = onlineEl.closest(".stat-card");
  if (online < list.length && list.length > 0) {
    onlineEl.classList.add("warn");
    if (card) card.classList.add("warn");
  } else {
    onlineEl.classList.remove("warn");
    if (card) card.classList.remove("warn");
  }

  // Update query volume chart (fetch 24h historical data)
  fetchAndRenderChart();
}
// Query volume chart
let queryChart = null;
const chartMaxPoints = 288; // 5-min buckets for 24h = 288 points

async function fetchAndRenderChart() {
  const canvas = document.getElementById("query-chart");
  if (!canvas) return;

  try {
    const res = await api("/api/stats?bucket=5m&since=24h");
    const stats = await res.json();
    
    if (!stats || stats.length === 0) {
      // Fallback to live polling if no historical data
      return;
    }

    const labels = stats.map(s => new Date(s.timestamp).toLocaleTimeString());
    const totalQueries = stats.map(s => s.total_queries);
    const blockedQueries = stats.map(s => s.blocked_queries);

    if (!queryChart) {
      const ctx = canvas.getContext("2d");
      queryChart = new Chart(ctx, {
        type: "line",
        data: {
          labels: labels,
          datasets: [
            {
              label: "Total Queries (5-min)",
              data: totalQueries,
              borderColor: "#3b82f6",
              backgroundColor: "rgba(59, 130, 246, 0.1)",
              fill: true,
              tension: 0.3,
              pointRadius: 0,
            },
            {
              label: "Blocked Queries (5-min)",
              data: blockedQueries,
              borderColor: "#ef4444",
              backgroundColor: "rgba(239, 68, 68, 0.1)",
              fill: true,
              tension: 0.3,
              pointRadius: 0,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 300 },
          interaction: { mode: "index", intersect: false },
          scales: {
            x: { display: true, title: { display: true, text: "Time (last 24h)" } },
            y: { beginAtZero: true, title: { display: true, text: "Queries / 5-min" } },
          },
          plugins: { legend: { position: "top" } },
        },
      });
    } else {
      queryChart.data.labels = labels;
      queryChart.data.datasets[0].data = totalQueries;
      queryChart.data.datasets[1].data = blockedQueries;
      queryChart.update("none");
    }
  } catch (err) {
    console.error("Failed to fetch chart data:", err);
  }
}

function renderInstances(list) {
  const el = document.getElementById("instances");
  el.innerHTML = "";
  if (!list.length) {
    el.innerHTML = '<div class="card"><h3>No instances</h3><div class="sub">Click + to add a blipd instance</div></div>';
    return;
  }
  for (const i of list) {
      const s = i.stats || {};
      const adoptBadge = i.adopted
        ? '<span class="badge on">claimed</span>'
        : '<span class="badge off">unclaimed</span>';
      const adoptBtn = i.adopted ? '' : '<button class="mini" data-adopt="' + i.id + '">Adopt\u2026</button>';
      const renameBtn = '<button class="mini" data-rename="' + i.id + '">Rename</button>';
      const card = document.createElement("div");
      card.className = "card";
      card.innerHTML =
        '\n      <h3>' +
        esc(i.label) +
        ' <span class="badge ' +
        (i.online ? "on" : "off") +
        '">' +
        (i.online ? "online" : "offline") +
        "</span> " +
        adoptBadge +
        "</h3>\n      <div class=\"sub\">" +
        esc(i.url) +
        "</div>\n      <div class=\"stat\"><span>queries</span><span>" +
        (s.queries_total ?? 0) +
        "</span></div>\n      <div class=\"stat\"><span>blocked</span><span>" +
        (s.blocked_total ?? 0) +
        "</span></div>\n      <div class=\"stat\"><span>upstream errs</span><span>" +
        (s.upstream_errors ?? 0) +
        "</span></div>\n      <div class=\"stat\"><span>cache</span><span>" +
        (s.cached ?? 0) +
        "</span></div>\n      <div class=\"actions\">" +
        adoptBtn +
        renameBtn +
        "</div>\n    ";
      el.appendChild(card);
    }
    document.querySelectorAll("[data-adopt]").forEach((b) => {
      b.onclick = () => adoptInstance(b.getAttribute("data-adopt"));
    });
    document.querySelectorAll("[data-rename]").forEach((b) => {
      b.onclick = () => renameInstance(b.getAttribute("data-rename"));
    });
  }

async function adoptInstance(id) {
  const code = prompt("Paste the blipd claim code (from its journal, one-time):");
  if (!code) return;
  try {
    await api("/api/instances/" + encodeURIComponent(id) + "/adopt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
    });
    toast("adopted " + id);
    refresh();
  } catch (e) {
    toast("adopt failed: " + e.message);
  }
}

async function renameInstance(id) {
  const label = prompt("Enter new label for instance " + id + ":");
  if (!label) return;
  try {
    await api("/api/instances/" + encodeURIComponent(id) + "/label", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ label }),
    });
    toast("renamed " + id);
    refresh();
  } catch (e) {
    toast("rename failed: " + e.message);
  }
}

let total = 0;
function addEvent(e) {
  const filter = document.getElementById("f-domain")?.value.toLowerCase() || "";
  if (filter && !((e.domain || "").toLowerCase().includes(filter)) && !((e.client || "").toLowerCase().includes(filter))) return;
  total++;
  const ec = document.getElementById("event-count");
  if (ec) ec.textContent = total + " events";
  const ul = document.getElementById("events");
  if (!ul) return;
  const li = document.createElement("li");
  const time = new Date(e.at).toLocaleTimeString();
  const cls = "type-" + e.type;
  let text = "";
  if (e.type === "block") text = "BLOCK " + e.domain + " \u2190 " + e.client;
  else if (e.type === "policy") text = "POLICY " + (e.msg || e.domain);
  else if (e.type === "health") text = "health ok (q=" + (e.stats ? e.stats.queries_total : 0) + ")";
  else text = e.type;
  li.innerHTML = '<span class="t">' + time + '</span><span class="' + cls + '">[' + esc(e.instance) + ']</span><span>' + esc(text) + "</span>";
  ul.prepend(li);
  while (ul.children.length > 200) ul.removeChild(ul.lastChild);
}

// --- Query Log tab ---
let queryLog = [];
const queryLogMax = 500;

function addQueryLog(entry) {
  queryLog.unshift(entry);
  if (queryLog.length > queryLogMax) queryLog = queryLog.slice(0, queryLogMax);
  if (!document.getElementById("queries-view").classList.contains("hidden")) {
    renderQueryLog();
  }
}

function renderQueryLog() {
  const instanceSel = document.getElementById("q-instance");
  const filter = document.getElementById("q-filter")?.value.toLowerCase() || "";
  const selectedInstance = instanceSel?.value || "";
  const tbody = document.querySelector("#q-table tbody");
  if (!tbody) return;

  // Update instance selector
  const instances = new Set(queryLog.map((e) => e.instance).filter(Boolean));
  const currentVal = instanceSel?.value || "";
  instanceSel.innerHTML = '<option value="">All</option>' + [...instances].map((i) => `<option value="${i}">${i}</option>`).join("");
  instanceSel.value = currentVal;

  const filterVal = document.getElementById("q-filter")?.value.toLowerCase() || "";

  const filtered = queryLog.filter((e) => {
    if (instanceSel?.value && e.instance !== instanceSel?.value) return false;
    const hay = `${e.instance} ${e.client} ${e.domain} ${e.action} ${e.upstream || ""}`.toLowerCase();
    return hay.includes(filterVal);
  });

  tbody.innerHTML = filtered
    .slice(0, 200)
    .map(
      (e) => `
      <tr class="action-${e.action?.toLowerCase() || "pass"}">
        <td>${new Date(e.at).toLocaleTimeString()}</td>
        <td>${e.instance || "\u2014"}</td>
        <td>${e.client || "\u2014"}</td>
        <td>${e.domain}</td>
        <td><span class="action-badge action-${e.action?.toLowerCase() || "pass"}">${e.action || "PASS"}</span></td>
        <td>${e.upstream || "\u2014"}</td>
      </tr>
    `
    )
    .join("");
}

function refreshQueryLog() {
  renderQueryLog();
}

document.getElementById("q-filter")?.addEventListener("input", renderQueryLog);
document.getElementById("q-instance")?.addEventListener("change", renderQueryLog);
document.getElementById("q-clear")?.addEventListener("click", () => {
  queryLog = [];
  renderQueryLog();
});

function connectSSE() {
  const qs = TOKEN ? "?token=" + encodeURIComponent(TOKEN) : "";
  const es = new EventSource("/api/events" + qs);
  es.onmessage = (ev) => {
    try {
      const e = JSON.parse(ev.data);
      addEvent(e);
      // Also add query log entries for block/pass events
      if (e.type === "block" || e.type === "pass") {
        addQueryLog({
          at: e.at,
          instance: e.instance,
          client: e.client,
          domain: e.domain,
          action: e.type.toUpperCase(),
          upstream: e.upstream || "\u2014",
        });
      }
    } catch {}
  };
  es.onerror = () => {
    const c = document.getElementById("conn");
    c.textContent = "reconnecting...";
  };
}

// Tab switching
document.querySelectorAll(".tab[data-tab]").forEach((t) => {
  t.addEventListener("click", (e) => {
    e.preventDefault();
    switchTab(t.dataset.tab);
  });
});

// Handle browser back/forward navigation
window.addEventListener("popstate", () => {
  currentTab = getTabFromPath();
  switchTab(currentTab);
});

// Modal wiring
const modal = document.getElementById("modal");
const addBtn = document.getElementById("add-btn");
if (addBtn) addBtn.onclick = () => modal.classList.remove("hidden");
const iCancel = document.getElementById("i-cancel");
if (iCancel) iCancel.onclick = () => modal.classList.add("hidden");
const iSave = document.getElementById("i-save");
if (iSave) {
  iSave.onclick = async () => {
    const body = {
      id: document.getElementById("i-id").value.trim(),
      label: document.getElementById("i-label").value.trim(),
      url: document.getElementById("i-url").value.trim(),
      token: document.getElementById("i-token").value,
      claim: document.getElementById("i-claim").value.trim(),
    };
    if (!body.id || !body.url) return toast("id and url required");
    try {
      await api("/api/instances", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      modal.classList.add("hidden");
      toast("instance added");
      if (body.claim) {
        await api("/api/instances/" + encodeURIComponent(body.id) + "/adopt", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ code: body.claim }),
        });
        toast("adopted " + body.id);
      }
      refresh();
    } catch (e) {
      toast("add failed: " + e.message);
    }
  };
}

function refreshSettings(list) {
  const upstreamInput = document.getElementById("s-upstream");
  if (upstreamInput) {
    // Get upstream from first instance's default policy
    let upstream = "";
    for (const i of list) {
      if (i.stats && i.stats.upstream) {
        upstream = i.stats.upstream;
        break;
      }
    }
    upstreamInput.value = upstream;
  }
}

// --- Blocklist ---
let blocklistDomains = [];

async function refreshBlocklist() {
  try {
    const r = await api("/api/blocklist");
    const data = await r.json();
    blocklistDomains = data.domains || [];
    renderBlocklist();
  } catch (e) {
    console.error("refreshBlocklist:", e);
  }
}

function renderBlocklist() {
  const ul = document.getElementById("blocklist");
  if (!ul) return;
  const filter = document.getElementById("b-filter")?.value.toLowerCase() || "";
  ul.innerHTML = "";
  blocklistDomains.forEach((d) => {
    if (filter && !d.toLowerCase().includes(filter)) return;
    const li = document.createElement("li");
    li.className = "blocklist-item";
    li.innerHTML = '<span>' + esc(d) + '</span><button class="mini" data-remove="' + esc(d) + '">Remove</button>';
    ul.appendChild(li);
  });
  document.querySelectorAll("[data-remove]").forEach((b) => {
    b.onclick = async () => {
      const domain = b.getAttribute("data-remove");
      try {
        await api("/api/blocklist", {
          method: "DELETE",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ domain }),
        });
        toast("removed " + domain);
        refreshBlocklist();
      } catch (e) {
        toast("remove failed: " + e.message);
      }
    };
  });
}

document.getElementById("s-save")?.addEventListener("click", async () => {
  const upstream = document.getElementById("s-upstream")?.value.trim();
  if (!upstream) return toast("upstream required");
  // Apply to first online instance's default policy
  const list = await api("/api/instances").then((r) => r.json());
  const online = list.find((i) => i.online);
  if (!online) return toast("no online instances");
  try {
    await api("/api/instances/" + encodeURIComponent(online.id) + "/policy", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: "default", upstream }),
    });
    toast("upstream saved");
    refresh();
  } catch (e) {
    toast("save failed: " + e.message);
  }
});

document.getElementById("b-add")?.addEventListener("click", async () => {
  const domain = document.getElementById("b-domain")?.value.trim() || "";
  if (!domain) return toast("domain required");
  try {
    await api("/api/blocklist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
    });
    toast("blocked " + domain);
    document.getElementById("b-domain").value = "";
    refreshBlocklist();
  } catch (e) {
    toast("add failed: " + e.message);
  }
});

document.getElementById("b-filter")?.addEventListener("input", renderBlocklist);
document.getElementById("b-export")?.addEventListener("click", () => {
  window.open("/api/blocklist/export", "_blank");
});

refresh();
connectSSE();
setInterval(refresh, 5000);