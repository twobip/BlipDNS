// BlipDNS Controller dashboard JS. Talks to the controller API and SSE feed.
const TOKEN = new URLSearchParams(location.search).get("token") || "";
const AUTH = TOKEN ? "Bearer " + TOKEN : "";

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

function renderInstances(list) {
  const el = document.getElementById("instances");
  el.innerHTML = "";
  if (!list.length) {
    el.innerHTML = '<div class="card"><h3>No instances</h3><div class="sub">Click + to add a blipd instance</div></div>';
    return;
  }
  for (const i of list) {
    const s = i.stats || {};
    const card = document.createElement("div");
    card.className = "card";
    card.innerHTML = `
      <h3>${esc(i.label)} <span class="badge ${i.online ? "on" : "off"}">${i.online ? "online" : "offline"}</span></h3>
      <div class="sub">${esc(i.url)}</div>
      <div class="stat"><span>queries</span><span>${s.queries_total ?? 0}</span></div>
      <div class="stat"><span>blocked</span><span>${s.blocked_total ?? 0}</span></div>
      <div class="stat"><span>upstream errs</span><span>${s.upstream_errors ?? 0}</span></div>
      <div class="stat"><span>cache</span><span>${s.cached ?? 0}</span></div>
    `;
    el.appendChild(card);
  }
}

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

let total = 0;
function addEvent(e) {
  const filter = document.getElementById("f-domain").value.toLowerCase();
  if (filter && !((e.domain || "").toLowerCase().includes(filter)) && !((e.client || "").toLowerCase().includes(filter))) return;
  total++;
  document.getElementById("event-count").textContent = total + " events";
  const ul = document.getElementById("events");
  const li = document.createElement("li");
  const time = new Date(e.at).toLocaleTimeString();
  const cls = "type-" + e.type;
  let text = "";
  if (e.type === "block") text = `BLOCK ${e.domain} ← ${e.client}`;
  else if (e.type === "policy") text = `POLICY ${e.msg || e.domain}`;
  else if (e.type === "health") text = `health ok (q=${e.stats ? e.stats.queries_total : 0})`;
  else text = e.type;
  li.innerHTML = `<span class="t">${time}</span><span class="${cls}">[${esc(e.instance)}]</span><span>${esc(text)}</span>`;
  ul.prepend(li);
  while (ul.children.length > 200) ul.removeChild(ul.lastChild);
}

async function refresh() {
  try {
    const list = await api("/api/instances").then((r) => r.json());
    renderInstances(list);
    const conn = document.getElementById("conn");
    conn.textContent = list.filter((i) => i.online).length + "/" + list.length + " online";
    conn.className = "badge " + (list.some((i) => i.online) ? "on" : "off");
  } catch (err) {
    document.getElementById("conn").textContent = "error";
  }
}

function connectSSE() {
  const qs = TOKEN ? "?token=" + encodeURIComponent(TOKEN) : "";
  const es = new EventSource("/api/events" + qs);
  es.onmessage = (ev) => { try { addEvent(JSON.parse(ev.data)); } catch {} };
  es.onerror = () => { const c = document.getElementById("conn"); c.textContent = "reconnecting…"; };
}

// modal wiring
const modal = document.getElementById("modal");
document.getElementById("add-btn").onclick = () => modal.classList.remove("hidden");
document.getElementById("i-cancel").onclick = () => modal.classList.add("hidden");
document.getElementById("i-save").onclick = async () => {
  const body = {
    id: document.getElementById("i-id").value.trim(),
    label: document.getElementById("i-label").value.trim(),
    url: document.getElementById("i-url").value.trim(),
    token: document.getElementById("i-token").value,
  };
  if (!body.id || !body.url) return toast("id and url required");
  try {
    await api("/api/instances", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    modal.classList.add("hidden");
    toast("instance added");
    refresh();
  } catch (e) { toast("add failed: " + e.message); }
};

document.getElementById("f-domain").oninput = () => {};

refresh();
connectSSE();
setInterval(refresh, 5000);
