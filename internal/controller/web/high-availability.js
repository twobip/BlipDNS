/* High Availability / LAN VRRP view. */
let haData = { cluster: {}, statuses: {} };
let haAutoIPBound = false;

async function loadHighAvailability() {
  try {
    const r = await API("/api/high-availability");
    haData = await r.json();
    renderHighAvailability();
  } catch (e) {
    const el = $("ha-error");
    if (el) { el.textContent = e.message; el.hidden = false; }
  }
}

function haInstanceOptions(selected) {
  return instances.map((i) => `<option value="${esc(i.id)}" ${i.id === selected ? "selected" : ""}>${esc(i.label || i.id)}</option>`).join("");
}

/* Best-effort node IP: parse the host out of the instance management URL. */
function haNodeIP(instId) {
  const inst = instances.find((i) => i.id === instId);
  if (!inst || !inst.url) return "";
  try { return new URL(inst.url).hostname; } catch (e) { return ""; }
}

function renderHighAvailability() {
  const c = haData.cluster || {};
  const p = c.primary || {}, s = c.secondary || {};
  const status = $("ha-status");
  const statuses = haData.statuses || {};
  const active = Object.values(statuses).some((v) => v && v.active);
  if (status) { status.textContent = c.enabled ? (active ? "active" : "configured") : "disabled"; status.className = "badge " + (active ? "on" : c.enabled ? "warn" : "off"); }
  const set = (id, value) => { const el = $(id); if (el) el.value = value ?? ""; };
  const check = (id, value) => { const el = $(id); if (el) el.checked = !!value; };
  check("ha-enabled", c.enabled);
  set("ha-primary", c.primary_instance);
  set("ha-secondary", c.secondary_instance);
  set("ha-mode", p.mode || "unicast");
  set("ha-primary-if", p.interface);
  set("ha-secondary-if", s.interface || p.interface);
  set("ha-primary-ip", p.source_ip);
  set("ha-secondary-ip", s.source_ip);
  set("ha-vip", p.virtual_ip);
  set("ha-router-id", p.virtual_router_id || 51);
  set("ha-primary-priority", p.priority || 101);
  set("ha-secondary-priority", s.priority || 100);
  set("ha-advert", p.advert_interval_sec || 1);
  // The API deliberately redacts the VRRP password. Keep the value already
  // entered in the form so a refresh does not accidentally clear it.
  if (p.auth_pass !== undefined) set("ha-auth", p.auth_pass || "");
  const psel = $("ha-primary"), ssel = $("ha-secondary");
  if (psel) psel.innerHTML = `<option value="">Select primary…</option>${haInstanceOptions(c.primary_instance)}`;
  if (ssel) ssel.innerHTML = `<option value="">Select secondary…</option>${haInstanceOptions(c.secondary_instance)}`;
  /* Auto-fill the node IP when an instance is picked; fill blank fields on load. */
  if (!haAutoIPBound) {
    haAutoIPBound = true;
    if (psel) psel.addEventListener("change", () => { const ip = $("ha-primary-ip"); if (ip) ip.value = haNodeIP(psel.value); });
    if (ssel) ssel.addEventListener("change", () => { const ip = $("ha-secondary-ip"); if (ip) ip.value = haNodeIP(ssel.value); });
  }
  const pip = $("ha-primary-ip"), sip = $("ha-secondary-ip");
  if (pip && !pip.value && psel && psel.value) pip.value = haNodeIP(psel.value);
  if (sip && !sip.value && ssel && ssel.value) sip.value = haNodeIP(ssel.value);
  const rows = $("ha-node-status");
  if (rows) rows.innerHTML = instances.map((i) => {
    const st = statuses[i.id] || {};
    return `<div class="ha-status-row"><span class="dot ${st.active ? "on" : st.state === "FAULT" ? "err" : "off"}"></span><strong>${esc(i.label || i.id)}</strong><span class="muted">${esc(st.state || "unknown")}</span><span class="cell-sub">${esc(st.message || st.last_error || "")}</span></div>`;
  }).join("") || `<div class="muted">Add and adopt two blipd instances first.</div>`;
}

function buildHACluster() {
  const value = (id) => $(id)?.value.trim() || "";
  const primary = {
    enabled: $("ha-enabled")?.checked || false, mode: value("ha-mode"), node_role: "primary",
    interface: value("ha-primary-if"), source_ip: value("ha-primary-ip"), peer_ip: value("ha-secondary-ip"),
    virtual_ip: value("ha-vip"), virtual_router_id: Number(value("ha-router-id")), priority: Number(value("ha-primary-priority")),
    advert_interval_sec: Number(value("ha-advert")), auth_pass: value("ha-auth")
  };
  const secondary = { ...primary, node_role: "secondary", interface: value("ha-secondary-if"), source_ip: value("ha-secondary-ip"), peer_ip: value("ha-primary-ip"), priority: Number(value("ha-secondary-priority")) };
  return { enabled: primary.enabled, primary_instance: value("ha-primary"), secondary_instance: value("ha-secondary"), primary, secondary };
}

async function saveHA() {
  const r = await API("/api/high-availability", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ cluster: buildHACluster() }) });
  if (!r.ok) throw new Error(await r.text());
  toast("High availability configuration saved");
  await loadHighAvailability();
}

async function haAction(action) {
  const r = await API(`/api/high-availability?action=${encodeURIComponent(action)}`, { method: "POST" });
  if (!r.ok) throw new Error(await r.text());
  toast(action === "apply" ? "VRRP applied" : `keepalived ${action} complete`);
  await loadHighAvailability();
}

function initHA() {
  $("ha-save")?.addEventListener("click", () => saveHA().catch((e) => toast(e.message, "err")));
  ["validate", "apply", "disable"].forEach((action) => $("ha-" + action)?.addEventListener("click", () => haAction(action).catch((e) => toast(e.message, "err")));
}
