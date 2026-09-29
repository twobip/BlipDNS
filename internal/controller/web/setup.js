(function () {
  var err = document.getElementById("setup-err");
  var ok = document.getElementById("setup-ok");
  var prevBtn = document.getElementById("setup-prev");
  var nextBtn = document.getElementById("setup-next");
  var skipBtn = document.getElementById("setup-skip");
  var nav = document.getElementById("setup-nav");

  var setupToken = new URLSearchParams(window.location.hash.replace(/^#/, "")).get("token") || "";
  var step = 1;
  var accountDone = false;
  var adopted = false;
  var initialBind = { host: window.location.hostname, port: window.location.port || (window.location.protocol === "https:" ? "443" : "80") };

  function $(id) { return document.getElementById(id); }
  function fail(msg) { err.textContent = msg; err.classList.add("show"); }
  function clear() { err.classList.remove("show"); ok.classList.remove("show"); }
  function note(msg) { ok.textContent = msg; ok.classList.add("show"); }
  function api(path, body) {
    return fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }).then(function (r) {
      if (r.ok) return r.json().catch(function () { return {}; });
      return r.text().then(function (text) { throw new Error(text || "Request failed."); });
    });
  }

  function go(n) {
    step = n;
    clear();
    [1, 2, 3, 4].forEach(function (i) { $("step-" + i).classList.toggle("hidden", i !== n); });
    var dots = document.querySelectorAll("#setup-steps .st");
    dots.forEach(function (d) {
      var s = parseInt(d.getAttribute("data-step"), 10);
      d.classList.toggle("on", s === Math.min(n, 3));
      d.classList.toggle("done", s < Math.min(n, 3) || (n === 4 && s === 3 && adopted) || (n === 4 && s <= 3 && accountDone));
    });
    // Bottom nav per step.
    prevBtn.style.display = (n === 2 || n === 3) ? "" : "none";
    nextBtn.style.display = (n === 2) ? "" : "none";
    skipBtn.style.display = (n === 3 && !adopted) ? "" : "none";
    nav.style.display = (n === 1 || n === 4) ? "none" : "";
    if (n === 2) {
      if ($("bind-host").value === "") $("bind-host").value = initialBind.host;
      if ($("bind-port").value === "") $("bind-port").value = initialBind.port;
    }
  }

  // Step 1: account creation (also signs us in for the later steps).
  $("step-1").addEventListener("submit", function (e) {
    e.preventDefault();
    if (accountDone) { go(2); return; }
    clear();
    var password = $("setup-pass").value;
    var confirm = $("setup-confirm").value;
    if (password !== confirm) { fail("Passwords do not match."); return; }
    var btn = $("setup-btn");
    btn.disabled = true;
    $("setup-label").textContent = "Creating account…";
    api("/api/setup", {
      token: setupToken,
      username: $("setup-user").value.trim(),
      password: password,
      confirm: confirm,
    }).then(function () {
      accountDone = true;
      go(2);
    }).catch(function (e2) {
      fail(e2.message || "Setup failed.");
      btn.disabled = false;
      $("setup-label").textContent = "Create account & continue";
    });
  });

  // Step 2: bind address. Saved only when changed; needs a restart to apply.
  function saveBind() {
    var host = $("bind-host").value.trim();
    var port = $("bind-port").value.trim();
    if (!host) { fail("Interface/host is required."); return Promise.resolve(false); }
    if (!/^\d+$/.test(port) || +port < 1 || +port > 65535) { fail("Port must be 1-65535."); return Promise.resolve(false); }
    if (host === initialBind.host && port === String(initialBind.port)) return Promise.resolve(true);
    nextBtn.disabled = true;
    return api("/api/setup/listen", { listen: host + ":" + port }).then(function (res) {
      nextBtn.disabled = false;
      note("Bind address saved (" + res.listen + "). Restart the controller to apply it.");
      return true;
    }).catch(function (e) {
      nextBtn.disabled = false;
      fail(e.message || "Could not save bind address.");
      return false;
    });
  }

  prevBtn.addEventListener("click", function () { if (step > 1) go(step - 1); });
  nextBtn.addEventListener("click", function () {
    if (step !== 2) return;
    clear();
    saveBind().then(function (saved) { if (saved) go(3); });
  });
  skipBtn.addEventListener("click", function () { go(4); });

  // Step 3: adopt one instance. Single call: the server adopts server-side
  // when a claim is present and reports the outcome.
  $("adopt-btn").addEventListener("click", function () {
    clear();
    var id = $("adopt-id").value.trim();
    var url = $("adopt-url").value.trim();
    var claim = $("adopt-claim").value.trim();
    if (!id || !url) { fail("Instance ID and management URL are required."); return; }
    var btn = $("adopt-btn");
    btn.disabled = true;
    $("adopt-btn-label").textContent = "Adopting…";
    api("/api/instances", {
      id: id,
      label: $("adopt-label").value.trim(),
      url: url,
      token: $("adopt-token").value,
      claim: claim,
    }).then(function (res) {
      if (claim && !res.adopted) throw new Error("Added, but adoption failed — retry the code or Skip for now.");
      adopted = true;
      btn.disabled = false;
      $("adopt-btn-label").textContent = "Adopt instance";
      note(claim ? ("Adopted " + id + ".") : ("Added " + id + "."));
      go(4);
    }).catch(function (e) {
      btn.disabled = false;
      $("adopt-btn-label").textContent = "Adopt instance";
      fail(e.message || "Adopt failed.");
    });
  });

  go(1);
})();
