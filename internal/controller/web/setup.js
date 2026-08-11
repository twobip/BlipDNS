(function () {
  var form = document.getElementById("setup-form");
  var err = document.getElementById("setup-err");
  var btn = document.getElementById("setup-btn");
  var label = document.getElementById("setup-label");

  var setupToken = new URLSearchParams(window.location.hash.replace(/^#/, "")).get("token") || "";
  form.addEventListener("submit", function (e) {
    e.preventDefault();
    err.classList.remove("show");
    var password = document.getElementById("setup-pass").value;
    var confirm = document.getElementById("setup-confirm").value;
    if (password !== confirm) {
      err.textContent = "Passwords do not match.";
      err.classList.add("show");
      return;
    }
    btn.disabled = true;
    label.textContent = "Creating account…";
    fetch("/api/setup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        token: setupToken,
        username: document.getElementById("setup-user").value.trim(),
        password: password,
        confirm: confirm,
      }),
    }).then(function (r) {
      if (r.ok) {
        window.location.href = "/";
        return null;
      }
      return r.text().then(function (text) { throw new Error(text || "Setup failed."); });
    }).catch(function (e) {
      err.textContent = e.message || "Setup failed.";
      err.classList.add("show");
      btn.disabled = false;
      label.textContent = "Create account";
    });
  });
})();
