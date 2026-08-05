// BlipDNS login page — external script (CSP `script-src 'self'` allows it).
// Submits credentials via fetch so the password never lands in the URL.
(function () {
  var form = document.getElementById("login-form");
  var err = document.getElementById("login-err");
  var btn = document.getElementById("login-btn");
  var label = document.getElementById("login-btn-label");

  form.addEventListener("submit", function (e) {
    e.preventDefault(); // never let the browser do a GET with credentials in the URL
    err.classList.remove("show");
    btn.disabled = true;
    label.textContent = "Signing in…";

    fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: document.getElementById("f-user").value.trim(),
        password: document.getElementById("f-pass").value,
      }),
    })
      .then(function (r) {
        if (r.ok) {
          window.location.href = "/";
          return;
        }
        return r.text().then(function (t) { throw new Error(r.status + ":" + (t || "")); });
      })
      .catch(function (ex) {
        label.textContent = "Sign in";
        btn.disabled = false;
        var code = parseInt(String(ex.message).split(":")[0], 10);
        var msg =
          code === 429 ? "Too many attempts. Wait a few minutes and try again."
          : code === 403 ? "Authentication is not configured on this controller."
          : "Invalid username or password.";
        err.textContent = msg;
        err.classList.add("show");
      });
  });
})();
