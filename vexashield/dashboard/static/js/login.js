(function () {
  "use strict";
  var form = document.getElementById("form");
  var err = document.getElementById("err");
  var submit = document.getElementById("submit");

  fetch("/api/health", { credentials: "same-origin" })
    .then(function (r) { return r.json(); })
    .then(function (j) {
      document.getElementById("foot").textContent = "VexaShield v" + (j.version || "1.0.0");
    })
    .catch(function () {});

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    err.textContent = "";
    submit.disabled = true;
    submit.textContent = "Verifying...";
    fetch("/api/login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: document.getElementById("token").value })
    })
      .then(function (r) { return r.json().then(function (j) { return { s: r.status, j: j }; }); })
      .then(function (res) {
        if (res.s === 200 && res.j.ok) {
          location.href = "/";
          return;
        }
        err.textContent = res.j.error || "sign in failed";
        submit.disabled = false;
        submit.textContent = "Sign in";
        document.getElementById("token").select();
      })
      .catch(function () {
        err.textContent = "network error";
        submit.disabled = false;
        submit.textContent = "Sign in";
      });
  });
})();
