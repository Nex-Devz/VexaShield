(function () {
  "use strict";

  function num(n) {
    return String(Number(n) || 0).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  }

  function ago(iso) {
    if (!iso) return "-";
    var t = Date.parse(iso);
    if (isNaN(t)) return iso;
    var s = Math.max(0, (Date.now() - t) / 1000);
    if (s < 90) return Math.round(s) + "s ago";
    if (s < 5400) return Math.round(s / 60) + "m ago";
    if (s < 172800) return Math.round(s / 3600) + "h ago";
    return Math.round(s / 86400) + "d ago";
  }

  function uptime(sec) {
    var d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600),
        m = Math.floor((sec % 3600) / 60);
    if (d > 0) return d + "d " + h + "h";
    if (h > 0) return h + "h " + m + "m";
    return m + "m";
  }

  function text(id, value) {
    var el = document.getElementById(id);
    if (el) el.textContent = value;
  }

  function render(j) {
    var p = j.protection || {};
    var live = p.loaded && j.enabled;

    document.getElementById("s-dot").className = "dot " + (live ? "ok" : "bad");
    text("s-state", live ? "protected" : "not loaded");
    text("s-profile", j.profile || "-");
    text("s-blocked", num(p.dropped));

    text("t-protection", live ? "active" : (j.enabled ? "loading" : "off"));
    text("t-packets", num(p.packets));
    text("t-dropped", num(p.dropped));

    var last = j.backup && j.backup.last;
    text("t-backup", last ? (last.ok ? "ok" : "failed") : "-");
    text("t-backup-sub", last ? ago(last.at) : "no run recorded");

    text("r-version", (j.product || "VexaShield") + " " + (j.version || ""));
    text("r-profile", j.profile || "-");
    text("r-applied", p.applied ? ago(p.applied) : "-");
    text("r-rules", num(p.rules));
    text("r-bans", num(j.bans));
    text("r-uptime", j.uptime ? uptime(j.uptime) : "-");
    text("r-backups", j.backup ? num(j.backup.files) : "0");
  }

  function load() {
    fetch("/api/public", { credentials: "omit" })
      .then(function (r) { return r.json(); })
      .then(render)
      .catch(function () {
        document.getElementById("s-dot").className = "dot bad";
        text("s-state", "unreachable");
      });
  }

  load();
  setInterval(load, 15000);
})();
