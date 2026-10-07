(function () {
  "use strict";

  var csrf = "";
  var view = "overview";
  var timer = null;
  var busy = { backup: false };

  /* ------------------------------------------------------------- helpers */
  function $(id) { return document.getElementById(id); }

  function api(method, path, body) {
    var opts = {
      method: method,
      headers: { "Content-Type": "application/json", "X-VS-CSRF": csrf },
      credentials: "same-origin"
    };
    if (body !== undefined) opts.body = JSON.stringify(body);
    return fetch(path, opts).then(function (r) {
      if (r.status === 401) { location.href = "/login"; throw new Error("auth"); }
      return r.json().then(function (j) {
        if (!r.ok && r.status !== 409) throw new Error(j.error || ("HTTP " + r.status));
        return j;
      });
    });
  }

  function bytes(n) {
    n = Number(n) || 0;
    var u = ["B", "KB", "MB", "GB", "TB"], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i === 0 ? n : n.toFixed(1)) + u[i];
  }

  function num(n) {
    n = Number(n) || 0;
    return n.toLocaleString("en-US");
  }

  function ago(ts) {
    if (!ts) return "-";
    var d;
    if (typeof ts === "string") { d = (Date.now() - Date.parse(ts)) / 1000; }
    else { d = (Date.now() / 1000) - ts; }
    if (isNaN(d)) return "-";
    if (d < 0) d = 0;
    if (d < 60) return Math.floor(d) + "s ago";
    if (d < 3600) return Math.floor(d / 60) + "m ago";
    if (d < 86400) return Math.floor(d / 3600) + "h ago";
    return Math.floor(d / 86400) + "d ago";
  }

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  function meter(el, pct) {
    if (!el) return;
    pct = Math.max(0, Math.min(100, Number(pct) || 0));
    el.style.width = pct + "%";
    el.className = pct >= 90 ? "bad" : (pct >= 75 ? "warn" : "");
  }

  function toast(msg, kind, sub) {
    var wrap = $("toasts");
    var el = document.createElement("div");
    el.className = "toast " + (kind || "");
    el.innerHTML = esc(msg) + (sub ? '<span class="t">' + esc(sub) + "</span>" : "");
    wrap.appendChild(el);
    setTimeout(function () {
      el.style.transition = "opacity .3s";
      el.style.opacity = "0";
      setTimeout(function () { el.remove(); }, 320);
    }, 4200);
  }

  function pill(text, kind) {
    return '<span class="pill ' + (kind || "") + '">' + esc(text) + "</span>";
  }

  function statePill(s) {
    s = String(s || "");
    if (s === "active" || s === "running" || s === "enabled") return pill(s, "ok");
    if (s === "failed" || s === "dead" || s === "disabled") return pill(s, "bad");
    if (s === "activating" || s === "reloading") return pill(s, "warn");
    return pill(s || "unknown");
  }

  /* --------------------------------------------------------------- toasts */
  function setHead(d) {
    var p = d.protection || {};
    $("hc-host").textContent = d.hostname || "-";
    $("hc-profile").textContent = p.profile || "-";
    $("hc-blocked").textContent = num(p.dropped || 0);
    $("nav-bans").textContent = num((d.bans || {}).total || 0);
    $("nav-drops").textContent = num((d.drops || []).length);
    $("sf-ver").textContent = d.version || "-";
    $("sf-uptime").textContent = (Math.round((d.uptime || 0) / 3600 * 10) / 10) + "h";
    $("sf-conn").textContent = num(d.conntrack || 0);
    var dot = $("hc-dot");
    dot.className = "dot " + (p.loaded ? "ok pulse" : "bad");
  }

  /* ------------------------------------------------------------ overview */
  function renderOverview(d) {
    setHead(d);

    var cpu = d.cpu || {};
    $("t-cpu").textContent = (cpu.percent || 0).toFixed(0) + "%";
    $("t-cpu-sub").textContent = "load " + (cpu.load || []).join(" / ") +
      " on " + (cpu.cores || "?") + " cores";
    meter($("m-cpu"), cpu.percent);

    var m = d.memory || {};
    $("t-mem").textContent = (m.percent || 0).toFixed(0) + "%";
    $("t-mem-sub").textContent = bytes(m.used) + " / " + bytes(m.total);
    meter($("m-mem"), m.percent);

    var disks = d.disks || [];
    var root = disks[0] || {};
    $("t-disk").textContent = (root.percent || 0).toFixed(0) + "%";
    $("t-disk-sub").textContent = bytes(root.used) + " / " + bytes(root.total);
    meter($("m-disk"), root.percent);

    var p = d.protection || {};
    $("t-pkt").textContent = num(p.packets || 0);
    $("t-pkt-sub").textContent = bytes(p.bytes || 0) + " inspected";
    drawSpark(d.spark || []);

    var meta = {};
    try { meta = d.sparkMeta || {}; } catch (e) {}
    $("p-applied").textContent = p.applied ? "applied " + ago(p.applied) : "not applied";
    $("p-rate").textContent = rateOf(p) || "-";
    $("p-conn").textContent = connOf(p) || "-";
    $("p-udp").textContent = udpOf(p) || "-";

    set("s-chain", p.loaded, p.loaded ? "loaded" : "not loaded");
    set("s-sysctl", p.sysctl, p.sysctl ? "active" : "missing");
    set("s-nginx", p.nginx, p.nginx ? "throttling" : "off");
    set("s-f2b", p.fail2ban, p.fail2ban ? "jails active" : "off");
    set("s-ufw", p.ufw, p.ufw ? "enabled" : "not enabled");

    // services
    var rows = (d.services || []).map(function (s) {
      return "<tr><td>" + esc(s.name) + "</td>" +
             '<td class="right">' + statePill(s.state) + "</td></tr>";
    }).join("");
    $("svc-body").innerHTML = rows || '<tr><td class="empty">no units</td></tr>';

    // events
    var ev = (d.events || []).slice(0, 12).map(function (e) {
      var k = e.level === "err" ? "bad" : (e.level === "warn" ? "warn" : "ok");
      return "<tr><td class=\"mono\" style=\"width:74px\">" + esc(e.ts.slice(11, 19) || "-") +
             "</td><td>" + pill(e.level, k) + "</td>" +
             '<td class="strong" style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:280px">' +
             esc(e.msg) + "</td></tr>";
    }).join("");
    $("events-body").innerHTML = ev || '<tr><td class="empty">no activity yet</td></tr>';

    // disks
    $("disk-body").innerHTML = (disks || []).map(function (dsk) {
      var cls = dsk.percent >= 90 ? "bad" : (dsk.percent >= 75 ? "warn" : "ok");
      return "<tr><td class=\"mono\">" + esc(dsk.mount) + "</td>" +
             '<td class="mono right">' + bytes(dsk.used) + " / " + bytes(dsk.total) + "</td>" +
             '<td class="right">' + pill(dsk.percent + "%", cls) + "</td></tr>";
    }).join("") || '<tr><td class="empty">no volumes</td></tr>';
  }

  function set(id, ok, txt) {
    var el = $(id);
    if (!el) return;
    el.innerHTML = '<span class="dot ' + (ok ? "ok" : "bad") + '"></span>' + esc(txt);
  }

  function rateOf(p) { return p.rate || p.profile && ""; }
  function connOf(p) { return p.conn ? p.conn + " / IP" : ""; }
  function udpOf(p) { return p.udp || ""; }

  function drawSpark(vals) {
    var svg = $("spark");
    if (!svg) return;
    if (!vals.length) { svg.innerHTML = ""; return; }
    var min = Math.min.apply(null, vals), max = Math.max.apply(null, vals);
    var span = (max - min) || 1;
    var pts = vals.map(function (v, i) {
      var x = vals.length === 1 ? 0 : (i / (vals.length - 1)) * 200;
      var y = 32 - ((v - min) / span) * 30;
      return x.toFixed(1) + "," + y.toFixed(1);
    }).join(" ");
    svg.innerHTML = '<polyline points="' + pts + '"/>';
  }

  /* -------------------------------------------------------------- drops */
  function renderDrops(d) {
    var rows = (d.drops || []).map(function (r) {
      return "<tr><td class=\"mono\">" + esc(r.ts) + "</td>" +
             "<td>" + pill(r.kind === "scan" ? "scan" : "flood",
                           r.kind === "scan" ? "warn" : "bad") + "</td>" +
             '<td class="mono strong">' + esc(r.ip) + "</td>" +
             '<td class="mono">' + esc(r.proto) + "</td>" +
             '<td class="mono">' + esc(r.port) + "</td>" +
             '<td class="right"><button class="btn sm danger" data-ban="' +
             esc(r.ip) + '">ban</button></td></tr>";
    }).join("");
    $("drops-body").innerHTML = rows || '<tr><td class="empty" colspan="6">no drops recorded - kernel log is clean</td></tr>';
    $("drops-count").textContent = (d.drops || []).length + " events";
    bindBanButtons();
  }

  /* ---------------------------------------------------------- protection */
  function renderProtection(d) {
    var p = d.protection || {};
    var meta = p;
    $("pr-rate").textContent = p.rate || "-";
    $("pr-conn").textContent = p.conn ? p.conn : "-";
    $("pr-udp").textContent = p.udp || "-";
    $("c-packets").textContent = num(p.packets || 0);
    $("c-bytes").textContent = bytes(p.bytes || 0);
    $("c-dropped").textContent = num(p.dropped || 0);
    $("c-rules").textContent = num(p.rules || 0);
    $("c-conn").textContent = num(d.conntrack || 0);
    $("c-applied").textContent = p.applied ? ago(p.applied) : "-";

    var active = p.profile || (d.config || {}).profile || "standard";
    Array.prototype.forEach.call($("seg-profile").children, function (b) {
      b.classList.toggle("on", b.dataset.profile === active);
    });
    var cfg = d.config || {};
    $("sw-log").checked = !!(cfg.log_drops === undefined ? true : cfg.log_drops);
    $("sw-ddos").checked = !!cfg.enable_ddos;
    $("sw-backup").checked = !!cfg.enable_backup;
  }

  /* ---------------------------------------------------------------- bans */
  function renderBans(data) {
    var jails = data.jails || [];
    $("jail-cards").innerHTML = jails.map(function (j) {
      var kind = j.currently_banned > 0 ? "bad" : "ok";
      return '<div class="card tile"><div class="k">' + esc(j.jail) + "</div>" +
             '<div class="v">' + num(j.currently_banned) + "</div>" +
             '<div class="sub">' + num(j.total_banned) + " lifetime bans</div>" +
             '<div style="margin-top:9px">' + pill(j.currently_banned > 0 ? "active bans" : "clear", kind) +
             "</div></div>";
    }).join("") || '<div class="card tile"><div class="k">fail2ban</div><div class="v">-</div><div class="sub">not installed</div></div>';

    var rows = [];
    jails.forEach(function (j) {
      (j.ips || []).forEach(function (ip) {
        rows.push("<tr><td class=\"mono\">" + esc(j.jail) + "</td>" +
                  '<td class="mono strong">' + esc(ip) + "</td>" +
                  '<td class="right"><button class="btn sm" data-unban="' + esc(ip) +
                  '" data-jail="' + esc(j.jail) + '">unban</button></td></tr>');
      });
    });
    $("ban-body").innerHTML = rows.join("") ||
      '<tr><td class="empty" colspan="3">no addresses currently banned</td></tr>';
    bindBanButtons();
  }

  function bindBanButtons() {
    Array.prototype.forEach.call(document.querySelectorAll("[data-unban]"), function (b) {
      b.onclick = function () {
        api("POST", "/api/unban", { jail: b.dataset.jail, ip: b.dataset.unban })
          .then(function (r) { toast(r.ok ? "Unbanned " + b.dataset.unban : "unban failed",
                                     r.ok ? "ok" : "bad"); refresh(true); })
          .catch(function (e) { toast("unban failed", "bad", e.message); });
      };
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-ban]"), function (b) {
      b.onclick = function () {
        api("POST", "/api/ban", { jail: "vs-portscan", ip: b.dataset.ban })
          .then(function (r) { toast(r.ok ? "Banned " + b.dataset.ban : "ban failed",
                                     r.ok ? "ok" : "bad"); refresh(true); })
          .catch(function (e) { toast("ban failed", "bad", e.message); });
      };
    });
  }

  /* ------------------------------------------------------------- backups */
  function renderBackups(d) {
    var hist = (d.history || {}).runs || [];
    var last = (d.history || {}).last || null;
    var files = d.files || [];
    var verify = {};
    (d.verify || []).forEach(function (v) { verify[v.file] = v; });

    $("b-dbname").textContent = (d.config && d.config.db_name) || "panel";
    if (last) {
      $("b-last").textContent = last.ok ? "ok" : "failed";
      $("b-last").style.color = last.ok ? "var(--ok)" : "var(--danger)";
      $("b-last-sub").textContent = ago(last.at) + " · " + last.duration + "s";
      $("b-size").textContent = bytes(last.zip || last.size || 0);
      $("b-size-sub").textContent = last.file || "-";
      $("b-deliv").textContent = last.delivered ? "sent" : (last.error ? "error" : "local");
      $("b-deliv-sub").textContent = last.chunks ? last.chunks + " message part(s)" : "not uploaded";
    }
    $("b-count").textContent = files.length + " files";
    $("b-count-sub").textContent = files.length ? bytes(files.reduce(function (a, f) { return a + f.size; }, 0)) : "-";

    $("hist-body").innerHTML = hist.map(function (r) {
      return "<tr><td class=\"mono\">" + esc(ago(r.at)) + "</td>" +
             '<td class="mono strong" style="max-width:200px;overflow:hidden;text-overflow:ellipsis">' + esc(r.file || "-") + "</td>" +
             '<td class="mono right">' + bytes(r.zip || 0) + "</td>" +
             '<td class="mono right">' + esc(r.duration + "s") + "</td>" +
             "<td>" + (r.ok ? pill(r.delivered ? "discord" : "local", r.delivered ? "ok" : "warn")
                            : pill("failed", "bad")) + "</td></tr>";
    }).join("") || '<tr><td class="empty" colspan="5">no runs yet</td></tr>';

    $("files-body").innerHTML = files.map(function (f) {
      var v = verify[f.file];
      return "<tr><td class=\"mono strong\" style=\"max-width:230px;overflow:hidden;text-overflow:ellipsis\">" +
             esc(f.file) + "</td>" +
             '<td class="mono right">' + bytes(f.size) + "</td>" +
             '<td class="mono right">' + esc(f.age) + "</td>" +
             "<td>" + (v ? (v.valid ? pill("valid", "ok") : pill("bad", "bad")) : pill("unchecked")) + "</td></tr>";
    }).join("") || '<tr><td class="empty" colspan="4">no archives</td></tr>';

    $("btn-backup").disabled = d.running;
    $("btn-backup").innerHTML = d.running ? '<span class="spin"></span> running' : "Run backup now";
  }

  /* ------------------------------------------------------------ settings */
  function renderSettings(d) {
    var c = d.config || {};
    $("c-backup_at").value = c.backup_at || "02:00";
    $("c-backup_retention").value = c.backup_retention || 7;
    $("c-backup_compress").value = c.backup_compress == null ? 6 : c.backup_compress;
    $("c-mention").value = c.mention_id || "";
    $("c-nginx_rate").value = c.nginx_rate || "10r/s";
    $("c-nginx_burst").value = c.nginx_burst || 30;
    $("c-nginx_conn").value = c.nginx_conn || 25;
    $("c-f2b_http_ban").value = c.f2b_http_ban || 600;
    $("c-f2b_flood_ban").value = c.f2b_flood_ban || 1800;
    $("k-alert").textContent = c.webhook_alert || "not set";
    $("k-backup").textContent = c.webhook_backup || "not set";
    $("k-token").textContent = c.has_token ? "configured" : "missing";
    $("k-db").textContent = c.db_name || "-";
    $("k-port").textContent = c.dash_port || "-";

    var u = d.ufw || {};
    $("u-state").innerHTML = statePill(u.active ? "active" : "inactive");
    $("u-in").textContent = u.default_in || "-";
    $("u-count").textContent = (u.rules || []).length;
  }

  /* -------------------------------------------------------------- router */
  var TITLES = {
    overview: "Overview", drops: "Blocked traffic", protection: "Protection",
    bans: "Bans & jails", backups: "Backups", settings: "Settings"
  };

  function show(name) {
    view = name;
    Array.prototype.forEach.call(document.querySelectorAll("section[id^=view-]"),
      function (s) { s.classList.toggle("hide", s.id !== "view-" + name); });
    Array.prototype.forEach.call(document.querySelectorAll(".nav button"),
      function (b) { b.classList.toggle("active", b.dataset.view === name); });
    $("title").textContent = TITLES[name] || name;
    refresh(true);
  }

  function paint(d) {
    if (view === "overview") renderOverview(d);
    if (view === "drops") renderDrops(d);
    if (view === "protection") renderProtection(d);
    if (view === "backups") renderBackups(d);
    if (view === "settings") renderSettings(d);
  }

  function refresh(force) {
    if (view === "bans") {
      api("GET", "/api/bans").then(renderBans).catch(function () {});
      api("GET", "/api/config").then(function (c) {
        renderBans._cfg = c;
      }).catch(function () {});
      api("GET", "/api/overview").then(setHead).catch(function () {});
      return;
    }
    api("GET", "/api/overview").then(paint).catch(function (e) {
      if (e.message !== "auth") console.warn(e);
    });
    if (view === "drops") {
      api("GET", "/api/drops").then(renderDrops).catch(function () {});
    }
    if (view === "backups") {
      api("GET", "/api/backups").then(renderBackups).catch(function () {});
    }
  }

  function loop() {
    clearInterval(timer);
    var ms = view === "overview" ? 5000 : 12000;
    timer = setInterval(refresh, ms);
  }

  /* --------------------------------------------------------------- wire */
  function boot() {
    api("GET", "/api/session").then(function (s) {
      csrf = s.csrf;
      Array.prototype.forEach.call(document.querySelectorAll(".nav button"),
        function (b) { b.onclick = function () { show(b.dataset.view); loop(); }; });
      $("refresh").onclick = function () { refresh(true); toast("refreshed"); };
      $("logout").onclick = function () {
        api("POST", "/api/logout", {}).then(function () { location.href = "/login"; });
      };

      $("drops-refresh").onclick = function () { refresh(true); };

      Array.prototype.forEach.call($("seg-profile").children, function (b) {
        b.onclick = function () {
          var prof = b.dataset.profile;
          api("POST", "/api/protection", { profile: prof, log_drops: $("sw-log").checked })
            .then(function () {
              toast("profile set to " + prof, "ok", "chain rebuilt");
              refresh(true);
            })
            .catch(function (e) { toast("failed to apply", "bad", e.message); });
        };
      });

      $("btn-reload").onclick = function () {
        var btn = this; btn.disabled = true;
        api("POST", "/api/protection/reload", {})
          .then(function () { toast("protection re-applied", "ok",
            "chain, nginx and fail2ban refreshed"); refresh(true); })
          .catch(function (e) { toast("reload failed", "bad", e.message); })
          .finally(function () { btn.disabled = false; });
      };

      $("btn-save-protection").onclick = function () {
        api("POST", "/api/config", {
          log_drops: $("sw-log").checked ? 1 : 0,
          enable_backup: $("sw-backup").checked ? 1 : 0,
          enable_ddos: $("sw-ddos").checked ? 1 : 0
        }).then(function () { toast("module state saved", "ok"); refresh(true); })
          .catch(function (e) { toast("save failed", "bad", e.message); });
      };

      $("btn-ban").onclick = function () {
        var ip = $("mb-ip").value.trim();
        if (!ip) { toast("enter an address", "bad"); return; }
        api("POST", "/api/ban", { jail: $("mb-jail").value, ip: ip })
          .then(function (r) { toast(r.ok ? "banned " + ip : "refused", r.ok ? "ok" : "bad", r.msg); $("mb-ip").value = ""; refresh(true); })
          .catch(function (e) { toast("ban failed", "bad", e.message); });
      };

      $("btn-backup").onclick = function () {
        if (busy.backup) return;
        busy.backup = true;
        api("POST", "/api/backup/run", {})
          .then(function (r) { toast(r.msg || "started", "ok", "watch the Backups tab"); setTimeout(refresh, 1200); })
          .catch(function (e) { toast("could not start", "bad", e.message); })
          .finally(function () { busy.backup = false; });
      };

      $("btn-save-config").onclick = function () {
        var body = {
          backup_at: $("c-backup_at").value.trim(),
          backup_retention: parseInt($("c-backup_retention").value, 10) || 7,
          backup_compress: parseInt($("c-backup_compress").value, 10) || 0,
          mention_id: $("c-mention").value.trim(),
          nginx_rate: $("c-nginx_rate").value.trim(),
          nginx_burst: parseInt($("c-nginx_burst").value, 10) || 30,
          nginx_conn: parseInt($("c-nginx_conn").value, 10) || 25,
          f2b_http_ban: parseInt($("c-f2b_http_ban").value, 10) || 600,
          f2b_flood_ban: parseInt($("c-f2b_flood_ban").value, 10) || 1800
        };
        api("POST", "/api/config", body)
          .then(function (r) { toast("settings saved", "ok"); if (r.config) renderSettings({ config: r.config, ufw: renderSettings._u }); })
          .catch(function (e) { toast("save failed", "bad", e.message); });
      };

      $("btn-ufw").onclick = function () {
        var btn = this; btn.disabled = true;
        api("POST", "/api/ufw/reload", { enable: true })
          .then(function (r) { toast(r.ok ? "ufw rules re-synced" : "ufw sync failed",
                                     r.ok ? "ok" : "bad", (r.allowed || []).length + " rules"); refresh(true); })
          .catch(function (e) { toast("failed", "bad", e.message); })
          .finally(function () { btn.disabled = false; });
      };

      show("overview");
      loop();
    }).catch(function () { location.href = "/login"; });
  }

  boot();
})();
