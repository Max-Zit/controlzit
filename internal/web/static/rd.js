// RMMZit remote desktop viewer. Screen updates arrive as binary
// WebSocket messages (see internal/proto/rd.go); input goes back as JSON.
(function () {
  "use strict";
  var root = document.getElementById("rd");
  if (!root) return;
  var canvas = document.getElementById("rd-canvas");
  var ctx = canvas.getContext("2d");
  var status = document.getElementById("rd-status");
  var t = function (k) { return root.getAttribute("data-t-" + k) || k; };
  var proto = location.protocol === "https:" ? "wss://" : "ws://";
  var ws = new WebSocket(proto + location.host + root.getAttribute("data-ws"));
  ws.binaryType = "arraybuffer";
  var open = false;
  var pending = Promise.resolve();
  var clipOn = root.getAttribute("data-clip") === "1";
  var lastClip = ""; // text both sides already have
  var monSel = document.getElementById("rd-monitor");
  var clipBtn = document.getElementById("rd-clip");

  function send(o) { if (open && ws.readyState === 1) ws.send(JSON.stringify(o)); }
  function setStatus(s, cls) { status.textContent = s; status.className = "rd-status " + (cls || ""); }

  ws.onopen = function () { setStatus(t("connecting")); };
  ws.onclose = function () {
    open = false;
    if (!status.classList.contains("err")) setStatus(t("closed"), "err");
    root.classList.add("closed");
  };
  ws.onmessage = function (ev) {
    if (typeof ev.data === "string") {
      try {
        var m = JSON.parse(ev.data);
        if (m.t === "error" && m.for && waiting[m.for]) { waiting[m.for].fail(m.text); delete waiting[m.for]; }
        else if (m.t === "error") setStatus(m.text, "err");
        else if (waiting[m.t]) { waiting[m.t].ok(m); delete waiting[m.t]; }
        else if (m.t === "copied") remoteFiles(m.items || []);
      } catch (e) { /* ignore */ }
      return;
    }
    var b = new DataView(ev.data);
    var kind = b.getUint8(0);
    if (kind === 1) { // screen info
      var info = JSON.parse(new TextDecoder().decode(new Uint8Array(ev.data, 1)));
      open = true;
      if (canvas.width !== info.w || canvas.height !== info.h) { canvas.width = info.w; canvas.height = info.h; fit(); }
      setStatus(t("connected") + " · " + info.w + "×" + info.h + (info.desktop && info.desktop !== "Default" ? " · " + t("signin") : ""), "ok");
      showMonitors(info.monitors || [], info.monitor);
    } else if (kind === 4) { // the remote clipboard changed
      remoteCopied(new TextDecoder().decode(new Uint8Array(ev.data, 1)));
    } else if (kind === 2) { // tiles
      var n = b.getUint16(1), off = 3, jobs = [];
      for (var i = 0; i < n; i++) {
        var x = b.getUint16(off), y = b.getUint16(off + 2), len = b.getUint32(off + 8);
        var blob = new Blob([new Uint8Array(ev.data, off + 12, len)], { type: "image/jpeg" });
        jobs.push(createImageBitmap(blob).then((function (x, y) { return function (img) { return { x: x, y: y, img: img }; }; })(x, y)));
        off += 12 + len;
      }
      // Draw batches in order, then let the agent send the next one.
      pending = pending.then(function () { return Promise.all(jobs); }).then(function (imgs) {
        imgs.forEach(function (o) { ctx.drawImage(o.img, o.x, o.y); o.img.close(); });
        send({ t: "ack" });
      }).catch(function () { send({ t: "ack" }); });
    }
  };

  // ---- mouse
  var mx = 0, my = 0, buttons = 0, moved = false;
  function pos(e) {
    var r = canvas.getBoundingClientRect();
    mx = Math.round((e.clientX - r.left) * canvas.width / r.width);
    my = Math.round((e.clientY - r.top) * canvas.height / r.height);
  }
  function mouse(wheel) { send({ t: "m", x: mx, y: my, b: buttons, w: wheel || 0 }); }
  var bit = { 0: 1, 1: 4, 2: 2 };
  canvas.addEventListener("mousemove", function (e) { pos(e); moved = true; });
  canvas.addEventListener("mousedown", function (e) { e.preventDefault(); focusKbd(); pos(e); buttons |= bit[e.button] || 0; mouse(); });
  canvas.addEventListener("mouseup", function (e) { e.preventDefault(); pos(e); buttons &= ~(bit[e.button] || 0); mouse(); });
  canvas.addEventListener("contextmenu", function (e) { e.preventDefault(); });
  canvas.addEventListener("wheel", function (e) { e.preventDefault(); pos(e); mouse(e.deltaY > 0 ? -120 : 120); }, { passive: false });
  (function loop() {
    if (moved) { moved = false; mouse(); }
    requestAnimationFrame(loop);
  })();

  // ---- keyboard (physical keys; the remote layout applies)
  // Keys go to a hidden text field: that way the browser hands over the
  // local clipboard in its paste event (Ctrl+V, Shift+Insert) without asking
  // for a permission. The paste key reaches the remote computer only after
  // the text is on its clipboard.
  var kbd = document.createElement("textarea");
  kbd.className = "rd-kbd";
  kbd.setAttribute("aria-label", canvas.getAttribute("aria-label") || "Remote screen");
  kbd.setAttribute("autocomplete", "off"); kbd.setAttribute("autocapitalize", "off"); kbd.setAttribute("spellcheck", "false");
  root.appendChild(kbd);
  function focusKbd() { kbd.focus({ preventScroll: true }); }
  canvas.addEventListener("focus", focusKbd);
  var down = {};
  var held = null; // the paste key, waiting for the paste event
  function key(code, isDown) { send({ t: "k", code: code, down: isDown }); }
  function isPaste(e) {
    return (e.code === "KeyV" && (e.ctrlKey || e.metaKey) && !e.altKey) || (e.code === "Insert" && e.shiftKey && !e.ctrlKey);
  }
  function releaseHeld() {
    if (!held) return;
    var c = held; held = null;
    key(c.code, true);
    if (c.up) key(c.code, false);
  }
  kbd.addEventListener("keydown", function (e) {
    if (e.isComposing) return;
    down[e.code] = true;
    if (clipOn && isPaste(e) && !e.repeat) {
      // Let the browser fire the paste event; send the key after it.
      releaseHeld();
      held = { code: e.code, up: false };
      setTimeout(releaseHeld, 400); // nothing (or no text) on the local clipboard
      return;
    }
    e.preventDefault();
    key(e.code, true);
  });
  kbd.addEventListener("keyup", function (e) {
    e.preventDefault();
    delete down[e.code];
    if (held && held.code === e.code) { held.up = true; return; }
    key(e.code, false);
  });
  kbd.addEventListener("paste", function (e) {
    e.preventDefault();
    var files = e.clipboardData ? e.clipboardData.files : null;
    if (clipOn && files && files.length) {
      // Files copied in Explorer: the paste key goes out after the upload.
      var wasHeld = held; held = null;
      sendFiles(files, !!wasHeld);
      return;
    }
    var s = e.clipboardData ? e.clipboardData.getData("text/plain") : "";
    if (clipOn && s && s !== lastClip) { lastClip = s; send({ t: "clip", text: s.slice(0, 65536) }); }
    // The agent sets the clipboard before it replays the next input.
    releaseHeld();
  });
  kbd.addEventListener("input", function () { kbd.value = ""; });
  kbd.addEventListener("blur", function () {
    releaseHeld();
    Object.keys(down).forEach(function (c) { key(c, false); });
    down = {};
    if (buttons) { buttons = 0; mouse(); }
  });

  // ---- tools
  document.getElementById("rd-quality").addEventListener("change", function (e) {
    send({ t: "q", quality: Number(e.target.value) });
    send({ t: "full" });
  });
  document.getElementById("rd-cad").addEventListener("click", function () { send({ t: "cad" }); focusKbd(); });
  document.getElementById("rd-paste").addEventListener("click", function () {
    var typeIt = function (s) { if (s) send({ t: "text", text: s.slice(0, 4096) }); focusKbd(); };
    if (navigator.clipboard && navigator.clipboard.readText) {
      navigator.clipboard.readText().then(typeIt, function () { typeIt(window.prompt(t("paste"))); });
    } else {
      typeIt(window.prompt(t("paste")));
    }
  });
  // ---- monitors
  function showMonitors(list, shown) {
    if (!monSel) return;
    if (list.length < 2) { monSel.hidden = true; return; }
    // The sizes come from the agent: text nodes only, never markup.
    monSel.textContent = "";
    function opt(value, text) {
      var o = document.createElement("option");
      o.value = value; o.textContent = text;
      monSel.appendChild(o);
    }
    list.forEach(function (m, i) {
      opt(String(i), t("monitor") + " " + (i + 1) + (m.primary ? " (" + t("primary") + ")" : "") + " · " + Number(m.w) + "×" + Number(m.h));
    });
    opt("-1", t("allmonitors"));
    monSel.value = String(shown);
    monSel.hidden = false;
  }
  if (monSel) monSel.addEventListener("change", function () { send({ t: "mon", monitor: Number(monSel.value) }); focusKbd(); });

  // ---- clipboard from the remote computer
  var remoteText = "";
  // Copied on the remote computer (Ctrl+C there): put it on the local
  // clipboard right away; the key press still counts as the user's action.
  function remoteCopied(s) {
    remoteText = s;
    lastClip = s;
    var done = function () { flash(t("copied")); };
    var fallback = function () {
      // Older way, inside the same user action: copy from the hidden field.
      var ok = false;
      try {
        kbd.value = s; kbd.select();
        ok = document.execCommand("copy");
      } catch (e) { ok = false; }
      kbd.value = "";
      focusKbd();
      if (ok) done(); else if (clipBtn) clipBtn.hidden = false;
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(s).then(done, fallback);
    } else {
      fallback();
    }
  }
  if (clipBtn) clipBtn.addEventListener("click", function () {
    if (navigator.clipboard) navigator.clipboard.writeText(remoteText).then(function () { clipBtn.hidden = true; flash(t("copied")); });
    focusKbd();
  });
  // ---- files through the clipboard (Windows)
  // Pasted or dropped files: the helper makes a staging folder in the
  // signed-in user's Temp, the console uploads the files there (audited like
  // any upload), the helper puts them on the remote clipboard as copied
  // files, and Ctrl+V pastes them where the user is.
  var waiting = {};
  var devBase = root.getAttribute("data-ws").replace(/\/rd\/ws$/, "");
  var busy = false;
  function ask(msg, answer) {
    return new Promise(function (ok, fail) {
      waiting[answer] = { ok: ok, fail: function (s) { fail(new Error(s)); } };
      setTimeout(function () { if (waiting[answer]) { delete waiting[answer]; fail(new Error(t("noanswer"))); } }, 20000);
      send(msg);
    });
  }
  function upload(dir, files) {
    return new Promise(function (ok, fail) {
      var fd = new FormData();
      fd.append("dir", dir);
      for (var i = 0; i < files.length; i++) fd.append("file", files[i], files[i].name);
      var x = new XMLHttpRequest();
      x.open("POST", devBase + "/rd/upload");
      x.upload.onprogress = function (e) {
        if (e.lengthComputable) setStatus(t("sending") + " " + Math.floor(e.loaded * 100 / e.total) + " %", "ok");
      };
      x.onload = function () {
        var res = {};
        try { res = JSON.parse(x.responseText); } catch (e) { res = { error: x.statusText }; }
        if (x.status === 200 && res.paths) ok(res.paths); else fail(new Error(res.error || x.statusText));
      };
      x.onerror = function () { fail(new Error(t("closed"))); };
      x.send(fd);
    });
  }
  function sendFiles(list, paste) {
    // Copy the list now: Firefox empties it when the paste or drop event ends.
    var files = Array.prototype.slice.call(list);
    if (busy) return;
    busy = true;
    var restore = status.textContent, restoreCls = status.className;
    setStatus(t("sending") + " 0 %", "ok");
    ask({ t: "stage" }, "stage").then(function (m) {
      return upload(m.path, files);
    }).then(function (paths) {
      return ask({ t: "files", paths: paths }, "files");
    }).then(function () {
      status.textContent = restore; status.className = restoreCls;
      if (paste) {
        // Ctrl+V on the remote computer (Ctrl may still be held here).
        var ctrlHeld = down.ControlLeft || down.ControlRight;
        if (!ctrlHeld) key("ControlLeft", true);
        key("KeyV", true); key("KeyV", false);
        if (!ctrlHeld) key("ControlLeft", false);
        flash(t("pasted").replace("%d", files.length));
      } else {
        flash(t("dropped").replace("%d", files.length));
      }
    }).catch(function (err) {
      setStatus(err.message, "err");
      setTimeout(function () { if (status.textContent === err.message) { status.textContent = restore; status.className = restoreCls; } }, 6000);
    }).then(function () { busy = false; focusKbd(); });
  }
  if (clipOn) {
    var screenEl = document.getElementById("rd-screen");
    screenEl.addEventListener("dragover", function (e) { e.preventDefault(); e.dataTransfer.dropEffect = "copy"; root.classList.add("dropping"); });
    screenEl.addEventListener("dragleave", function () { root.classList.remove("dropping"); });
    screenEl.addEventListener("drop", function (e) {
      e.preventDefault();
      root.classList.remove("dropping");
      if (e.dataTransfer && e.dataTransfer.files.length) sendFiles(e.dataTransfer.files, false);
    });
  }
  // Copied files on the remote computer: offer them for download.
  var filesBtn = document.getElementById("rd-files");
  var copiedItems = [];
  function remoteFiles(items) {
    copiedItems = items.slice(0, 200);
    if (!filesBtn || !copiedItems.length) return;
    filesBtn.querySelector("span").textContent = t("download").replace("%d", copiedItems.length);
    filesBtn.hidden = false;
  }
  if (filesBtn) filesBtn.addEventListener("click", function () {
    if (!copiedItems.length) return;
    var q = copiedItems.map(function (it) { return "path=" + encodeURIComponent(it.path); }).join("&");
    var url = copiedItems.length === 1 && !copiedItems[0].dir ? devBase + "/files/download?" + q : devBase + "/files/zip?" + q;
    var a = document.createElement("a");
    a.href = url; a.download = "";
    document.body.appendChild(a); a.click(); a.remove();
    filesBtn.hidden = true;
    flash(t("downloading"));
    focusKbd();
  });

  var flashTimer = 0;
  function flash(s) {
    var old = status.textContent, cls = status.className;
    status.textContent = s;
    clearTimeout(flashTimer);
    flashTimer = setTimeout(function () { if (status.textContent === s) { status.textContent = old; status.className = cls; } }, 2500);
  }

  document.getElementById("rd-full").addEventListener("click", function () {
    var el = document.getElementById("rd");
    if (document.fullscreenElement) document.exitFullscreen(); else if (el.requestFullscreen) el.requestFullscreen();
    focusKbd();
  });

  // ---- fit the remote screen into the space there is (page, own window or
  // full screen), keeping its aspect ratio; mouse positions scale with it.
  var screenBox = document.getElementById("rd-screen");
  var own = document.body.classList.contains("rdwin");
  function fit() {
    var full = document.fullscreenElement === root;
    var w = screenBox.clientWidth;
    var h = full || own ? screenBox.clientHeight : window.innerHeight - screenBox.getBoundingClientRect().top - 24;
    if (w < 50 || h < 50 || !canvas.width) return;
    var s = Math.min(w / canvas.width, h / canvas.height);
    if (!full && !own) s = Math.min(s, 1); // on the page never larger than real size
    canvas.style.width = Math.floor(canvas.width * s) + "px";
    canvas.style.height = Math.floor(canvas.height * s) + "px";
  }
  window.addEventListener("resize", fit);
  document.addEventListener("fullscreenchange", function () {
    setTimeout(fit, 50);
    // Full screen: shortcuts the browser would take (Ctrl+W, Ctrl+T, the
    // Windows key, Esc) go to the remote computer; hold Esc to leave.
    if (navigator.keyboard && navigator.keyboard.lock) {
      if (document.fullscreenElement === root) navigator.keyboard.lock().catch(function () { /* not supported */ });
      else navigator.keyboard.unlock();
    }
    focusKbd();
  });
  fit();
})();
