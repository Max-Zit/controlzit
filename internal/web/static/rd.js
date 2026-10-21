// ControlZit remote desktop viewer. Screen updates arrive as binary
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
        if (m.t === "error") setStatus(m.text, "err");
      } catch (e) { /* ignore */ }
      return;
    }
    var b = new DataView(ev.data);
    var kind = b.getUint8(0);
    if (kind === 1) { // screen info
      var info = JSON.parse(new TextDecoder().decode(new Uint8Array(ev.data, 1)));
      open = true;
      if (canvas.width !== info.w || canvas.height !== info.h) { canvas.width = info.w; canvas.height = info.h; }
      setStatus(t("connected") + " · " + info.w + "×" + info.h + (info.desktop && info.desktop !== "Default" ? " · " + t("signin") : ""), "ok");
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
  canvas.addEventListener("mousedown", function (e) { e.preventDefault(); canvas.focus(); pos(e); buttons |= bit[e.button] || 0; mouse(); });
  canvas.addEventListener("mouseup", function (e) { e.preventDefault(); pos(e); buttons &= ~(bit[e.button] || 0); mouse(); });
  canvas.addEventListener("contextmenu", function (e) { e.preventDefault(); });
  canvas.addEventListener("wheel", function (e) { e.preventDefault(); pos(e); mouse(e.deltaY > 0 ? -120 : 120); }, { passive: false });
  (function loop() {
    if (moved) { moved = false; mouse(); }
    requestAnimationFrame(loop);
  })();

  // ---- keyboard (physical keys; the remote layout applies)
  var down = {};
  canvas.addEventListener("keydown", function (e) {
    e.preventDefault();
    down[e.code] = true;
    send({ t: "k", code: e.code, down: true });
  });
  canvas.addEventListener("keyup", function (e) {
    e.preventDefault();
    delete down[e.code];
    send({ t: "k", code: e.code, down: false });
  });
  canvas.addEventListener("blur", function () {
    Object.keys(down).forEach(function (c) { send({ t: "k", code: c, down: false }); });
    down = {};
    if (buttons) { buttons = 0; mouse(); }
  });

  // ---- tools
  document.getElementById("rd-quality").addEventListener("change", function (e) {
    send({ t: "q", quality: Number(e.target.value) });
    send({ t: "full" });
  });
  document.getElementById("rd-cad").addEventListener("click", function () { send({ t: "cad" }); canvas.focus(); });
  document.getElementById("rd-paste").addEventListener("click", function () {
    var typeIt = function (s) { if (s) send({ t: "text", text: s.slice(0, 4096) }); canvas.focus(); };
    if (navigator.clipboard && navigator.clipboard.readText) {
      navigator.clipboard.readText().then(typeIt, function () { typeIt(window.prompt(t("paste"))); });
    } else {
      typeIt(window.prompt(t("paste")));
    }
  });
  document.getElementById("rd-full").addEventListener("click", function () {
    var el = document.getElementById("rd");
    if (document.fullscreenElement) document.exitFullscreen(); else if (el.requestFullscreen) el.requestFullscreen();
    canvas.focus();
  });
})();
