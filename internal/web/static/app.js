// ControlZit console: small progressive enhancements (the console works
// without JavaScript). No inline scripts: the CSP allows only this file.
(function () {
  "use strict";
  var root = document.documentElement;

  function storedTheme() {
    try { return localStorage.getItem("cz-theme"); } catch (e) { return null; }
  }
  var t = storedTheme();
  if (t === "light" || t === "dark") root.setAttribute("data-theme", t);

  function currentTheme() {
    var a = root.getAttribute("data-theme");
    if (a) return a;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  document.addEventListener("click", function (ev) {
    var el = ev.target.closest("[data-theme-toggle],[data-toggle],[data-close],[data-copy]");
    if (!el) return;
    if (el.hasAttribute("data-theme-toggle")) {
      var next = currentTheme() === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("cz-theme", next); } catch (e) { /* private mode */ }
    } else if (el.hasAttribute("data-toggle")) {
      var target = document.querySelector(el.getAttribute("data-toggle"));
      if (target) target.classList.toggle("open");
    } else if (el.hasAttribute("data-close")) {
      var c = document.querySelector(el.getAttribute("data-close"));
      if (c) c.classList.remove("open");
    } else if (el.hasAttribute("data-copy")) {
      var src = document.querySelector(el.getAttribute("data-copy"));
      if (!src || !navigator.clipboard) return;
      var text = src.tagName === "UL"
        ? Array.prototype.map.call(src.querySelectorAll("li"), function (li) { return li.textContent.trim(); }).join("\n")
        : src.textContent.trim();
      navigator.clipboard.writeText(text).then(function () {
        el.classList.add("done");
        setTimeout(function () { el.classList.remove("done"); }, 1500);
      });
    }
  });

  document.addEventListener("change", function (ev) {
    if (ev.target.matches("select[data-autosubmit]")) ev.target.form.submit();
  });

  document.addEventListener("submit", function (ev) {
    var msg = ev.target.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) ev.preventDefault();
  });
})();

// Sidebar clock: the server's time, ticking every second from the value at
// page load (data-ms: Unix ms, data-off: zone offset in seconds).
document.addEventListener("DOMContentLoaded", function () {
  "use strict";
  var el = document.getElementById("clock");
  if (!el) return;
  var delta = Number(el.getAttribute("data-ms")) - Date.now();
  var off = Number(el.getAttribute("data-off")) * 1000;
  var pad = function (n) { return (n < 10 ? "0" : "") + n; };
  setInterval(function () {
    var d = new Date(Date.now() + delta + off); // read in UTC = server zone
    el.textContent = d.getUTCFullYear() + "-" + pad(d.getUTCMonth() + 1) + "-" + pad(d.getUTCDate()) + " " +
      pad(d.getUTCHours()) + ":" + pad(d.getUTCMinutes()) + ":" + pad(d.getUTCSeconds());
  }, 1000);
});
