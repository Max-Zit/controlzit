// RMMZit terminal: a small xterm-compatible terminal emulator for the
// Linux root shell (term.start). The agent sends the shell output as binary
// messages; keystrokes go back as {"t":"i","d":…} and the window size as
// {"t":"r","cols":…,"rows":…}. It covers what shells and the usual full-
// screen programs (top, less, nano, vim, mc) use: cursor movement, erasing,
// insert/delete, scroll regions, the alternate screen, 16/256/true colors.
(function () {
  "use strict";
  var root = document.getElementById("term");
  if (!root) return;
  var screenEl = document.getElementById("term-screen");
  var statusEl = document.getElementById("term-status");
  var T = function (k) { return root.getAttribute("data-t-" + k) || k; };

  // ---- palette (xterm-like, readable on the dark background)
  var base16 = ["#1e1e1e", "#d75f5f", "#5faf5f", "#d7af5f", "#5f87d7", "#af5fd7", "#5fafaf", "#c8c8c8",
    "#767676", "#ff7b7b", "#87d787", "#ffd75f", "#87afff", "#d787ff", "#87d7d7", "#ffffff"];
  var palette = base16.slice();
  (function () {
    var v = [0, 95, 135, 175, 215, 255], hex = function (n) { return (n < 16 ? "0" : "") + n.toString(16); };
    for (var r = 0; r < 6; r++) for (var g = 0; g < 6; g++) for (var b = 0; b < 6; b++) palette.push("#" + hex(v[r]) + hex(v[g]) + hex(v[b]));
    for (var i = 0; i < 24; i++) { var c = 8 + i * 10; palette.push("#" + hex(c) + hex(c) + hex(c)); }
  })();
  var F_BOLD = 1, F_DIM = 2, F_ITALIC = 4, F_UNDER = 8, F_INV = 16, F_HIDE = 32, F_STRIKE = 64;
  var DEF = { fg: -1, bg: -1, f: 0 };
  function attr(fg, bg, f) { return (fg === -1 && bg === -1 && f === 0) ? DEF : { fg: fg, bg: bg, f: f }; }

  // DEC special graphics (ESC ( 0): line drawing.
  var lineDraw = { "`": "◆", a: "▒", f: "°", g: "±", j: "┘", k: "┐", l: "┌", m: "└", n: "┼", o: "⎺", p: "⎻", q: "─", r: "⎼", s: "⎽",
    t: "├", u: "┤", v: "┴", w: "┬", x: "│", y: "≤", z: "≥", "{": "π", "|": "≠", "}": "£", "~": "·" };

  function wide(cp) {
    return cp >= 0x1100 && (cp <= 0x115f || cp === 0x2329 || cp === 0x232a ||
      (cp >= 0x2e80 && cp <= 0xa4cf && cp !== 0x303f) || (cp >= 0xac00 && cp <= 0xd7a3) ||
      (cp >= 0xf900 && cp <= 0xfaff) || (cp >= 0xfe30 && cp <= 0xfe4f) || (cp >= 0xff00 && cp <= 0xff60) ||
      (cp >= 0xffe0 && cp <= 0xffe6) || (cp >= 0x1f300 && cp <= 0x1f64f) || (cp >= 0x1f900 && cp <= 0x1f9ff) ||
      (cp >= 0x20000 && cp <= 0x3fffd));
  }
  function combining(cp) {
    return (cp >= 0x300 && cp <= 0x36f) || (cp >= 0x1ab0 && cp <= 0x1aff) || (cp >= 0x1dc0 && cp <= 0x1dff) ||
      (cp >= 0x20d0 && cp <= 0x20ff) || (cp >= 0xfe20 && cp <= 0xfe2f) || cp === 0x200d || (cp >= 0xfe00 && cp <= 0xfe0f);
  }

  // ---- screen state
  var cols = 80, rows = 24;
  var lines, altLines = null, mainLines = null;
  var x = 0, y = 0, wrapPending = false, cur = DEF;
  var top = 0, bottom = rows - 1;
  var saved = null, savedMain = null;
  var mode = { appCursor: false, wrap: true, cursor: true, paste: false, insert: false, origin: false, alt: false };
  var g0Line = false, lastChar = " ";
  var dirty = [], sbPending = [];

  function blankLine(a) {
    var l = { c: new Array(cols), a: new Array(cols) };
    for (var i = 0; i < cols; i++) { l.c[i] = " "; l.a[i] = a || DEF; }
    return l;
  }
  function eraseAttr() { return cur.bg === -1 ? DEF : attr(-1, cur.bg, 0); }
  function allDirty() { for (var i = 0; i < rows; i++) dirty[i] = true; }
  function reset() {
    lines = []; for (var i = 0; i < rows; i++) lines.push(blankLine());
    altLines = null; mainLines = null; x = y = 0; wrapPending = false; cur = DEF; top = 0; bottom = rows - 1;
    saved = savedMain = null; g0Line = false;
    mode = { appCursor: false, wrap: true, cursor: true, paste: false, insert: false, origin: false, alt: false };
    root.classList.remove("alt");
    allDirty();
  }

  function scrollUp(n, keep) {
    for (var k = 0; k < n; k++) {
      var gone = lines.splice(top, 1)[0];
      if (keep && top === 0 && !mode.alt) sbPending.push(gone);
      lines.splice(bottom, 0, blankLine(eraseAttr()));
    }
    for (var i = top; i <= bottom; i++) dirty[i] = true;
  }
  function scrollDown(n) {
    for (var k = 0; k < n; k++) {
      lines.splice(bottom, 1);
      lines.splice(top, 0, blankLine(eraseAttr()));
    }
    for (var i = top; i <= bottom; i++) dirty[i] = true;
  }
  function lineFeed() {
    wrapPending = false;
    if (y === bottom) scrollUp(1, true);
    else if (y < rows - 1) y++;
  }
  function clampX() { x = Math.max(0, Math.min(cols - 1, x)); wrapPending = false; }
  function moveTo(r, c) {
    var t = mode.origin ? top : 0, b = mode.origin ? bottom : rows - 1;
    y = Math.max(t, Math.min(b, r + t)); x = c; clampX();
  }

  function put(ch, cp) {
    if (g0Line && lineDraw[ch]) ch = lineDraw[ch];
    if (combining(cp)) {
      var px = wrapPending ? x : x - 1;
      if (px >= 0) { lines[y].c[px] += ch; dirty[y] = true; }
      return;
    }
    var w = wide(cp) ? 2 : 1;
    if (wrapPending && mode.wrap) { x = 0; lineFeed(); }
    if (x + w > cols) { if (mode.wrap) { x = 0; lineFeed(); } else x = cols - w; }
    var l = lines[y];
    if (mode.insert) {
      for (var i = 0; i < w; i++) { l.c.splice(x, 0, " "); l.a.splice(x, 0, cur); l.c.pop(); l.a.pop(); }
    }
    l.c[x] = ch; l.a[x] = cur;
    if (w === 2) { l.c[x + 1] = ""; l.a[x + 1] = cur; }
    lastChar = ch;
    dirty[y] = true;
    x += w;
    if (x >= cols) { x = cols - 1; wrapPending = true; }
  }

  function eraseLine(l, from, to) {
    var a = eraseAttr();
    for (var i = from; i < to; i++) { l.c[i] = " "; l.a[i] = a; }
  }
  function eraseDisplay(n) {
    var i;
    if (n === 0) { eraseLine(lines[y], x, cols); for (i = y + 1; i < rows; i++) eraseLine(lines[i], 0, cols); for (i = y; i < rows; i++) dirty[i] = true; }
    else if (n === 1) { eraseLine(lines[y], 0, x + 1); for (i = 0; i < y; i++) eraseLine(lines[i], 0, cols); for (i = 0; i <= y; i++) dirty[i] = true; }
    else if (n === 2) { for (i = 0; i < rows; i++) eraseLine(lines[i], 0, cols); allDirty(); }
    else if (n === 3) { var sb = screenEl.querySelector(".term-sb"); if (sb) sb.textContent = ""; sbPending = []; }
  }

  function saveCursor() { return { x: x, y: y, cur: cur, g0: g0Line, origin: mode.origin, wrapPending: wrapPending }; }
  function restoreCursor(s) {
    if (!s) { x = y = 0; cur = DEF; return; }
    x = Math.min(s.x, cols - 1); y = Math.min(s.y, rows - 1); cur = s.cur; g0Line = s.g0; mode.origin = s.origin; wrapPending = s.wrapPending;
  }
  function setAlt(on, clear) {
    if (on === mode.alt) return;
    if (on) {
      mainLines = lines; lines = []; for (var i = 0; i < rows; i++) lines.push(blankLine());
      mode.alt = true; root.classList.add("alt");
    } else {
      lines = mainLines || lines; mainLines = null;
      mode.alt = false; root.classList.remove("alt");
    }
    if (clear) eraseDisplay(2);
    allDirty();
  }

  function sgr(ps) {
    if (ps.length === 0) ps = [0];
    var fg = cur.fg, bg = cur.bg, f = cur.f;
    for (var i = 0; i < ps.length; i++) {
      var p = ps[i] || 0;
      if (p === 0) { fg = -1; bg = -1; f = 0; }
      else if (p === 1) f |= F_BOLD; else if (p === 2) f |= F_DIM; else if (p === 3) f |= F_ITALIC;
      else if (p === 4) f |= F_UNDER; else if (p === 7) f |= F_INV; else if (p === 8) f |= F_HIDE; else if (p === 9) f |= F_STRIKE;
      else if (p === 21 || p === 22) f &= ~(F_BOLD | F_DIM); else if (p === 23) f &= ~F_ITALIC; else if (p === 24) f &= ~F_UNDER;
      else if (p === 27) f &= ~F_INV; else if (p === 28) f &= ~F_HIDE; else if (p === 29) f &= ~F_STRIKE;
      else if (p >= 30 && p <= 37) fg = p - 30; else if (p === 39) fg = -1;
      else if (p >= 40 && p <= 47) bg = p - 40; else if (p === 49) bg = -1;
      else if (p >= 90 && p <= 97) fg = p - 90 + 8; else if (p >= 100 && p <= 107) bg = p - 100 + 8;
      else if (p === 38 || p === 48) {
        var c = null;
        if (ps[i + 1] === 5) { c = (ps[i + 2] || 0) & 255; i += 2; }
        else if (ps[i + 1] === 2) {
          var h = function (n) { n = Math.max(0, Math.min(255, n || 0)); return (n < 16 ? "0" : "") + n.toString(16); };
          c = "#" + h(ps[i + 2]) + h(ps[i + 3]) + h(ps[i + 4]); i += 4;
        }
        if (c !== null) { if (p === 38) fg = c; else bg = c; }
      }
    }
    cur = attr(fg, bg, f);
  }

  function setMode(priv, ps, on) {
    for (var i = 0; i < ps.length; i++) {
      var p = ps[i];
      if (!priv) { if (p === 4) mode.insert = on; continue; }
      switch (p) {
        case 1: mode.appCursor = on; break;
        case 6: mode.origin = on; moveTo(0, 0); break;
        case 7: mode.wrap = on; break;
        case 25: mode.cursor = on; dirty[y] = true; break;
        case 47: case 1047: setAlt(on, false); break;
        case 1048: if (on) saved = saveCursor(); else restoreCursor(saved); break;
        case 1049:
          if (on) { savedMain = saveCursor(); setAlt(true, true); }
          else { setAlt(false, false); restoreCursor(savedMain); }
          break;
        case 2004: mode.paste = on; break;
      }
    }
  }

  function csi(prefix, params, inter, fin) {
    var ps = params === "" ? [] : params.split(";").map(function (s) { return parseInt(s.split(":")[0], 10) || 0; });
    var n = ps[0] || 1, i;
    if (prefix === "?" && (fin === "h" || fin === "l")) { setMode(true, ps, fin === "h"); return; }
    if (prefix === ">" || prefix === "=") {
      if (fin === "c" && prefix === ">") send("\x1b[>0;276;0c");
      return;
    }
    if (inter !== "") return; // DECSCUSR (cursor style) and friends
    switch (fin) {
      case "@": for (i = 0; i < Math.min(n, cols - x); i++) { lines[y].c.splice(x, 0, " "); lines[y].a.splice(x, 0, eraseAttr()); lines[y].c.pop(); lines[y].a.pop(); } dirty[y] = true; break;
      case "A": y = Math.max(y < top ? 0 : top, y - n); wrapPending = false; break;
      case "B": y = Math.min(y > bottom ? rows - 1 : bottom, y + n); wrapPending = false; break;
      case "C": case "a": x += n; clampX(); break;
      case "D": x -= n; clampX(); break;
      case "E": y = Math.min(bottom, y + n); x = 0; wrapPending = false; break;
      case "F": y = Math.max(top, y - n); x = 0; wrapPending = false; break;
      case "G": case "`": x = n - 1; clampX(); break;
      case "H": case "f": moveTo((ps[0] || 1) - 1, (ps[1] || 1) - 1); break;
      case "I": for (i = 0; i < n; i++) x = Math.min(cols - 1, (Math.floor(x / 8) + 1) * 8); wrapPending = false; break;
      case "Z": for (i = 0; i < n; i++) x = Math.max(0, (Math.ceil(x / 8) - 1) * 8); wrapPending = false; break;
      case "J": eraseDisplay(ps[0] || 0); break;
      case "K":
        var k = ps[0] || 0;
        if (k === 0) eraseLine(lines[y], x, cols); else if (k === 1) eraseLine(lines[y], 0, x + 1); else eraseLine(lines[y], 0, cols);
        dirty[y] = true; break;
      case "L": if (y >= top && y <= bottom) { var t0 = top; top = y; scrollDown(Math.min(n, bottom - y + 1)); top = t0; x = 0; } break;
      case "M": if (y >= top && y <= bottom) { var t1 = top; top = y; scrollUp(Math.min(n, bottom - y + 1), false); top = t1; x = 0; } break;
      case "P": for (i = 0; i < Math.min(n, cols - x); i++) { lines[y].c.splice(x, 1); lines[y].a.splice(x, 1); lines[y].c.push(" "); lines[y].a.push(eraseAttr()); } dirty[y] = true; break;
      case "S": scrollUp(n, false); break;
      case "T": scrollDown(n); break;
      case "X": eraseLine(lines[y], x, Math.min(cols, x + n)); dirty[y] = true; break;
      case "b": for (i = 0; i < Math.min(n, 1000); i++) put(lastChar, lastChar.codePointAt(0)); break;
      case "c": if (prefix === "") send("\x1b[?62;22c"); break;
      case "d": moveTo(n - 1, x); break;
      case "e": y = Math.min(rows - 1, y + n); wrapPending = false; break;
      case "h": case "l": setMode(false, ps, fin === "h"); break;
      case "m": sgr(ps); break;
      case "n":
        if (ps[0] === 6) send("\x1b[" + (y - (mode.origin ? top : 0) + 1) + ";" + (x + 1) + "R");
        else if (ps[0] === 5) send("\x1b[0n");
        break;
      case "r":
        var t2 = (ps[0] || 1) - 1, b2 = (ps[1] || rows) - 1;
        if (t2 < b2 && b2 < rows) { top = t2; bottom = b2; moveTo(0, 0); }
        break;
      case "s": saved = saveCursor(); break;
      case "u": restoreCursor(saved); break;
    }
  }

  function esc(ch) {
    switch (ch) {
      case "7": saved = saveCursor(); break;
      case "8": restoreCursor(saved); break;
      case "D": lineFeed(); break;
      case "E": x = 0; lineFeed(); break;
      case "M": wrapPending = false; if (y === top) scrollDown(1); else if (y > 0) y--; break;
      case "c": reset(); break;
    }
  }

  // ---- parser
  var st = 0, pPrefix = "", pParams = "", pInter = "", strEsc = false, oscBuf = "";
  var GROUND = 0, ESC = 1, CSI = 2, OSC = 3, STR = 4, CHARSET = 5, SKIP1 = 6;
  var charsetFor = "";
  function write(text) {
    for (var i = 0; i < text.length; i++) {
      var cp = text.codePointAt(i), ch = String.fromCodePoint(cp);
      if (cp > 0xffff) i++;
      switch (st) {
        case GROUND:
          if (cp === 0x1b) { st = ESC; }
          else if (cp < 0x20 || cp === 0x7f) control(cp);
          else put(ch, cp);
          break;
        case ESC:
          if (ch === "[") { st = CSI; pPrefix = ""; pParams = ""; pInter = ""; }
          else if (ch === "]") { st = OSC; oscBuf = ""; strEsc = false; }
          else if (ch === "P" || ch === "X" || ch === "^" || ch === "_") { st = STR; strEsc = false; }
          else if (ch === "(" || ch === ")" || ch === "*" || ch === "+") { st = CHARSET; charsetFor = ch; }
          else if (ch === "#" || ch === "%" || ch === " ") st = SKIP1;
          else { st = GROUND; esc(ch); }
          break;
        case CSI:
          if (cp < 0x20) { control(cp); break; }
          if (pParams === "" && pInter === "" && (ch === "?" || ch === ">" || ch === "=" || ch === "<") && pPrefix === "") pPrefix = ch;
          else if (cp >= 0x30 && cp <= 0x3f) pParams += ch;
          else if (cp >= 0x20 && cp <= 0x2f) pInter += ch;
          else if (cp >= 0x40 && cp <= 0x7e) { st = GROUND; csi(pPrefix, pParams, pInter, ch); }
          else st = GROUND;
          if (pParams.length > 200) st = GROUND;
          break;
        case OSC: case STR:
          if (cp === 0x07) { if (st === OSC) osc(oscBuf); st = GROUND; }
          else if (strEsc) { strEsc = false; if (ch === "\\") { if (st === OSC) osc(oscBuf); st = GROUND; } }
          else if (cp === 0x1b) strEsc = true;
          else if (st === OSC && oscBuf.length < 4096) oscBuf += ch;
          break;
        case CHARSET:
          if (charsetFor === "(") g0Line = ch === "0";
          st = GROUND; break;
        case SKIP1:
          st = GROUND; break;
      }
    }
    schedule();
  }
  function osc(s) {
    var m = /^[02];(.*)$/.exec(s);
    if (m && root.closest("body.rdwin")) document.title = m[1].slice(0, 120);
  }
  function control(cp) {
    switch (cp) {
      case 0x08: if (wrapPending) wrapPending = false; else if (x > 0) x--; break;
      case 0x09: x = Math.min(cols - 1, (Math.floor(x / 8) + 1) * 8); wrapPending = false; break;
      case 0x0a: case 0x0b: case 0x0c: lineFeed(); break;
      case 0x0d: x = 0; wrapPending = false; break;
      case 0x0e: g0Line = true; break; // SO (G1) — treated as line drawing
      case 0x0f: g0Line = false; break;
    }
  }

  // ---- rendering
  var sbEl = document.createElement("div"); sbEl.className = "term-sb";
  var rowsEl = document.createElement("div"); rowsEl.className = "term-rows";
  screenEl.appendChild(sbEl); screenEl.appendChild(rowsEl);
  var rowEls = [];
  var shownCursor = -1, focused = false;
  var pending = false;
  function schedule() { if (!pending) { pending = true; requestAnimationFrame(render); } }

  function color(c) { return typeof c === "string" ? c : palette[c]; }
  function lineNode(l, curX) {
    var div = document.createElement("div");
    div.className = "trow";
    var i = 0;
    while (i < l.c.length) {
      var a = l.a[i], j = i, text = "";
      if (i === curX) { j = i + 1; text = l.c[i] || " "; }
      else {
        while (j < l.c.length && l.a[j] === a && j !== curX) { text += l.c[j]; j++; }
      }
      var span = document.createElement("span");
      span.textContent = text;
      var fg = a.fg, bg = a.bg;
      if ((a.f & F_BOLD) && typeof fg === "number" && fg >= 0 && fg < 8) fg += 8;
      if (a.f & F_INV) { var t = fg; fg = bg; bg = t; if (fg === -1) span.classList.add("tinvfg"); if (bg === -1) span.classList.add("tinvbg"); }
      if (fg !== -1) span.style.color = color(fg);
      if (bg !== -1) span.style.backgroundColor = color(bg);
      if (a.f & F_BOLD) span.classList.add("tb");
      if (a.f & F_DIM) span.classList.add("td");
      if (a.f & F_ITALIC) span.classList.add("ti");
      if (a.f & F_UNDER) span.classList.add("tu");
      if (a.f & F_STRIKE) span.classList.add("ts");
      if (a.f & F_HIDE) span.classList.add("th");
      if (i === curX) span.classList.add(focused ? "tcur" : "tcur-off");
      div.appendChild(span);
      i = j;
    }
    return div;
  }
  function atBottom() { return screenEl.scrollTop + screenEl.clientHeight >= screenEl.scrollHeight - 4; }
  function render() {
    pending = false;
    var stick = atBottom();
    if (sbPending.length) {
      var frag = document.createDocumentFragment();
      sbPending.forEach(function (l) { frag.appendChild(lineNode(l, -1)); });
      sbPending = [];
      sbEl.appendChild(frag);
      var extra = sbEl.childElementCount - 3000;
      while (extra-- > 0) sbEl.removeChild(sbEl.firstChild);
    }
    var cy = mode.cursor ? y : -1;
    if (shownCursor !== cy) { if (shownCursor >= 0) dirty[shownCursor] = true; if (cy >= 0) dirty[cy] = true; }
    for (var r = 0; r < rows; r++) {
      if (!dirty[r] && rowEls[r]) continue;
      var node = lineNode(lines[r], r === cy ? x : -1);
      if (rowEls[r]) rowsEl.replaceChild(node, rowEls[r]); else rowsEl.appendChild(node);
      rowEls[r] = node; dirty[r] = false;
    }
    while (rowEls.length > rows) rowsEl.removeChild(rowEls.pop());
    shownCursor = cy;
    if (stick) screenEl.scrollTop = screenEl.scrollHeight;
  }

  // ---- size
  var cellW = 8, cellH = 17;
  function measure() {
    var probe = document.createElement("span");
    probe.className = "trow-probe";
    probe.textContent = "MMMMMMMMMM";
    rowsEl.appendChild(probe);
    var b = probe.getBoundingClientRect();
    rowsEl.removeChild(probe);
    if (b.width > 0) { cellW = b.width / 10; cellH = b.height; }
  }
  function fitSize() {
    measure();
    var cs = getComputedStyle(screenEl);
    var w = screenEl.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight) - 2;
    var h = screenEl.clientHeight - parseFloat(cs.paddingTop) - parseFloat(cs.paddingBottom);
    return { cols: Math.max(20, Math.min(500, Math.floor(w / cellW))), rows: Math.max(5, Math.min(300, Math.floor(h / cellH))) };
  }
  function resize(nc, nr) {
    if (nc === cols && nr === rows) return false;
    var fix = function (ls) {
      ls.forEach(function (l) {
        while (l.c.length < nc) { l.c.push(" "); l.a.push(DEF); }
        l.c.length = nc; l.a.length = nc;
      });
    };
    var adjust = function (ls, isMain) {
      while (ls.length > nr) {
        // drop from the top while the cursor would fall off, else from the bottom
        if (ls === lines && y >= nr) { var gone = ls.shift(); if (isMain) sbPending.push(gone); y--; }
        else ls.pop();
      }
      while (ls.length < nr) ls.push(blankLine());
    };
    cols = nc;
    fix(lines); if (mainLines) fix(mainLines);
    adjust(lines, !mode.alt); if (mainLines) adjust(mainLines, true);
    rows = nr; top = 0; bottom = rows - 1;
    x = Math.min(x, cols - 1); y = Math.min(y, rows - 1); wrapPending = false;
    rowEls.forEach(function (e) { rowsEl.removeChild(e); }); rowEls = [];
    allDirty(); schedule();
    return true;
  }

  // ---- connection
  var ws = null, decoder = null, open = false;
  var reconnectBtn = document.getElementById("term-reconnect");
  function setStatus(text, cls) { statusEl.textContent = text; statusEl.className = "rd-status" + (cls ? " " + cls : ""); }
  function send(d) { if (ws && open && d) ws.send(JSON.stringify({ t: "i", d: d })); }
  function connect() {
    var size = fitSize();
    resize(size.cols, size.rows);
    reset();
    decoder = new TextDecoder("utf-8");
    reconnectBtn.hidden = true;
    setStatus(T("connecting"));
    var url = (location.protocol === "https:" ? "wss://" : "ws://") + location.host + root.getAttribute("data-ws") + "?cols=" + cols + "&rows=" + rows;
    ws = new WebSocket(url);
    ws.binaryType = "arraybuffer";
    var ended = false;
    ws.onmessage = function (ev) {
      if (typeof ev.data !== "string") {
        if (!open) { open = true; setStatus(T("connected"), "ok"); }
        write(decoder.decode(new Uint8Array(ev.data), { stream: true }));
        return;
      }
      var m; try { m = JSON.parse(ev.data); } catch (e) { return; }
      if (m.t === "error") { ended = true; setStatus(m.text, "bad"); }
      else if (m.t === "exit") { ended = true; setStatus(T("exit").replace("%d", m.code), "warn"); }
    };
    ws.onopen = function () { open = true; setStatus(T("connected"), "ok"); focusInput(); };
    ws.onclose = function () {
      open = false;
      if (!ended) setStatus(T("closed"), "bad");
      reconnectBtn.hidden = false;
      focused = false; dirty[y] = true; schedule();
    };
  }
  reconnectBtn.addEventListener("click", function () {
    var sep = document.createElement("div"); sep.className = "trow term-sep";
    sbEl.appendChild(sep);
    lines.forEach(function (l) { sbPending.push(l); });
    connect();
  });

  // ---- keyboard, paste, focus
  var input = document.createElement("textarea");
  input.className = "term-input"; input.setAttribute("aria-label", "Terminal input");
  input.setAttribute("autocomplete", "off"); input.setAttribute("autocapitalize", "off"); input.setAttribute("spellcheck", "false");
  root.appendChild(input);
  function focusInput() { input.focus({ preventScroll: true }); }
  input.addEventListener("focus", function () { focused = true; dirty[y] = true; schedule(); });
  input.addEventListener("blur", function () { focused = false; dirty[y] = true; schedule(); });
  screenEl.addEventListener("mouseup", function () {
    var sel = window.getSelection();
    if (!sel || sel.isCollapsed) focusInput();
  });
  screenEl.addEventListener("focus", focusInput);

  function selectionText() { var s = window.getSelection(); return s && !s.isCollapsed ? s.toString() : ""; }
  var keys = { ArrowUp: "A", ArrowDown: "B", ArrowRight: "C", ArrowLeft: "D", Home: "H", End: "F" };
  var tilde = { Insert: 2, Delete: 3, PageUp: 5, PageDown: 6, F5: 15, F6: 17, F7: 18, F8: 19, F9: 20, F10: 21, F11: 23, F12: 24 };
  var ss3 = { F1: "P", F2: "Q", F3: "R", F4: "S" };
  input.addEventListener("keydown", function (ev) {
    if (ev.isComposing || ev.keyCode === 229) return;
    var k = ev.key, ctrl = ev.ctrlKey, alt = ev.altKey, shift = ev.shiftKey;
    var altGr = ctrl && alt && k.length === 1; // Windows reports AltGr as Ctrl+Alt
    var mod = 1 + (shift ? 1 : 0) + (alt ? 2 : 0) + (ctrl ? 4 : 0);
    var out = null;
    if (ctrl && shift && (k === "C" || k === "c")) { var t = selectionText(); if (t && navigator.clipboard) navigator.clipboard.writeText(t); ev.preventDefault(); return; }
    if (ctrl && !alt && (k === "v" || k === "V")) return; // the paste event follows
    if (ctrl && !shift && !alt && (k === "c" || k === "C") && selectionText()) {
      if (navigator.clipboard) navigator.clipboard.writeText(selectionText());
      window.getSelection().removeAllRanges(); ev.preventDefault(); return;
    }
    if (shift && (k === "PageUp" || k === "PageDown")) { screenEl.scrollTop += (k === "PageUp" ? -1 : 1) * screenEl.clientHeight * 0.9; ev.preventDefault(); return; }
    if (keys[k]) {
      if (mod > 1) out = "\x1b[1;" + mod + keys[k];
      else out = (mode.appCursor ? "\x1bO" : "\x1b[") + keys[k];
    } else if (tilde[k]) out = "\x1b[" + tilde[k] + (mod > 1 ? ";" + mod : "") + "~";
    else if (ss3[k]) out = mod > 1 ? "\x1b[1;" + mod + ss3[k] : "\x1bO" + ss3[k];
    else if (k === "Enter") out = alt ? "\x1b\r" : "\r";
    else if (k === "Backspace") out = (alt ? "\x1b" : "") + (ctrl ? "\x08" : "\x7f");
    else if (k === "Tab") out = shift ? "\x1b[Z" : "\t";
    else if (k === "Escape") out = "\x1b";
    else if (altGr) out = k;
    else if (ctrl && k.length === 1) {
      var c = k.toUpperCase().charCodeAt(0);
      if (c >= 64 && c <= 95) out = String.fromCharCode(c - 64);
      else if (k === " " || k === "2") out = "\x00";
      else if (k === "/" || k === "7") out = "\x1f";
      else if (k === "3") out = "\x1b"; else if (k === "4") out = "\x1c"; else if (k === "5") out = "\x1d"; else if (k === "6") out = "\x1e"; else if (k === "8") out = "\x7f";
      if (out !== null && alt) out = "\x1b" + out;
    } else if (alt && !ev.metaKey && k.length === 1) out = "\x1b" + k;
    else if (k.length === 1 && !ev.metaKey) out = k;
    if (out !== null) {
      ev.preventDefault();
      send(out);
      screenEl.scrollTop = screenEl.scrollHeight;
    }
  });
  // Text from an input method (IME) or dictation arrives as input events.
  input.addEventListener("input", function (ev) {
    if (ev.isComposing) return;
    if (input.value) { send(input.value); input.value = ""; }
  });
  input.addEventListener("compositionend", function () { if (input.value) { send(input.value); input.value = ""; } });
  function pasteText(text) {
    if (!text) return;
    text = text.replace(/\r\n/g, "\r").replace(/\n/g, "\r");
    if (mode.paste) text = "\x1b[200~" + text.replace(/\x1b\[20[01]~/g, "") + "\x1b[201~";
    send(text);
  }
  input.addEventListener("paste", function (ev) {
    ev.preventDefault();
    pasteText(ev.clipboardData && ev.clipboardData.getData("text/plain"));
  });
  document.getElementById("term-paste").addEventListener("click", function () {
    var t = window.prompt(T("paste"));
    if (t) pasteText(t);
    focusInput();
  });
  document.getElementById("term-full").addEventListener("click", function () {
    if (document.fullscreenElement) document.exitFullscreen();
    else if (root.requestFullscreen) root.requestFullscreen();
    focusInput();
  });

  var resizeTimer = null;
  function onResize() {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(function () {
      var s = fitSize();
      if (resize(s.cols, s.rows) && ws && open) ws.send(JSON.stringify({ t: "r", cols: cols, rows: rows }));
    }, 80);
  }
  if (window.ResizeObserver) new ResizeObserver(onResize).observe(screenEl);
  else window.addEventListener("resize", onResize);
  document.addEventListener("fullscreenchange", onResize);

  reset();
  if (root.querySelector("#term-status").textContent.trim() === T("connecting")) connect();
  else reconnectBtn.hidden = false;
})();
