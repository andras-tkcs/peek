// bridge.js — runs inside the sandboxed iframe containing user HTML.
// Responsibilities:
//  - expose an element picker when the parent requests "comment mode"
//  - show a "Comment" bubble when the viewer selects text
//  - send the anchor (element selector + text quote) to the parent on pick
//  - draw numbered pins + highlight commented text, anchored to the page
//  - scroll-to + flash an anchor when the parent requests "locate"
//  - forward the Shift+H toolbar shortcut to the parent
//  - expose window.peek.params / setParams so a page can keep its filters in
//    the viewer's address bar (the parent URL's query string)
//  - expose window.peek.fetch so a page can call its backend; the request is
//    relayed by the parent page
// It does NOT call the server directly (the iframe is opaque-origin); all
// comments traffic and peek.fetch calls go through the trusted parent page
// via postMessage.
(function () {
  "use strict";

  // The logo's teal-blue (the viewer's --primary); these styles live inside the shared page.
  var ACCENT = "#0b5f86";
  var ACCENT_HOVER = "#084b6b";
  var supportsHL = !!(window.Highlight && window.CSS && CSS.highlights);
  var state = {
    modeOn: false,
    highlight: null,
    pins: [],           // [{selector, quote, kind, n, el, node, range}]
    pinLayer: null,
    selBtn: null,
    rafPending: false,
    selTimer: null
  };

  // --- injected styles (parent /style.css is not loaded in this iframe) ---
  function injectStyles() {
    var css =
      "#hn-pin-layer{position:absolute;top:0;left:0;width:0;height:0;pointer-events:none;z-index:2147483000}" +
      ".hn-pin{position:absolute;display:flex;align-items:center;justify-content:center;" +
        "width:24px;height:24px;padding:0;border-radius:50%;box-sizing:border-box;" +
        "background:" + ACCENT + ";color:#fff;font:700 12px/1 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;" +
        "letter-spacing:0;box-shadow:0 2px 8px rgba(10,35,66,.28),0 0 0 2px rgba(255,255,255,.95);" +
        "cursor:pointer;pointer-events:auto;transform:translate(-50%,-50%);transition:transform .12s ease;" +
        "-webkit-font-smoothing:antialiased;user-select:none}" +
      ".hn-pin:hover{transform:translate(-50%,-50%) scale(1.12)}" +
      ".hn-hover-outline{outline:2px solid " + ACCENT + " !important;outline-offset:1px !important;cursor:crosshair}" +
      ".hn-pulse{animation:hn-pulse 1.2s ease-out 1}" +
      "@keyframes hn-pulse{0%{box-shadow:0 0 0 0 rgba(11,95,134,.42)}100%{box-shadow:0 0 0 14px rgba(11,95,134,0)}}" +
      "::highlight(hn-highlight){background-color:rgba(11,95,134,.18);color:inherit}" +
      "::highlight(hn-highlight-active){background-color:rgba(11,95,134,.36);color:inherit}" +
      ".hn-sel-btn{position:fixed;z-index:2147483600;display:flex;align-items:center;gap:6px;" +
        "height:34px;padding:0 13px;border:1px solid " + ACCENT + ";border-radius:12px;background:" + ACCENT + ";color:#fff;" +
        "font:600 13px/1 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;" +
        "box-shadow:0 8px 24px rgba(10,35,66,.18);cursor:pointer;" +
        "pointer-events:auto;white-space:nowrap;-webkit-font-smoothing:antialiased}" +
      ".hn-sel-btn:hover{border-color:" + ACCENT_HOVER + ";background:" + ACCENT_HOVER + "}";
    var style = document.createElement("style");
    style.id = "hn-style";
    style.textContent = css;
    (document.head || document.documentElement).appendChild(style);
  }

  function uniqueSelector(el) {
    if (!el || el.nodeType !== 1) return "";
    if (el === document.body) return "body";
    if (el.id) return "#" + CSS.escape(el.id);
    var parts = [];
    var node = el;
    while (node && node.nodeType === 1 && node.tagName !== "HTML" && node.tagName !== "BODY") {
      var part = node.tagName.toLowerCase();
      if (node.id) {
        parts.unshift("#" + CSS.escape(node.id));
        return parts.join(" > ");
      }
      var parent = node.parentElement;
      if (parent) {
        var sibs = Array.prototype.filter.call(parent.children, function (c) {
          return c.tagName === node.tagName;
        });
        if (sibs.length > 1) part += ":nth-of-type(" + (sibs.indexOf(node) + 1) + ")";
      }
      parts.unshift(part);
      node = node.parentElement;
    }
    return parts.length ? parts.join(" > ") : "body";
  }

  function snippet(el) {
    var txt = (el.innerText || "").trim().replace(/\s+/g, " ");
    return txt.length > 120 ? txt.slice(0, 120) + "…" : txt;
  }

  function resolve(selector) {
    try { return document.querySelector(selector); } catch (e) { return null; }
  }

  // --- text quote anchoring ---
  function normalize(s) {
    var out = "", map = [], prevSpace = false;
    for (var i = 0; i < s.length; i++) {
      var ch = s[i];
      if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r" || ch === "\f") {
        if (prevSpace) continue;
        out += " "; map.push(i); prevSpace = true;
      } else { out += ch; map.push(i); prevSpace = false; }
    }
    return { out: out, map: map };
  }

  // Find a Range within `root` matching the (whitespace-insensitive) quote.
  function findQuoteRange(root, quote) {
    if (!root || !quote) return null;
    var nodes = [], w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null), n;
    while ((n = w.nextNode())) nodes.push(n);
    if (!nodes.length) return null;
    var raw = "", starts = [];
    for (var i = 0; i < nodes.length; i++) { starts.push(raw.length); raw += nodes[i].nodeValue; }
    var H = normalize(raw);
    var needle = normalize(quote).out.trim();
    if (!needle) return null;
    var idx = H.out.indexOf(needle);
    if (idx < 0) return null;
    var rawStart = H.map[idx];
    var rawEnd = H.map[idx + needle.length - 1] + 1;
    function locate(pos) {
      for (var k = nodes.length - 1; k >= 0; k--) {
        if (starts[k] <= pos) return { node: nodes[k], offset: Math.min(pos - starts[k], nodes[k].nodeValue.length) };
      }
      return { node: nodes[0], offset: 0 };
    }
    var a = locate(rawStart), b = locate(rawEnd);
    try { var r = document.createRange(); r.setStart(a.node, a.offset); r.setEnd(b.node, b.offset); return r; }
    catch (e) { return null; }
  }

  function applyHighlights() {
    if (!supportsHL) return;
    var hl = new Highlight();
    state.pins.forEach(function (p) { if (p.range) hl.add(p.range); });
    CSS.highlights.set("hn-highlight", hl);
  }

  // --- element picker highlight (comment mode) ---
  function highlight(el) {
    if (state.highlight) state.highlight.classList.remove("hn-hover-outline");
    state.highlight = el;
    if (el && el.nodeType === 1) el.classList.add("hn-hover-outline");
  }
  function onMouseMove(e) { if (!state.modeOn) return; highlight(e.target); }
  function onClick(e) {
    if (!state.modeOn) return;
    e.preventDefault();
    e.stopPropagation();
    if (!e.target || e.target.nodeType !== 1) return;
    var sel = uniqueSelector(e.target);
    var r = e.target.getBoundingClientRect();
    var rect = { top: r.top, left: r.left, right: r.right, bottom: r.bottom, width: r.width, height: r.height };
    parent.postMessage({ hn: "pick", selector: sel, element_text: snippet(e.target), anchor_kind: "element", rect: rect }, "*");
    highlight(null);
  }
  function setMode(on) {
    state.modeOn = on;
    document.body.style.cursor = on ? "crosshair" : "";
    if (on) hideSelButton();
    else highlight(null);
  }

  function makeCommentIcon() {
    var ns = "http://www.w3.org/2000/svg";
    var svg = document.createElementNS(ns, "svg");
    svg.setAttribute("width", "14");
    svg.setAttribute("height", "14");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "2");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");

    var path = document.createElementNS(ns, "path");
    path.setAttribute("d", "M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z");
    svg.appendChild(path);

    return svg;
  }

  // --- text selection -> floating Comment bubble ---
  function ensureSelButton() {
    if (state.selBtn && state.selBtn.isConnected) return state.selBtn;
    state.selBtn = document.createElement("button");
    state.selBtn.className = "hn-sel-btn";
    state.selBtn.type = "button";
    state.selBtn.appendChild(makeCommentIcon());
    state.selBtn.appendChild(document.createTextNode("Comment"));
    state.selBtn.style.display = "none";
    // mousedown so the selection is still alive when we read it
    state.selBtn.addEventListener("mousedown", function (e) {
      e.preventDefault();
      e.stopPropagation();
      var sel = window.getSelection();
      if (!sel || sel.isCollapsed) { hideSelButton(); return; }
      var text = sel.toString().replace(/\s+/g, " ").trim();
      if (text.length < 2) { hideSelButton(); return; }
      if (text.length > 200) text = text.slice(0, 200);
      var range = sel.getRangeAt(0);
      var anchor = range.commonAncestorContainer;
      if (anchor.nodeType !== 1) anchor = anchor.parentElement;
      var selector = uniqueSelector(anchor) || "body";
      var rr = range.getBoundingClientRect();
      var rect = { top: rr.top, left: rr.left, right: rr.right, bottom: rr.bottom, width: rr.width, height: rr.height };
      var br = state.selBtn.getBoundingClientRect();
      var triggerRect = { top: br.top, left: br.left, right: br.right, bottom: br.bottom, width: br.width, height: br.height };
      parent.postMessage({ hn: "pick", selector: selector, element_text: text, anchor_kind: "text", rect: rect, trigger_rect: triggerRect }, "*");
      hideSelButton();
      sel.removeAllRanges();
    });
    document.documentElement.appendChild(state.selBtn);
    return state.selBtn;
  }
  function showSelButton(rect) {
    var b = ensureSelButton();
    b.style.left = (rect.left + rect.width / 2) + "px";
    b.style.top = Math.max(8, rect.top - 42) + "px";
    b.style.transform = "translateX(-50%)";
    b.style.display = "flex";
  }
  function hideSelButton() { if (state.selBtn) state.selBtn.style.display = "none"; }
  function onSelectionChange() {
    clearTimeout(state.selTimer);
    state.selTimer = setTimeout(function () {
      if (state.modeOn) { hideSelButton(); return; }
      var sel = window.getSelection();
      if (!sel || sel.isCollapsed || sel.rangeCount === 0) { hideSelButton(); return; }
      var text = sel.toString().trim();
      if (text.length < 2) { hideSelButton(); return; }
      var rect = sel.getRangeAt(0).getBoundingClientRect();
      if (!rect || (!rect.width && !rect.height)) { hideSelButton(); return; }
      showSelButton(rect);
    }, 120);
  }

  // --- pins + highlights ---
  function ensureLayer() {
    if (state.pinLayer && state.pinLayer.isConnected) return state.pinLayer;
    state.pinLayer = document.getElementById("hn-pin-layer");
    if (state.pinLayer && state.pinLayer.getAttribute("data-hn-pin-layer") !== "true") state.pinLayer = null;
    if (!state.pinLayer) {
      state.pinLayer = document.createElement("div");
      state.pinLayer.id = "hn-pin-layer";
      state.pinLayer.setAttribute("data-hn-pin-layer", "true");
      document.documentElement.appendChild(state.pinLayer);
    }
    return state.pinLayer;
  }

  function renderPins(items) {
    var layer = ensureLayer();
    var frag = document.createDocumentFragment();
    state.pins = [];
    (items || []).forEach(function (it) {
      var node = resolve(it.selector);
      if (!node) return;
      var range = it.quote ? findQuoteRange(node, it.quote) : null;
      var pin = document.createElement("div");
      pin.className = "hn-pin";
      pin.textContent = it.n;
      pin.title = (it.author ? it.author + " · " : "") + "Comment " + it.n;
      if (it.color) pin.style.background = it.color;
      pin.addEventListener("click", function (e) {
        e.preventDefault();
        e.stopPropagation();
        parent.postMessage({ hn: "pinclick", selector: it.selector, quote: it.quote || "" }, "*");
      });
      frag.appendChild(pin);
      state.pins.push({ selector: it.selector, quote: it.quote || "", kind: it.anchor_kind || (it.quote ? "text" : "element"), n: it.n, el: pin, node: node, range: range });
    });
    layer.replaceChildren(frag);
    applyHighlights();
    positionPins();
  }

  function firstUsableRect(rects) {
    for (var i = 0; i < rects.length; i++) {
      var r = rects[i];
      if (r && (r.width || r.height)) return r;
    }
    return null;
  }

  function anchorPoint(p) {
    if (p.range) {
      try {
        var rr = firstUsableRect(p.range.getClientRects());
        if (!rr) rr = p.range.getBoundingClientRect();
        if (rr && (rr.width || rr.height)) return { x: rr.right, y: rr.top };
      } catch (e) {}
    }
    if (p.node && p.node.isConnected) {
      var r = p.node.getBoundingClientRect();
      if (r && (r.width || r.height)) return { x: r.right, y: r.top };
    }
    return null;
  }

  function layerMetrics(layer) {
    var marker = layer.querySelector("#hn-pin-measure");
    if (!marker) {
      marker = document.createElement("div");
      marker.id = "hn-pin-measure";
      marker.style.cssText = "position:absolute;left:0;top:0;width:100px;height:100px;pointer-events:none;visibility:hidden;";
      layer.appendChild(marker);
    }
    var r = marker.getBoundingClientRect();
    return {
      left: r.left,
      top: r.top,
      sx: r.width ? r.width / 100 : 1,
      sy: r.height ? r.height / 100 : 1
    };
  }

  function positionPins() {
    if (!state.pins.length) return;
    var layer = ensureLayer();
    var m = layerMetrics(layer);
    state.pins.forEach(function (p) {
      var pt = anchorPoint(p);
      if (!pt) { p.el.style.display = "none"; return; }
      p.el.style.display = "";
      p.el.style.left = ((pt.x - m.left) / m.sx) + "px";
      p.el.style.top = ((pt.y - m.top) / m.sy) + "px";
    });
  }

  function scheduleReposition() {
    if (state.rafPending) return;
    state.rafPending = true;
    requestAnimationFrame(function () { state.rafPending = false; positionPins(); });
  }

  function locate(selector, quote) {
    var match = null;
    for (var i = 0; i < state.pins.length; i++) {
      if (state.pins[i].selector === selector && (state.pins[i].quote || "") === (quote || "")) { match = state.pins[i]; break; }
    }
    var node = match ? match.node : resolve(selector);
    if (!node) return;
    node.scrollIntoView({ behavior: "smooth", block: "center" });
    if (match && match.range && supportsHL) {
      var hl = new Highlight(); hl.add(match.range);
      CSS.highlights.set("hn-highlight-active", hl);
      setTimeout(function () { CSS.highlights.delete("hn-highlight-active"); }, 1300);
    } else {
      node.classList.remove("hn-pulse");
      void node.offsetWidth;
      node.classList.add("hn-pulse");
      setTimeout(function () { node.classList.remove("hn-pulse"); }, 1300);
    }
  }

  function isEditableTarget(t) {
    return !!t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName || ""));
  }

  function onKeyDown(e) {
    if (e.defaultPrevented) return;
    if ((e.key === "H" || e.key === "h" || e.code === "KeyH") && e.shiftKey && !e.ctrlKey && !e.metaKey && !e.altKey && !e.repeat && !isEditableTarget(e.target)) {
      parent.postMessage({ hn: "togglebar" }, "*");
    }
  }

  function notifyReady() {
    parent.postMessage({ hn: "ready" }, "*");
  }

  // --- page params (filters kept in the parent URL's query string) ---
  // The parent passes its query string in this iframe's fragment, so the page
  // can read it synchronously (location.hash) before this script even runs.
  var MAX_PARAMS = 2048;
  function currentParams() {
    return new URLSearchParams((location.hash || "").replace(/^#/, ""));
  }
  function sendParams(qs) {
    if (qs.length > MAX_PARAMS) return false;
    try { history.replaceState(null, "", qs ? "#" + qs : location.pathname + location.search); } catch (e) {}
    parent.postMessage({ hn: "params", query: qs }, "*");
    return true;
  }

  // --- peek.fetch (relayed by the parent page to /svc/<slug>/v/<n>/...) ---
  var FETCH_TIMEOUT_MS = 35000;
  var FETCH_METHODS = { GET: 1, POST: 1, PUT: 1, PATCH: 1, DELETE: 1 };
  var fetchPending = {};
  var fetchCounter = 0;

  function settleFetch(d) {
    var p = fetchPending[d.id];
    if (!p) return;
    delete fetchPending[d.id];
    clearTimeout(p.timer);
    if (d.ok === true) {
      var s = Number(d.status) || 0;
      var nullBody = s === 204 || s === 205 || s === 304;
      try {
        p.resolve(new Response(nullBody ? null : d.body, {
          status: s,
          headers: d.contentType ? { "content-type": String(d.contentType) } : {}
        }));
      } catch (err) {
        p.reject(new Error("peek.fetch bad response"));
      }
    } else {
      p.reject(new Error(typeof d.error === "string" && d.error ? d.error : "backend request failed"));
    }
  }

  function fetchHeaders(init) {
    var out = {};
    var h = init && init.headers;
    if (!h) return out;
    function keep(k, v) {
      k = String(k).toLowerCase();
      if (k === "content-type" || k === "accept") out[k] = String(v);
    }
    if (typeof Headers !== "undefined" && h instanceof Headers) h.forEach(function (v, k) { keep(k, v); });
    else Object.keys(h).forEach(function (k) { keep(k, h[k]); });
    return out;
  }

  // Resolves to {body, type}; rejects with TypeError for unsupported bodies.
  function fetchBody(body) {
    if (body === undefined || body === null) return Promise.resolve({ body: undefined, type: "" });
    if (typeof body === "string") return Promise.resolve({ body: body, type: "" });
    if (body instanceof ArrayBuffer) return Promise.resolve({ body: body, type: "" });
    if (ArrayBuffer.isView(body)) {
      return Promise.resolve({ body: body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength), type: "" });
    }
    if (typeof Blob !== "undefined" && body instanceof Blob) {
      return body.arrayBuffer().then(function (buf) { return { body: buf, type: body.type || "" }; });
    }
    if (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) {
      return Promise.resolve({ body: body.toString(), type: "application/x-www-form-urlencoded;charset=UTF-8" });
    }
    return Promise.reject(new TypeError("peek.fetch body type not supported"));
  }

  function peekFetch(path, init) {
    init = init || {};
    if (typeof path !== "string" || path.charAt(0) !== "/") {
      return Promise.reject(new TypeError("peek.fetch path must start with /"));
    }
    var method = String(init.method || "GET").toUpperCase();
    if (!FETCH_METHODS[method]) return Promise.reject(new TypeError("peek.fetch method not allowed"));
    var headers = fetchHeaders(init);
    return fetchBody(init.body).then(function (b) {
      if (b.type && !headers["content-type"]) headers["content-type"] = b.type;
      return new Promise(function (resolve, reject) {
        var id = "f" + (++fetchCounter);
        var timer = setTimeout(function () {
          delete fetchPending[id];
          reject(new Error("peek.fetch timed out"));
        }, FETCH_TIMEOUT_MS);
        fetchPending[id] = { resolve: resolve, reject: reject, timer: timer };
        parent.postMessage({ hn: "fetch", id: id, path: path, method: method, headers: headers, body: b.body }, "*");
      });
    });
  }

  window.peek = {
    fetch: peekFetch,
    get params() { return currentParams(); },
    // setParams({region: "eu", q: null}) merges into the current params;
    // null/undefined/"" removes a key. A string replaces them wholesale.
    setParams: function (next) {
      var qs;
      if (typeof next === "string") {
        qs = next.replace(/^[?#]/, "");
      } else {
        var p = currentParams();
        Object.keys(next || {}).forEach(function (k) {
          var v = next[k];
          if (v === null || v === undefined || v === "") p.delete(k);
          else if (Array.isArray(v)) { p.delete(k); v.forEach(function (x) { p.append(k, String(x)); }); }
          else p.set(k, String(v));
        });
        qs = p.toString();
      }
      return sendParams(qs);
    }
  };
  // Pages that simply assign location.hash are mirrored to the parent too.
  window.addEventListener("hashchange", function () {
    var qs = (location.hash || "").replace(/^#/, "");
    if (qs.length <= MAX_PARAMS) parent.postMessage({ hn: "params", query: qs }, "*");
  });

  // --- wiring ---
  window.addEventListener("mousemove", onMouseMove, true);
  window.addEventListener("click", onClick, true);
  window.addEventListener("scroll", function () { scheduleReposition(); hideSelButton(); }, true);
  window.addEventListener("resize", scheduleReposition);
  document.addEventListener("selectionchange", onSelectionChange);
  window.addEventListener("keydown", onKeyDown);
  window.addEventListener("load", function () {
    notifyReady();
    positionPins();
    setTimeout(positionPins, 300);
    setTimeout(positionPins, 1000);
  });

  window.addEventListener("message", function (e) {
    if (e.source !== parent) return;
    var d = e.data;
    if (!d || !d.hn) return;
    if (d.hn === "mode") setMode(d.on);
    else if (d.hn === "comments") renderPins(d.items);
    else if (d.hn === "locate") locate(d.selector, d.quote);
    else if (d.hn === "fetch-result") settleFetch(d);
  });

  injectStyles();
  notifyReady();
})();
