(function () {
  "use strict";

  const STORAGE_KEY = "hn_name";
  // One colour per comment author, from the logo's blues and teals outward. `color` carries
  // white text (the pin number); `text` is AA on the panel in light mode, `darkText` in dark mode.
  const AUTHOR_PALETTE = [
    { color: "#0b5f86", soft: "rgba(11, 95, 134, .13)", text: "#0b5f86", darkText: "#7fd3f0" },
    { color: "#0c7a72", soft: "rgba(12, 122, 114, .14)", text: "#08615a", darkText: "#6fe0cf" },
    { color: "#a35a00", soft: "rgba(163, 90, 0, .14)", text: "#8a4b00", darkText: "#f3b765" },
    { color: "#6d3fd1", soft: "rgba(109, 63, 209, .14)", text: "#5b2fb8", darkText: "#b9a2ff" },
    { color: "#c0264f", soft: "rgba(192, 38, 79, .13)", text: "#a51f43", darkText: "#ff94ad" },
    { color: "#2456a6", soft: "rgba(36, 86, 166, .14)", text: "#1d4a90", darkText: "#9cb9ff" },
  ];
  const DARK_SCHEME = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

  function frame() {
    const f = document.getElementById("hn-frame");
    return f ? f.contentWindow : null;
  }

  function postToFrame(msg) {
    const f = frame();
    if (f) {
      f.postMessage(msg, "*");
    }
  }

  function isEditableTarget(t) {
    return !!t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName || ""));
  }

  function isToggleBarKey(e) {
    return (e.key === "H" || e.key === "h" || e.code === "KeyH") && e.shiftKey && !e.ctrlKey && !e.metaKey && !e.altKey && !e.repeat && !isEditableTarget(e.target);
  }

  function colorizeComments(comments) {
    const byAuthor = new Map();
    let colorIndex = 0;
    return comments.map((comment, index) => {
      const author = (comment.verified === true ? "verified:" : "guest:") + (comment.author || "anonymous");
      if (!byAuthor.has(author)) {
        byAuthor.set(author, AUTHOR_PALETTE[colorIndex % AUTHOR_PALETTE.length]);
        colorIndex++;
      }
      return normalizeComment(comment, index, byAuthor.get(author));
    });
  }

  function normalizeComment(comment, index, color) {
    const created = comment.created_at ? new Date(comment.created_at * 1000) : null;
    return {
      ...comment,
      number: comment.selector ? index + 1 : 0,
      name: comment.author || "anonymous",
      verified: comment.verified === true,
      scope: comment.anchor_kind === "text" ? "Text" : (comment.anchor_kind === "element" ? "Element" : "Page"),
      target: comment.element_text || comment.selector || "",
      created_human: created && !Number.isNaN(created.getTime()) ? created.toLocaleString() : "",
      authorColor: color.color,
      authorSoft: color.soft,
      authorText: DARK_SCHEME && DARK_SCHEME.matches ? color.darkText : color.text,
    };
  }

  function fallbackOriginRect() {
    const width = 56;
    const height = 42;
    return {
      left: window.innerWidth / 2 - width / 2,
      top: window.innerHeight / 2 - height / 2,
      width: width,
      height: height,
    };
  }

  function rectFromElement(el) {
    if (!el || typeof el.getBoundingClientRect !== "function") {
      return fallbackOriginRect();
    }
    const r = el.getBoundingClientRect();
    return {
      left: r.left,
      top: r.top,
      width: r.width,
      height: r.height,
    };
  }

  function normalizeRect(rect) {
    if (!rect) {
      return fallbackOriginRect();
    }
    const width = Math.max(24, Math.min(Number(rect.width) || 44, window.innerWidth - 16));
    const height = Math.max(24, Math.min(Number(rect.height) || 40, window.innerHeight - 16));
    const left = Math.min(Math.max(8, Number(rect.left) || 0), Math.max(8, window.innerWidth - width - 8));
    const top = Math.min(Math.max(8, Number(rect.top) || 0), Math.max(8, window.innerHeight - height - 8));
    return { left: left, top: top, width: width, height: height };
  }

  function setMorphOrigin(rect) {
    const anchor = document.getElementById("hn-morph-anchor");
    if (!anchor) return;
    const r = normalizeRect(rect);
    anchor.style.left = r.left + "px";
    anchor.style.top = r.top + "px";
    anchor.style.width = r.width + "px";
    anchor.style.height = r.height + "px";
  }

  function composerElement() {
    return document.getElementById("hn-composer");
  }

  async function responseMessage(res, fallback) {
    const contentType = res.headers.get("Content-Type") || "";
    if (contentType.indexOf("application/json") !== -1) {
      try {
        const data = await res.json();
        return (data && data.error) || fallback;
      } catch (e) {
        return fallback;
      }
    }
    try {
      const text = await res.text();
      return text || fallback;
    } catch (e) {
      return fallback;
    }
  }

  document.addEventListener("alpine:init", () => {
    Alpine.data("pageApp", () => ({
      slug: "",
      version: 0,
      visibility: "restricted",

      comments: [],
      commentCount: 0,
      panelOpen: false,
      panelLoading: false,
      panelLoaded: false,
      activeComment: null,

      viewCount: 0,
      showSparkline: false,
      barHidden: false,
      barHintShown: false,
      sparklineTotal: "",
      sparklineUnique: "",

      commentMode: false,
      composerOpen: false,
      composerTarget: null,
      composerTargetLabel: "",
      composerTargetIsGeneral: false,
      composerBody: "",
      composerError: "",

      name: localStorage.getItem(STORAGE_KEY) || "",
      nameInput: "",
      nameModalOpen: false,
      pendingCommentAfterName: false,
      allowAnonymousComment: false,
      frameLoads: 0,
      fetchInFlight: 0,
      reloadPending: false,

      init() {
        const dataset = document.body ? document.body.dataset : {};
        this.slug = dataset.slug || "";
        this.version = Number(dataset.version) || 0;
        this.visibility = dataset.visibility || "restricted";

        const stored = localStorage.getItem(STORAGE_KEY);
        if (stored) {
          this.name = stored;
        } else if (!localStorage.getItem("hn_name_asked")) {
          this.nameModalOpen = true;
          localStorage.setItem("hn_name_asked", "1");
        }

        this.bindBridge();
        this.bindKeyboard();
        this.loadComments();
        this.loadViews();
        if (dataset.live === "1") this.watchVersions();
      },

      // watchVersions reloads the page when a newer version is uploaded. Only the
      // latest-version link (/p/{slug}) is live; a /v/{n} link stays put.
      watchVersions() {
        if (!this.slug || typeof EventSource !== "function") return;
        const source = new EventSource("/api/uploads/" + this.slug + "/events");
        source.addEventListener("version", (ev) => {
          if ((Number(ev.data) || 0) <= this.version) return;
          source.close();
          this.reloadPending = true;
          this.reloadWhenIdle();
        });
        const retry = () => this.reloadWhenIdle();
        document.addEventListener("visibilitychange", retry);
        this.$watch("composerOpen", retry);
        this.$watch("nameModalOpen", retry);
        this.$watch("nameInput", retry);
        this.$watch("commentMode", retry);
      },

      // reloadWhenIdle waits while the tab is hidden or the viewer is writing a
      // comment, so a reload never throws away unsent text.
      reloadWhenIdle() {
        if (!this.reloadPending) return;
        const typingName = this.nameModalOpen && this.nameInput.trim() !== "";
        if (document.hidden || this.composerOpen || typingName || this.commentMode) return;
        this.reloadPending = false;
        window.location.reload();
      },

      loadComments() {
        if (!this.slug) return;
        this.panelLoading = true;
        fetch("/api/uploads/" + this.slug + "/comments" + (this.version ? "?v=" + this.version : ""), {
          credentials: "same-origin",
        })
          .then((r) => r.json())
          .then((data) => {
            const comments = Array.isArray(data) ? data : (data.comments || []);
            this.comments = colorizeComments(comments);
            this.commentCount = this.comments.length;
            this.panelLoading = false;
            this.panelLoaded = true;
            this.sendPins();
          })
          .catch(() => {
            this.panelLoading = false;
          });
      },

      loadViews() {
        if (!this.slug) return;
        fetch("/api/uploads/" + this.slug + "/views", {
          credentials: "same-origin",
        })
          .then((r) => r.json())
          .then((data) => {
            this.viewCount = data.total || 0;
            this.sparklineTotal = (data.total || 0) + " visits";
            this.sparklineUnique = (data.unique || 0) + " unique";
            this.renderSparkline((data.buckets || []).map((b) => b.n));
          })
          .catch(() => {});
      },

      renderSparkline(counts) {
        const svg = document.getElementById("hn-sparkline-svg");
        if (!svg || !counts.length) return;

        const w = 168, h = 56, pad = 2;
        const max = Math.max.apply(null, counts) || 1;
        const stepX = (w - pad * 2) / Math.max(counts.length - 1, 1);

        let points = "";
        for (let i = 0; i < counts.length; i++) {
          const x = pad + i * stepX;
          const y = h - pad - (counts[i] / max) * (h - pad * 4);
          points += (i ? " L " : "M ") + x.toFixed(1) + " " + y.toFixed(1);
        }

        const area = points + " L " + (pad + (counts.length - 1) * stepX).toFixed(1) + " " + (h - pad) + " L " + pad.toFixed(1) + " " + (h - pad) + " Z";
        const lastX = pad + (counts.length - 1) * stepX;
        const lastY = h - pad - (counts[counts.length - 1] / max) * (h - pad * 4);

        while (svg.firstChild) svg.removeChild(svg.firstChild);

        const NS = "http://www.w3.org/2000/svg";
        const areaPath = document.createElementNS(NS, "path");
        areaPath.setAttribute("d", area);
        areaPath.setAttribute("fill", "rgba(22,119,232,.14)");
        svg.appendChild(areaPath);

        const linePath = document.createElementNS(NS, "path");
        linePath.setAttribute("d", points);
        linePath.setAttribute("fill", "none");
        linePath.setAttribute("stroke", "rgb(22,119,232)");
        linePath.setAttribute("stroke-width", "1.5");
        linePath.setAttribute("stroke-linecap", "round");
        linePath.setAttribute("stroke-linejoin", "round");
        svg.appendChild(linePath);

        const dot = document.createElementNS(NS, "circle");
        dot.setAttribute("cx", lastX.toFixed(1));
        dot.setAttribute("cy", lastY.toFixed(1));
        dot.setAttribute("r", "2.5");
        dot.setAttribute("fill", "rgb(22,119,232)");
        svg.appendChild(dot);
      },

      bindBridge() {
        const f = document.getElementById("hn-frame");
        if (f) {
          f.addEventListener("load", () => {
            this.frameLoads += 1;
            this.syncFrame();
          });
        }

        window.addEventListener("message", (e) => {
          if (e.source !== frame()) return;
          const data = e.data;
          if (!data) return;

          if (data.hn === "ready") {
            this.syncFrame();
            return;
          }
          if (data.hn === "params") {
            this.syncParams(data.query);
            return;
          }
          if (data.hn === "togglebar") {
            this.toggleBar();
            return;
          }
          if (data.hn === "fetch") {
            this.relayFetch(data);
            return;
          }
          if (data.hn === "pick") {
            this.openComposer(data);
            return;
          }
          if (data.hn === "pinclick") {
            this.panelOpen = true;
            const match = this.comments.find((c) => c.selector === data.selector && (c.element_text || "") === (data.quote || ""));
            if (match) {
              this.activeComment = match.id;
              setTimeout(() => {
                if (this.activeComment === match.id) this.activeComment = null;
              }, 3000);
            }
            return;
          }
          if (!data.type) return;

          switch (data.type) {
            case "elementSelected":
              this.openComposer(data);
              break;
            case "commentModeEscaped":
              this.commentMode = false;
              break;
          }
        });
      },

      // relayFetch forwards a peek.fetch call from the page to /svc with the
      // viewer's cookies. Everything the page sent is untrusted: validate it,
      // and only ever build URLs under this page version's /svc prefix.
      relayFetch(d) {
        const id = typeof d.id === "string" && d.id.length <= 32 ? d.id : "";
        const reply = (msg) => postToFrame(Object.assign({ hn: "fetch-result", id }, msg));
        if (!id) return;
        // After the second load the iframe has navigated away from the uploaded
        // page; a site the viewer clicked into must not use the backend.
        if (this.frameLoads > 1) {
          reply({ ok: false, error: "page navigated; reload to use the backend" });
          return;
        }
        const methods = ["GET", "POST", "PUT", "PATCH", "DELETE"];
        let valid = typeof d.path === "string" && d.path.charAt(0) === "/" && d.path.length <= 2048;
        valid = valid && typeof d.method === "string" && methods.includes(d.method);
        valid = valid && !!d.headers && typeof d.headers === "object" && !Array.isArray(d.headers);
        if (valid) {
          valid = Object.keys(d.headers).every(
            (k) => (k === "content-type" || k === "accept") && typeof d.headers[k] === "string"
          );
        }
        valid = valid && (d.body === undefined || typeof d.body === "string" || d.body instanceof ArrayBuffer);
        if (!valid) {
          reply({ ok: false, error: "invalid peek.fetch request" });
          return;
        }
        if (this.fetchInFlight >= 16) {
          reply({ ok: false, error: "too many concurrent peek.fetch requests" });
          return;
        }
        const prefix = "/svc/" + encodeURIComponent(this.slug) + "/v/" + this.version + "/";
        const url = new URL(prefix + d.path.slice(1), location.origin);
        if (!(url.origin === location.origin && url.pathname.startsWith(prefix))) {
          reply({ ok: false, error: "invalid peek.fetch path" });
          return;
        }
        this.fetchInFlight += 1;
        fetch(url, {
          method: d.method,
          headers: Object.assign({}, d.headers, { "X-Peek-Svc": "1" }),
          body: d.body,
          credentials: "same-origin",
          redirect: "error",
          cache: "no-store",
        })
          .then((res) =>
            res.arrayBuffer().then((body) =>
              reply({ ok: true, status: res.status, contentType: res.headers.get("content-type") || "", body })
            )
          )
          .catch(() => reply({ ok: false, error: "backend request failed" }))
          .finally(() => {
            this.fetchInFlight -= 1;
          });
      },

      bindKeyboard() {
        document.addEventListener("keydown", (e) => {
          if (isToggleBarKey(e)) {
            e.preventDefault();
            this.toggleBar();
            return;
          }
          if (e.key === "Escape") {
            if (this.nameModalOpen) {
              this.closeNameModal();
              return;
            }
            if (this.composerOpen) {
              this.closeComposer();
              return;
            }
            if (this.commentMode) {
              this.commentMode = false;
              return;
            }
            if (this.panelOpen) {
              this.panelOpen = false;
            }
          }
        });
      },

      // Mirror the page's on-page filters into this URL's query string.
      syncParams(query) {
        if (typeof query !== "string" || query.length > 2048) return;
        const qs = query.replace(/^[?#]/, "");
        const url = window.location.pathname + (qs ? "?" + qs : "") + window.location.hash;
        try {
          history.replaceState(null, "", url);
        } catch (e) {}
      },

      toggleCommentMode() {
        this.commentMode = !this.commentMode;
        if (this.commentMode) {
          postToFrame({ hn: "mode", on: true });
        } else {
          postToFrame({ hn: "mode", on: false });
          if (this.composerOpen) this.closeComposer();
        }
      },

      syncFrame() {
        postToFrame({ hn: "mode", on: this.commentMode });
        this.sendPins();
      },

      startGeneralComment(event) {
        setMorphOrigin(rectFromElement(event && event.currentTarget));
        this.composerTarget = { selector: "", text: "", anchorKind: "page", style: "" };
        this.composerTargetLabel = "General comment on this page";
        this.composerTargetIsGeneral = true;
        this.composerBody = "";
        this.composerError = "";
        this.showComposer();
      },

      openComposer(data) {
        setMorphOrigin(data.trigger_rect || data.rect);
        this.composerTarget = {
          selector: data.selector || "",
          text: data.element_text || data.text || "",
          anchorKind: data.anchor_kind || (data.selector ? "element" : "page"),
          style: "",
        };
        this.composerTargetLabel = data.target || data.element_text || data.text || data.selector || "General comment on this page";
        this.composerTargetIsGeneral = false;
        this.composerBody = "";
        this.composerError = "";
        this.commentMode = false;
        postToFrame({ hn: "mode", on: false });
        this.showComposer();
      },

      showComposer() {
        this.composerOpen = true;
        this.$nextTick(() => {
          const composer = composerElement();
          if (composer && typeof composer.showPopover === "function" && !composer.matches(":popover-open")) {
            try {
              composer.showPopover();
            } catch (e) {}
          }
          const ta = this.$refs.composerTextarea;
          if (ta) ta.focus();
        });
      },

      closeComposer() {
        const composer = composerElement();
        if (composer && typeof composer.hidePopover === "function" && composer.matches(":popover-open")) {
          try {
            composer.hidePopover();
          } catch (e) {}
        }
        this.composerOpen = false;
        this.scheduleComposerClear();
      },

      scheduleComposerClear() {
        setTimeout(() => {
          if (this.composerOpen) return;
          this.composerTarget = null;
          this.composerBody = "";
          this.composerError = "";
        }, 420);
      },

      syncComposerPopover(event) {
        if (event && event.newState === "closed" && this.composerOpen) {
          if (this.nameModalOpen) return;
          this.composerOpen = false;
          this.scheduleComposerClear();
        }
      },

      showComposerError(message) {
        this.composerError = message;
        window.peekToast(message, { type: "danger", duration: 6500 });
      },

      async postComment() {
        const body = (this.composerBody || "").trim();
        if (!body) return;

        this.composerError = "";
        if (!this.slug) {
          this.showComposerError("Page is still loading. Please try again.");
          return;
        }
        if (!this.name && !this.allowAnonymousComment) {
          this.pendingCommentAfterName = true;
          this.showNameModal();
          return;
        }
        this.pendingCommentAfterName = false;
        this.allowAnonymousComment = false;

        const target = this.composerTarget;
        const payload = { body: body, name: this.name || "" };
        if (target) {
          payload.selector = target.selector || "";
          payload.element_text = target.text || "";
          payload.anchor_kind = target.anchorKind || "";
        }

        try {
          const res = await fetch("/api/uploads/" + this.slug + "/comments" + (this.version ? "?v=" + this.version : ""), {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
          });

          if (!res.ok) {
            const text = await responseMessage(res, "Failed to post comment.");
            this.showComposerError(text);
            return;
          }

          this.closeComposer();
          this.loadComments();
        } catch (e) {
          this.showComposerError("Network error. Please try again.");
        }
      },

      sendPins() {
        const items = this.comments
          .filter((c) => c.selector)
          .map((c) => ({
            selector: c.selector,
            quote: c.anchor_kind === "text" ? c.element_text : "",
            anchor_kind: c.anchor_kind,
            n: c.number,
            color: c.authorColor,
            author: c.name,
          }));
        postToFrame({ hn: "comments", items: items });
      },

      locateComment(c) {
        if (!c.selector) return;
        this.activeComment = c.id;
        postToFrame({ hn: "locate", selector: c.selector, quote: c.anchor_kind === "text" ? c.element_text : "" });
        setTimeout(() => {
          if (this.activeComment === c.id) this.activeComment = null;
        }, 3000);
      },

      exportComments(format) {
        let text = "";
        if (format === "json") {
          text = JSON.stringify(this.comments, null, 2);
        } else {
          for (const c of this.comments) {
            text += "## " + (c.name || "anonymous") + (c.verified ? " (signed in)" : "") + " (" + c.created_human + ")\n";
            if (c.target) text += "> on: " + c.target + "\n";
            text += "\n" + c.body + "\n\n---\n\n";
          }
        }
        window.peekCopyText(text, { success: format === "json" ? "Copied comments as JSON." : "Copied comments as Markdown." });
      },

      showNameModal() {
        this.nameInput = this.name || "";
        this.nameModalOpen = true;
        localStorage.setItem("hn_name_asked", "1");
        const composer = composerElement();
        if (composer && typeof composer.hidePopover === "function" && composer.matches(":popover-open")) {
          try {
            composer.hidePopover();
          } catch (e) {}
        }
        this.$nextTick(() => {
          const inp = this.$refs.nameInput;
          if (inp) inp.focus();
        });
      },

      closeNameModal() {
        this.nameModalOpen = false;
        this.pendingCommentAfterName = false;
        this.allowAnonymousComment = false;
      },

      saveName() {
        const n = (this.nameInput || "").trim();
        if (!n) {
          const inp = this.$refs.nameInput;
          if (inp) inp.focus();
          return;
        }
        const resume = this.pendingCommentAfterName;
        this.pendingCommentAfterName = false;
        this.allowAnonymousComment = false;
        this.name = n;
        localStorage.setItem(STORAGE_KEY, n);
        localStorage.setItem("hn_name_asked", "1");
        this.nameModalOpen = false;
        if (resume) {
          this.$nextTick(() => {
            this.postComment();
          });
        }
      },

      skipName() {
        const resume = this.pendingCommentAfterName;
        this.pendingCommentAfterName = false;
        this.nameModalOpen = false;
        localStorage.setItem("hn_name_asked", "1");
        if (resume) {
          this.allowAnonymousComment = true;
          this.$nextTick(() => {
            this.postComment();
          });
        }
      },

      toggleSparkline() {
        this.showSparkline = !this.showSparkline;
      },

      hideBar() {
        if (this.barHidden) return;
        this.showSparkline = false;
        if (this.commentMode) this.toggleCommentMode();
        this.barHidden = true;
        if (!this.barHintShown) {
          this.barHintShown = true;
          window.peekToast("Toolbar hidden", { type: "info", description: "Press Shift+H to show it again." });
        }
      },

      showBar() {
        this.barHidden = false;
      },

      toggleBar() {
        if (this.barHidden) {
          this.showBar();
        } else {
          this.hideBar();
        }
      },
    }));
  });
})();
