(function () {
  "use strict";

  function clipboardState() {
    return {
      copied: "",

      copy(text, success) {
        const value = String(text || "");
        return window.peekCopyText(value, { success: success || "Copied link." }).then((ok) => {
          if (ok) {
            this.copied = value;
            setTimeout(() => { if (this.copied === value) this.copied = ""; }, 1500);
          }
          return ok;
        });
      },

      absoluteURL(value) {
        const text = String(value || "");
        try {
          return new URL(text, window.location.origin).href;
        } catch (e) {
          return text;
        }
      },

      copyAbsolute(value) {
        this.copy(this.absoluteURL(value));
      },
    };
  }

  document.addEventListener("alpine:init", () => {
    Alpine.data("dashboard", () => ({
      ...clipboardState(),
      mode: "file",
      visibility: "restricted",
      fileName: "",
      fileSizeLabel: "",
      html: "",
      name: "",

      setSelectedFile(file) {
        if (!file) {
          this.fileName = "";
          this.fileSizeLabel = "";
          return;
        }
        this.fileName = file.name || "Selected file";
        this.fileSizeLabel = this.formatFileSize(file.size);
      },

      formatFileSize(bytes) {
        const size = Number(bytes);
        if (!Number.isFinite(size) || size < 0) return "";
        if (size < 1024) return `${size} B`;
        if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
        return `${(size / (1024 * 1024)).toFixed(1)} MB`;
      },

      canUpload() {
        if (this.mode === "empty") return this.name.trim() !== "";
        if (this.mode === "paste") return this.html.trim().length > 0;
        return this.fileName !== "";
      },

      guardUploadSubmit(event) {
        if (!this.canUpload()) {
          event.preventDefault();
        }
      },

      confirm(event, message) {
        if (!window.confirm(message)) {
          event.preventDefault();
        }
      },
    }));

    Alpine.data("admin", (initial = {}) => ({
      ...clipboardState(),
      settingsTab: "auth",
      oauth: {
        google: Boolean(initial.googleOAuth),
        github: Boolean(initial.githubOAuth),
        oidc: Boolean(initial.oidcOAuth),
      },
      storageBackend: initial.storageBackend || "file",

      confirm(event, message) {
        if (!window.confirm(message)) {
          event.preventDefault();
        }
      },
    }));
  });
})();
