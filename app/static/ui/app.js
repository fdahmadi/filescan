(() => {
  const apiKeyInput = document.getElementById("apiKey");
  const sensitivityEl = document.getElementById("sensitivity");
  const useRemoteIntelEl = document.getElementById("useRemoteIntel");
  const fileInput = document.getElementById("fileInput");
  const dropzone = document.getElementById("dropzone");
  const fileNameEl = document.getElementById("fileName");
  const scanBtn = document.getElementById("scanBtn");
  const statusLine = document.getElementById("statusLine");
  const resultEl = document.getElementById("result");
  const verdictEl = document.getElementById("verdict");
  const summaryEl = document.getElementById("summary");
  const metaEl = document.getElementById("meta");
  const scanIdRow = document.getElementById("scanIdRow");
  const scanIdEl = document.getElementById("scanId");
  const copyScanIdBtn = document.getElementById("copyScanId");
  const enginesEl = document.getElementById("engines");
  const healthLine = document.getElementById("healthLine");

  let selectedFile = null;
  const KEY_STORE = "filescan.apiKey";
  const DEMO_KEY = "dev-demo-key";

  // Pilot default: prefill demo key unless the user already saved another value
  const savedKey = sessionStorage.getItem(KEY_STORE);
  apiKeyInput.value = savedKey !== null ? savedKey : DEMO_KEY;
  if (savedKey === null) sessionStorage.setItem(KEY_STORE, DEMO_KEY);

  apiKeyInput.addEventListener("change", () => {
    sessionStorage.setItem(KEY_STORE, apiKeyInput.value.trim());
  });

  function setFile(file) {
    selectedFile = file || null;
    if (!selectedFile) {
      fileNameEl.hidden = true;
      fileNameEl.textContent = "";
      dropzone.classList.remove("has-file");
      scanBtn.disabled = true;
      return;
    }
    fileNameEl.hidden = false;
    fileNameEl.textContent = `${selectedFile.name} · ${formatBytes(selectedFile.size)}`;
    dropzone.classList.add("has-file");
    scanBtn.disabled = false;
  }

  function formatBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  }

  dropzone.addEventListener("click", () => fileInput.click());
  dropzone.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      fileInput.click();
    }
  });
  fileInput.addEventListener("change", () => setFile(fileInput.files?.[0]));

  ["dragenter", "dragover"].forEach((evt) => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    });
  });
  ["dragleave", "drop"].forEach((evt) => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
    });
  });
  dropzone.addEventListener("drop", (e) => {
    const file = e.dataTransfer?.files?.[0];
    if (file) {
      fileInput.value = "";
      setFile(file);
    }
  });

  scanBtn.addEventListener("click", async () => {
    if (!selectedFile) return;
    const key = apiKeyInput.value.trim();
    sessionStorage.setItem(KEY_STORE, key);

    scanBtn.disabled = true;
    scanBtn.classList.add("busy");
    scanBtn.textContent = "Scanning…";
    statusLine.textContent = "Running engines…";
    resultEl.hidden = true;

    const body = new FormData();
    body.append("file", selectedFile, selectedFile.name);
    body.append("sensitivity", sensitivityEl.value || "balanced");
    body.append("use_remote_intel", useRemoteIntelEl.checked ? "true" : "false");

    const headers = {};
    if (key) headers["X-API-Key"] = key;

    try {
      const res = await fetch("/v1/scan", { method: "POST", headers, body });
      const text = await res.text();
      let data;
      try {
        data = JSON.parse(text);
      } catch {
        throw new Error(text || `HTTP ${res.status}`);
      }
      if (!res.ok) {
        const detail = data.detail;
        const msg = typeof detail === "string" ? detail : JSON.stringify(detail || data);
        throw new Error(msg || `HTTP ${res.status}`);
      }
      renderResult(data);
      statusLine.textContent = "Scan complete.";
    } catch (err) {
      statusLine.textContent = err.message || "Scan failed.";
      resultEl.hidden = true;
    } finally {
      scanBtn.classList.remove("busy");
      scanBtn.textContent = "Scan file";
      scanBtn.disabled = !selectedFile;
    }
  });

  function renderResult(data) {
    const verdict = (data.verdict || "unknown").toLowerCase();
    verdictEl.textContent = verdict;
    verdictEl.className = `verdict ${verdict}`;

    const engines = data.engines || [];
    const flagged = engines.filter((e) =>
      ["infected", "matched", "suspicious"].includes(String(e.status || "").toLowerCase())
    );
    const names = flagged.map((e) => e.name).slice(0, 6);
    const sens = data.sensitivity || sensitivityEl.value || "balanced";
    const remote =
      typeof data.use_remote_intel === "boolean"
        ? data.use_remote_intel
        : useRemoteIntelEl.checked;
    const remoteLabel = remote ? "remote on" : "local only";
    if (flagged.length) {
      summaryEl.textContent = `${flagged.length} engine(s) flagged · ${names.join(", ")} · ${sens} · ${remoteLabel}`;
    } else {
      summaryEl.textContent = `No engine flags · ${sens} · ${remoteLabel}`;
    }

    const file = data.file || {};
    const scanId = data.id != null && data.id !== "" ? String(data.id) : "";
    const bits = [
      scanId && `id ${scanId}`,
      file.name && file.name,
      file.mime && file.mime,
      file.sha256 && `sha256 ${String(file.sha256).slice(0, 16)}…`,
      data.cache_hit ? "cache hit" : null,
    ].filter(Boolean);
    metaEl.textContent = bits.join(" · ");

    if (scanId && scanIdRow && scanIdEl && copyScanIdBtn) {
      scanIdEl.textContent = scanId;
      scanIdRow.removeAttribute("hidden");
      scanIdRow.style.display = "flex";
      copyScanIdBtn.textContent = "Copy";
      copyScanIdBtn.onclick = async () => {
        try {
          await navigator.clipboard.writeText(scanId);
          copyScanIdBtn.textContent = "Copied";
          setTimeout(() => {
            copyScanIdBtn.textContent = "Copy";
          }, 1500);
        } catch {
          copyScanIdBtn.textContent = "Failed";
          setTimeout(() => {
            copyScanIdBtn.textContent = "Copy";
          }, 1500);
        }
      };
    } else if (scanIdRow) {
      if (scanIdEl) scanIdEl.textContent = "";
      scanIdRow.setAttribute("hidden", "");
      scanIdRow.style.display = "none";
      if (copyScanIdBtn) copyScanIdBtn.onclick = null;
    }

    enginesEl.innerHTML = "";
    engines.forEach((eng) => {
      const row = document.createElement("div");
      row.className = "engine";
      const status = (eng.status || "").toLowerCase();
      const threats = (eng.threats || []).slice(0, 3).join(", ");
      const detail = eng.details ? String(eng.details).slice(0, 100) : "";
      const body = threats || detail || "—";
      row.innerHTML = `
        <div class="engine-name">${escapeHtml(eng.name || "engine")}</div>
        <div class="engine-body">
          <span class="engine-status ${escapeHtml(status)}">${escapeHtml(status)}</span>
          ${escapeHtml(body)}
        </div>
      `;
      enginesEl.appendChild(row);
    });

    resultEl.hidden = false;
  }

  function escapeHtml(s) {
    return String(s)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  }

  async function refreshHealth() {
    try {
      const res = await fetch("/v1/health");
      const data = await res.json();
      const ok = (data.engines || []).filter((e) => e.enabled && e.healthy).length;
      const total = (data.engines || []).filter((e) => e.enabled).length;
      healthLine.textContent = `Service ${data.status} · ${ok}/${total} engines healthy · v${data.version || "?"}`;
    } catch {
      healthLine.textContent = "Service unreachable";
    }
  }

  refreshHealth();
})();
