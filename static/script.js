(() => {
  const form = document.getElementById("scanForm");
  const loading = document.getElementById("loading");
  const input = form ? form.querySelector("input[name='url']") : null;

  /* ------------------------------
     Loading Animation Controls
  ------------------------------ */
  function showLoading() {
    if (loading) loading.classList.remove("hidden");
    if (form) {
      Array.from(form.elements).forEach(el => el.disabled = true);
    }
  }

  function hideLoading() {
    if (loading) loading.classList.add("hidden");
    if (form) {
      Array.from(form.elements).forEach(el => el.disabled = false);
    }
  }

  /* ------------------------------
     Simple URL Validation
  ------------------------------ */
  function isLikelyUrl(s) {
    if (!s || typeof s !== "string") return false;
    s = s.trim();
    if (s.indexOf(" ") !== -1) return false;
    if (s.indexOf(".") === -1) return false;
    return true;
  }

  /* ------------------------------
     History Management
  ------------------------------ */
  function saveHistory(url, label, confidence) {
    try {
      const key = "phish_scan_history_v1";
      const raw = localStorage.getItem(key);
      const hist = raw ? JSON.parse(raw) : [];
      hist.unshift({ url, label, confidence, ts: Date.now() });
      const trimmed = hist.slice(0, 8);
      localStorage.setItem(key, JSON.stringify(trimmed));
      renderHistory();
    } catch (e) {
      // ignore localStorage errors
    }
  }

  function renderHistory() {
    const h = document.getElementById("history");
    if (!h) return;
    const raw = localStorage.getItem("phish_scan_history_v1");
    if (!raw) {
      h.innerHTML = `<p class="history-empty">No recent scans</p>`;
      return;
    }
    const hist = JSON.parse(raw);
    if (!hist.length) {
      h.innerHTML = `<p class="history-empty">No recent scans</p>`;
      return;
    }
    h.innerHTML = hist
      .map(item => {
        const time = new Date(item.ts).toLocaleString();
        const safeClass = (item.label || "").toLowerCase().includes("phish")
          ? "danger"
          : "success";
        return `<div class="history-item ${safeClass}">
                  <div class="h-url">${escapeHtml(item.url)}</div>
                  <div class="h-meta">
                    <span class="h-label">${escapeHtml(item.label)}</span> · 
                    ${item.confidence}% · 
                    <span class="h-time">${time}</span>
                  </div>
                </div>`;
      })
      .join("");
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  /* ------------------------------
     AJAX Prediction Handler
  ------------------------------ */
  async function postAndReplace(url, formData) {
    try {
      const res = await fetch(url, {
        method: "POST",
        body: formData,
        headers: { "X-Requested-With": "XMLHttpRequest" },
        credentials: "same-origin"
      });
      if (!res.ok) throw new Error("Network response not ok");
      const text = await res.text();

      // Parse minimal info for history
      const parser = new DOMParser();
      const doc = parser.parseFromString(text, "text/html");
      const labelEl = doc.querySelector(".result-card h2, .alert, .result-card strong");
      const confEl = doc.querySelector(".confidence, .alert small, .result-card p");
      const urlText = formData.get("url");
      const label = labelEl ? labelEl.textContent.trim() : "Result";
      let conf = confEl ? (confEl.textContent.match(/(\d+(\.\d+)?)/) || [null])[0] : null;
      conf = conf ? parseFloat(conf) : null;

      if (label) saveHistory(urlText, label, conf || 0);

      // Replace the full page with new HTML
      document.open();
      document.write(text);
      document.close();
    } catch (err) {
      console.warn("AJAX predict failed; falling back to normal submit.", err);
      form.submit();
    }
  }

  /* ------------------------------
     Form Event Handling
  ------------------------------ */
  if (form) {
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      const val = input.value.trim();
      if (!isLikelyUrl(val)) {
        input.classList.add("invalid");
        input.focus();
        return;
      }
      input.classList.remove("invalid");
      showLoading();
      const fd = new FormData(form);
      postAndReplace(form.action || "/predict", fd).finally(() => hideLoading());
    });
  }

  /* ------------------------------
     Confidence Bar Animation
  ------------------------------ */
  document.addEventListener("DOMContentLoaded", () => {
    const confidenceInput = document.getElementById("confidenceData");
    const confidenceFill = document.getElementById("confidenceFill");
    const confidenceValue = document.getElementById("confidenceValue");

    if (confidenceInput && confidenceFill) {
      let confidence = parseFloat(confidenceInput.value) || 0;
      confidence = Math.min(100, Math.max(0, confidence));

      // Animate bar width smoothly
      requestAnimationFrame(() => {
        confidenceFill.style.transition = "width 0.8s ease";
        confidenceFill.style.width = confidence + "%";
      });

      // Update text display
      if (confidenceValue) confidenceValue.textContent = confidence.toFixed(2) + "%";
    }

    // Render history on every page load
    renderHistory();
  });

  /* ------------------------------
     Expose for Debugging
  ------------------------------ */
  window.PhishUI = { renderHistory, saveHistory, isLikelyUrl };
})();
