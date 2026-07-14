// CPA Login Hub — panel client.
//
// Flow (CPA-first):
//   1. User clicks CPA's Login Hub OAuth button → CPA calls our
//      AuthProvider.StartLogin → we return URL=<panel-url>?state=<token>.
//   2. CPA frontend opens that URL with window.open(_, _, "noopener").
//      This file loads with state in URL search params.
//   3. Bootstrap: read management key from sessionStorage (if the user
//      already entered it on a previous panel visit), otherwise prompt.
//      Public /schema resource — no auth required for that one.
//   4. User picks provider + fills form + submits.
//   5. POST /submit-login?state=<token> with Authorization: Bearer <key>.
//   6. Poll get-auth-status?state=<token> — same Bearer auth.
//
// i18n comes from window.cpaI18n (see i18n.js). All user-visible strings
// pass through t(key). Language + theme pickers live in the header
// toolbar.

(function () {
  "use strict";

  const t = (k, p) => window.cpaI18n.t(k, p);
  // Management routes live at /v0/management/ (flat). We namespace our
  // routes ourselves by embedding the plugin id in the path (see
  // handleManagementRegister on the Go side). Resources on the other
  // hand are auto-namespaced under /v0/resource/plugins/<pluginID>/.
  const BASE = "/v0/management/cpa-login-hub";
  const CPA_BASE = "/v0/management";
  const RESOURCE_BASE = "/v0/resource/plugins/cpa-login-hub";

  const el = {
    provider: document.getElementById("provider"),
    description: document.getElementById("provider-description"),
    fields: document.getElementById("fields"),
    submit: document.getElementById("submit"),
    cancel: document.getElementById("cancel"),
    statusPanel: document.getElementById("status-panel"),
    statusLine: document.getElementById("status-line"),
    statusDetail: document.getElementById("status-detail"),
    version: document.getElementById("plugin-version"),
    themePicker: document.getElementById("theme-picker"),
    langPicker: document.getElementById("lang-picker"),
    keyRow: null,
    keyInput: null,
  };

  const state = new URLSearchParams(location.search).get("state") || "";
  let schema = null;
  let currentProvider = null;
  let pollTimer = null;

  // ---------- theme -------------------------------------------------------
  //
  // CPA has 4 theme choices (in order):
  //   auto  — follow OS (prefers-color-scheme: dark → dark, else → wool)
  //   white — pure white
  //   wool  — warm-cream "Wool Paper" (CPA's out-of-the-box look)
  //   dark  — dark
  //
  // CSS drives off html[data-theme]. For "auto" we resolve to wool/dark
  // at runtime and re-apply on media-query change.

  const THEME_STORAGE = "cpa-login-hub:theme";
  const VALID_THEMES = ["auto", "white", "wool", "dark"];
  const darkMedia = window.matchMedia("(prefers-color-scheme: dark)");
  let currentThemeChoice = "auto";

  function initTheme() {
    const fromUrl = new URLSearchParams(location.search).get("theme");
    const fromStore = localStorage.getItem(THEME_STORAGE);
    const initial = VALID_THEMES.includes(fromUrl)
      ? fromUrl
      : VALID_THEMES.includes(fromStore) ? fromStore : "auto";
    populateThemePicker();
    applyTheme(initial);
    el.themePicker.addEventListener("change", (e) => applyTheme(e.target.value));
    // Re-resolve when the OS toggles dark mode while "auto" is active.
    darkMedia.addEventListener("change", () => {
      if (currentThemeChoice === "auto") resolveAndApply("auto");
    });
  }

  function populateThemePicker() {
    el.themePicker.innerHTML = VALID_THEMES.map(
      (v) => `<option value="${v}">${t("theme." + v)}</option>`
    ).join("");
  }

  function applyTheme(name) {
    if (!VALID_THEMES.includes(name)) name = "auto";
    currentThemeChoice = name;
    localStorage.setItem(THEME_STORAGE, name);
    el.themePicker.value = name;
    resolveAndApply(name);
  }

  function resolveAndApply(name) {
    const effective =
      name === "auto" ? (darkMedia.matches ? "dark" : "wool") : name;
    document.documentElement.setAttribute("data-theme", effective);
  }

  // ---------- language ----------------------------------------------------

  function initLang() {
    populateLangPicker();
    el.langPicker.addEventListener("change", (e) => {
      window.cpaI18n.setLang(e.target.value);
    });
    window.addEventListener("cpa-login-hub:lang-changed", () => {
      applyStaticI18n();
      populateLangPicker();
      populateThemePicker();
      if (currentProvider) refreshProviderView();
      renderKeyInputPlaceholder();
    });
  }

  function populateLangPicker() {
    const current = window.cpaI18n.getLang();
    el.langPicker.innerHTML = window.cpaI18n.listLangs()
      .map((code) => {
        const label = code.startsWith("zh") ? t("lang.zh") : t("lang.en");
        return `<option value="${code}"${code === current ? " selected" : ""}>${label}</option>`;
      })
      .join("");
  }

  function applyStaticI18n() {
    // Walk elements with data-i18n and fill textContent.
    document.querySelectorAll("[data-i18n]").forEach((node) => {
      const key = node.getAttribute("data-i18n");
      node.textContent = t(key);
    });
    document.title = "CPA Login Hub";
  }

  // ---------- management key ----------------------------------------------

  const KEY_STORAGE = "cpa-login-hub:mgmt-key";

  function getManagementKey() {
    return sessionStorage.getItem(KEY_STORAGE) || "";
  }
  function setManagementKey(v) {
    if (v) sessionStorage.setItem(KEY_STORAGE, v);
    else sessionStorage.removeItem(KEY_STORAGE);
  }

  function ensureAuthUI() {
    if (el.keyRow) return;
    const row = document.createElement("div");
    row.className = "row";
    row.style.marginBottom = "16px";
    const labelEl = document.createElement("label");
    labelEl.htmlFor = "mgmt-key";
    labelEl.textContent = t("field.mgmt_key");
    labelEl.setAttribute("data-i18n-refresh", "field.mgmt_key");
    const input = document.createElement("input");
    input.id = "mgmt-key";
    input.type = "password";
    input.placeholder = t("field.mgmt_key.placeholder");
    input.setAttribute("data-i18n-refresh-placeholder", "field.mgmt_key.placeholder");
    input.value = getManagementKey();
    input.addEventListener("change", () => setManagementKey(input.value.trim()));
    input.addEventListener("blur", () => setManagementKey(input.value.trim()));
    row.appendChild(labelEl);
    row.appendChild(input);
    const body = document.querySelector(".panel-body");
    body.insertBefore(row, body.firstChild);
    el.keyRow = row;
    el.keyInput = input;
  }

  function renderKeyInputPlaceholder() {
    if (!el.keyRow) return;
    el.keyRow.querySelector("label").textContent = t("field.mgmt_key");
    el.keyRow.querySelector("input").placeholder = t("field.mgmt_key.placeholder");
  }

  // ---------- status render -----------------------------------------------

  function setStatus(kind, message, detail) {
    el.statusPanel.hidden = false;
    el.statusLine.className = "status-line " + kind;
    el.statusLine.textContent = message;
    if (detail !== undefined) {
      el.statusDetail.textContent =
        typeof detail === "string" ? detail : JSON.stringify(detail, null, 2);
    }
  }

  // ---------- provider form ----------------------------------------------

  function refreshProviderView() {
    const p = schema.providers.find((x) => x.key === currentProvider);
    if (!p) return;
    const badge = p.can_refresh
      ? `<span class="badge-refresh">${t("badge.can_refresh")}</span>`
      : `<span class="badge-refresh absent">${t("badge.no_refresh")}</span>`;
    el.description.innerHTML = p.description + " " + badge;
    renderFields(p);
  }

  function renderFields(p) {
    el.fields.innerHTML = "";
    el.fields.appendChild(renderFieldGroup(t("group.common"), p.fields || []));
    el.fields.appendChild(renderFieldGroup(t("group.provider_specific"), p.extras || []));
  }

  function renderFieldGroup(title, fields) {
    const group = document.createElement("div");
    group.className = "field-group";
    const heading = document.createElement("div");
    heading.className = "field-group-title";
    heading.textContent = title;
    group.appendChild(heading);
    for (const f of fields) group.appendChild(renderFieldRow(f));
    return group;
  }

  function renderFieldRow(field) {
    const row = document.createElement("div");
    row.className = "field-row";
    const labelEl = document.createElement("label");
    labelEl.htmlFor = "field-" + field.key;
    labelEl.textContent = field.title || field.key;
    if (field.required) {
      const mark = document.createElement("span");
      mark.className = "required-mark";
      mark.textContent = t("required.marker");
      labelEl.appendChild(mark);
    }
    row.appendChild(labelEl);
    const input = document.createElement("input");
    input.type = field.type === "password" ? "password" : "text";
    input.id = "field-" + field.key;
    input.dataset.fieldKey = field.key;
    input.autocomplete = "off";
    input.spellcheck = false;
    if (field.placeholder) input.placeholder = field.placeholder;
    row.appendChild(input);
    return row;
  }

  function collectFormValues() {
    const values = { label: "", proxy: "", extras: {} };
    for (const input of el.fields.querySelectorAll("input")) {
      const k = input.dataset.fieldKey;
      const v = input.value.trim();
      if (k === "label") values.label = v;
      else if (k === "proxy") values.proxy = v;
      else if (v !== "") values.extras[k] = v;
    }
    return values;
  }

  function validateForm(binding) {
    const values = collectFormValues();
    for (const f of binding.extras || []) {
      if (f.required && !values.extras[f.key]) {
        return { ok: false, message: t("status.warn.field_required", { field: f.title || f.key }) };
      }
    }
    return { ok: true, values };
  }

  // ---------- API ---------------------------------------------------------

  function authHeaders() {
    const key = getManagementKey();
    return key ? { Authorization: "Bearer " + key } : {};
  }
  async function apiGetPublic(path) {
    const res = await fetch(path, { credentials: "same-origin" });
    if (!res.ok) throw new Error(`GET ${path}: HTTP ${res.status}`);
    return res.json();
  }
  async function apiGet(path) {
    const res = await fetch(path, { credentials: "same-origin", headers: authHeaders() });
    if (res.status === 401) throw new Error(t("status.error.auth_required"));
    if (!res.ok) throw new Error(`GET ${path}: HTTP ${res.status}`);
    return res.json();
  }
  async function apiPost(path, body) {
    const res = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json", ...authHeaders() },
      body: JSON.stringify(body),
    });
    if (res.status === 401) throw new Error(t("status.error.auth_required"));
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `POST ${path}: HTTP ${res.status}`);
    return data;
  }

  // ---------- login flow --------------------------------------------------

  async function submitLogin() {
    if (!state) {
      setStatus("error", t("status.warn.no_state"));
      return;
    }
    const binding = schema.providers.find((p) => p.key === currentProvider);
    if (!binding) return;
    const check = validateForm(binding);
    if (!check.ok) {
      setStatus("warn", check.message);
      return;
    }
    disableSubmit(true);
    setStatus("info", t("status.preparing"), "");
    try {
      const resp = await apiPost(
        BASE + "/submit-login?state=" + encodeURIComponent(state),
        {
          provider: currentProvider,
          label: check.values.label,
          proxy: check.values.proxy,
          timeout: 600,
          extras: check.values.extras,
        }
      );
      setStatus("info", t("status.submitted", { state: state.slice(0, 8) + "…" }), resp);
      startPolling();
    } catch (err) {
      setStatus("error", t("status.error.submit", { msg: err.message }));
      disableSubmit(false);
    }
  }

  function startPolling() {
    if (pollTimer) clearInterval(pollTimer);
    let elapsed = 0;
    pollTimer = setInterval(async () => {
      elapsed += 2;
      try {
        const [cpaStatus, pluginStatus] = await Promise.all([
          apiGet(`${schema.status_path}?state=${encodeURIComponent(state)}`),
          apiGet(`${BASE}/status?state=${encodeURIComponent(state)}`),
        ]);
        if (cpaStatus.status === "ok") {
          clearInterval(pollTimer);
          setStatus("success", t("status.success", { elapsed }), { cpa: cpaStatus, plugin: pluginStatus });
          disableSubmit(false);
          return;
        }
        if (cpaStatus.status === "error") {
          clearInterval(pollTimer);
          setStatus("error", t("status.error.login", { msg: cpaStatus.error || "unknown" }), { cpa: cpaStatus, plugin: pluginStatus });
          disableSubmit(false);
          return;
        }
        setStatus("info", t("status.running", { elapsed, stage: pluginStatus.status || "unknown" }), pluginStatus);
      } catch (err) {
        console.warn("poll error:", err);
      }
    }, 2000);
  }

  function disableSubmit(disabled) {
    el.submit.disabled = disabled;
  }

  async function cancelFlow() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    try {
      await apiPost(BASE + "/cancel", {});
      setStatus("warn", t("status.warn.cancelled"));
    } catch (err) {
      setStatus("warn", t("status.warn.cancel_failed", { msg: err.message }));
    }
    disableSubmit(false);
  }

  // ---------- init --------------------------------------------------------

  // ---------- home view (no state) --------------------------------------
  //
  // When the panel is opened directly from the sidebar (no ?state=), we
  // don't have an active OAuth flow to feed. Show a summary instead:
  //   - Registered providers + refresh capability
  //   - The auth-files this plugin has produced (queried from CPA's own
  //     /v0/management/auth-files, filtered to provider=cpa-login-hub)
  //   - A primary CTA that kicks off a new OAuth login by hitting the
  //     CPA-native auth-url — which then window.opens the login form
  //     back into this same page (with state this time).

  async function renderHomeView() {
    // Hide the login form; render a home view in its place.
    document.querySelector(".panel-body").innerHTML = "";
    document.getElementById("status-panel").hidden = true;

    const body = document.querySelector(".panel-body");
    body.innerHTML = `
      <div class="home-hero">
        <h2 data-i18n="home.title">${t("home.title")}</h2>
        <p data-i18n="home.blurb">${t("home.blurb")}</p>
        <div class="home-actions">
          <button id="home-start" type="button">${t("home.start")}</button>
        </div>
      </div>
      <div class="row" style="margin-top: 8px;">
        <label for="mgmt-key">${t("field.mgmt_key")}</label>
        <input id="mgmt-key" type="password" placeholder="${t("field.mgmt_key.placeholder")}" />
      </div>
      <div class="home-section">
        <h3>${t("home.providers")}</h3>
        <ul id="home-providers" class="home-list"></ul>
      </div>
      <div class="home-section">
        <h3>${t("home.recent")} <button id="home-refresh" class="secondary" type="button" style="padding:4px 10px; font-size:12px; margin-left:8px;">${t("home.refresh")}</button></h3>
        <div id="home-auth-files" class="home-list">${t("home.loading")}</div>
      </div>
    `;

    // Wire management-key input.
    const keyInput = document.getElementById("mgmt-key");
    keyInput.value = getManagementKey();
    keyInput.addEventListener("change", () => setManagementKey(keyInput.value.trim()));
    keyInput.addEventListener("blur", () => setManagementKey(keyInput.value.trim()));
    el.keyInput = keyInput;
    el.keyRow = keyInput.closest(".row");

    // Provider list.
    const ul = document.getElementById("home-providers");
    ul.innerHTML = schema.providers.map((p) => `
      <li>
        <span class="provider-key">${p.key}</span>
        <span class="provider-label">${p.label}</span>
        <span class="provider-badge ${p.can_refresh ? "" : "absent"}">${t(p.can_refresh ? "badge.can_refresh" : "badge.no_refresh")}</span>
      </li>
    `).join("");

    // Auth files.
    document.getElementById("home-refresh").addEventListener("click", loadAuthFiles);
    document.getElementById("home-start").addEventListener("click", startOAuthFlow);
    await loadAuthFiles();
  }

  async function loadAuthFiles() {
    const container = document.getElementById("home-auth-files");
    container.textContent = t("home.loading");
    try {
      // Use CPA's own /v0/management/auth-files (CPA_BASE, not BASE):
      // it returns every auth file the host knows about; we filter to
      // the ones our plugin produced.
      const data = await apiGet(CPA_BASE + "/auth-files");
      const files = (data.files || []).filter((f) => (f.provider || "").toLowerCase() === "cpa-login-hub");
      if (files.length === 0) {
        container.innerHTML = `<div class="empty">${t("home.no_records")}</div>`;
        return;
      }
      container.innerHTML = `
        <table class="auth-files-table">
          <thead><tr>
            <th>${t("home.file.provider")}</th>
            <th>${t("home.file.label")}</th>
            <th>${t("home.file.name")}</th>
            <th>${t("home.file.status")}</th>
          </tr></thead>
          <tbody>
            ${files.map((f) => `
              <tr>
                <td><span class="provider-key">${f.metadata?.provider_key || "?"}</span></td>
                <td>${escapeHtml(f.label || f.name || "-")}</td>
                <td class="mono">${escapeHtml(f.name || "-")}</td>
                <td>${f.disabled ? `<span class="status-badge dis">${t("home.file.disabled")}</span>` : `<span class="status-badge ok">${t("home.file.active")}</span>`}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      `;
    } catch (err) {
      container.innerHTML = `<div class="empty">${escapeHtml(err.message)}</div>`;
    }
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  async function startOAuthFlow() {
    // CPA-native endpoint /v0/management/<plugin>-auth-url triggers
    // StartLogin and returns {status:ok, state, url:<panel-url>?state=…}.
    // Navigate the current window there so we land on the login-form
    // view with the state token pre-attached.
    try {
      const resp = await apiGet(CPA_BASE + "/cpa-login-hub-auth-url");
      if (resp.status !== "ok" || !resp.url) {
        throw new Error(JSON.stringify(resp));
      }
      window.location.assign(resp.url);
    } catch (err) {
      alert(t("status.error.submit", { msg: err.message }));
    }
  }

  // ---------- login form view (with state) ------------------------------

  async function renderLoginView() {
    ensureAuthUI();
    el.provider.innerHTML = "";
    for (const p of schema.providers) {
      const opt = document.createElement("option");
      opt.value = p.key;
      opt.textContent = p.label + (p.can_refresh ? " ✓" : "");
      el.provider.appendChild(opt);
    }
    el.provider.addEventListener("change", () => {
      currentProvider = el.provider.value;
      refreshProviderView();
    });
    if (schema.providers.length > 0) {
      currentProvider = schema.providers[0].key;
      el.provider.value = currentProvider;
      refreshProviderView();
    }
    el.submit.addEventListener("click", submitLogin);
    el.cancel.addEventListener("click", cancelFlow);
  }

  // ---------- init --------------------------------------------------------

  async function init() {
    initLang();
    applyStaticI18n();
    initTheme();
    try {
      schema = await apiGetPublic(RESOURCE_BASE + "/schema");
    } catch (err) {
      setStatus("error", t("status.error.schema", { msg: err.message }));
      return;
    }
    el.version.textContent = `${schema.plugin} ${schema.version}`;

    if (state) {
      // Login form view (came from OAuth-Login click).
      await renderLoginView();
    } else {
      // Home view (came from sidebar menu).
      await renderHomeView();
    }
  }

  init();
})();
