// CPA Login Hub — i18n table.
//
// Minimal in-file translations keyed by dot-path. panel.js pulls
// strings via t(key). Two languages: zh-CN (default, matches CPA
// fallback) and en-US. Language pick precedence:
//   1. ?lang= URL param
//   2. localStorage["cpa-login-hub:lang"]
//   3. navigator.language starts with "zh" → zh-CN, else en-US
//
// Provider label + description strings come from /schema (Go side)
// and stay in their source language — this file only translates the
// panel's own chrome.
(function () {
  "use strict";

  const RES = {
    "zh-CN": {
      "header.subtitle": "选择一个 provider，填账号密码，剩下的交给 Camoufox 自动完成。生成的 auth-file 会自动落到 CPA 的 auth 目录。",
      "field.provider": "Provider",
      "field.mgmt_key": "管理密钥",
      "field.mgmt_key.placeholder": "粘贴 CPA 管理面板登录密码（同 management.html 用的那一个）",
      "group.common": "通用",
      "group.provider_specific": "Provider 特定字段",
      "action.submit": "开始登录",
      "action.cancel": "取消 / 重置",
      "status.title": "进度",
      "status.idle": "idle",
      "status.preparing": "准备中...",
      "status.submitted": "已提交，Camoufox 已启动，state={state}（首次运行需 ~90s 装 venv）",
      "status.running": "⏳ 运行中... {elapsed}s ({stage})",
      "status.success": "✅ 登录完成 ({elapsed}s)。auth-file 已由 CPA 保存。",
      "status.error.login": "登录失败：{msg}",
      "status.error.submit": "提交失败：{msg}",
      "status.error.schema": "加载 schema 失败：{msg}",
      "status.error.auth_required": "需要管理密钥 — 请在页面顶部粘贴 CPA 管理密码后重试",
      "status.warn.no_state": "URL 里没有 ?state 参数 — 请从 CPA 面板的 OAuth Login → CPA Login Hub 按钮进入本页面，不要直接访问菜单",
      "status.warn.field_required": "字段 \"{field}\" 是必填的",
      "status.warn.no_state_hint": "本页面需要通过 CPA 的 OAuth Login → CPA Login Hub 按钮打开（URL 里需要带 ?state=…）。直接访问菜单会看不到登录入口。",
      "status.warn.cancelled": "已取消并清理工作进程",
      "status.warn.cancel_failed": "取消请求失败：{msg}",
      "badge.can_refresh": "支持 refresh",
      "badge.no_refresh": "无 refresh — 过期需重登",
      "footer.suffix": "首次运行会自动配置 Python venv (~90s)",
      "theme.label": "主题",
      "theme.auto": "跟随系统",
      "theme.white": "白色",
      "theme.wool": "羊毛纸",
      "theme.dark": "深色",
      "lang.label": "语言",
      "lang.zh": "中文",
      "lang.en": "English",
      "required.marker": "*",
      "home.title": "CPA Login Hub",
      "home.blurb": "为 kiro / openai / grok / antigravity / cursor 批量导入账号。点下方按钮开始一次新登录（会跳转到 OAuth 登录表单）；下方列表展示本插件已经生成的 auth-file。",
      "home.start": "发起新登录 → OAuth",
      "home.providers": "支持的 Provider",
      "home.recent": "已导入的账号",
      "home.refresh": "刷新",
      "home.loading": "加载中...",
      "home.no_records": "还没有通过本插件导入的账号",
      "home.file.provider": "Provider",
      "home.file.label": "Label",
      "home.file.name": "文件名",
      "home.file.status": "状态",
      "home.file.disabled": "已禁用",
      "home.file.active": "启用",
    },
    "en-US": {
      "header.subtitle": "Pick a provider, fill in credentials, and Camoufox will drive the browser for you. The resulting auth-file lands in CPA's auth directory automatically.",
      "field.provider": "Provider",
      "field.mgmt_key": "Management key",
      "field.mgmt_key.placeholder": "Paste the CPA management password (same one you use on management.html)",
      "group.common": "General",
      "group.provider_specific": "Provider-specific fields",
      "action.submit": "Start login",
      "action.cancel": "Cancel / reset",
      "status.title": "Progress",
      "status.idle": "idle",
      "status.preparing": "Preparing...",
      "status.submitted": "Submitted; Camoufox is running (state={state}). First run may take ~90s to bootstrap the venv.",
      "status.running": "⏳ Running... {elapsed}s ({stage})",
      "status.success": "✅ Login completed ({elapsed}s). Auth-file saved by CPA.",
      "status.error.login": "Login failed: {msg}",
      "status.error.submit": "Submit failed: {msg}",
      "status.error.schema": "Failed to load schema: {msg}",
      "status.error.auth_required": "Management key required — paste your CPA management password at the top of the page and retry.",
      "status.warn.no_state": "No ?state in URL — open this page via CPA's OAuth Login → CPA Login Hub button, not directly from the menu.",
      "status.warn.field_required": "Field \"{field}\" is required",
      "status.warn.no_state_hint": "This page must be opened via CPA's OAuth Login → CPA Login Hub button (URL needs a ?state=… param). Opening the menu directly won't work.",
      "status.warn.cancelled": "Cancelled; running workers cleaned up",
      "status.warn.cancel_failed": "Cancel request failed: {msg}",
      "badge.can_refresh": "supports refresh",
      "badge.no_refresh": "no refresh — re-login on expiry",
      "footer.suffix": "First run auto-provisions the Python venv (~90s)",
      "theme.label": "Theme",
      "theme.auto": "System",
      "theme.white": "White",
      "theme.wool": "Wool Paper",
      "theme.dark": "Dark",
      "lang.label": "Language",
      "lang.zh": "中文",
      "lang.en": "English",
      "required.marker": "*",
      "home.title": "CPA Login Hub",
      "home.blurb": "Bulk-import accounts for kiro / openai / grok / antigravity / cursor. Click below to start a new login (opens the OAuth login form); the list below shows auth-files this plugin has already produced.",
      "home.start": "Start new login → OAuth",
      "home.providers": "Supported providers",
      "home.recent": "Imported accounts",
      "home.refresh": "Refresh",
      "home.loading": "Loading…",
      "home.no_records": "No accounts have been imported through this plugin yet.",
      "home.file.provider": "Provider",
      "home.file.label": "Label",
      "home.file.name": "Filename",
      "home.file.status": "Status",
      "home.file.disabled": "Disabled",
      "home.file.active": "Active",
    },
  };

  const VALID = Object.keys(RES);
  const STORE = "cpa-login-hub:lang";

  function detectLang() {
    const fromUrl = new URLSearchParams(location.search).get("lang");
    if (VALID.includes(fromUrl)) return fromUrl;
    const stored = localStorage.getItem(STORE);
    if (VALID.includes(stored)) return stored;
    const nav = (navigator.language || "").toLowerCase();
    return nav.startsWith("zh") ? "zh-CN" : "en-US";
  }

  let current = detectLang();

  function t(key, params) {
    const table = RES[current] || RES["zh-CN"];
    let s = table[key];
    if (s === undefined) s = RES["zh-CN"][key] || key;
    if (params) {
      for (const [k, v] of Object.entries(params)) {
        s = s.split("{" + k + "}").join(String(v));
      }
    }
    return s;
  }

  function setLang(lang) {
    if (!VALID.includes(lang)) return;
    current = lang;
    localStorage.setItem(STORE, lang);
    document.documentElement.lang = lang;
    // Re-render dispatch — panel.js listens for this custom event.
    window.dispatchEvent(new CustomEvent("cpa-login-hub:lang-changed"));
  }

  function getLang() {
    return current;
  }

  function listLangs() {
    return VALID.slice();
  }

  window.cpaI18n = { t, setLang, getLang, listLangs };
})();
