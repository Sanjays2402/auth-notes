// Auth Notes — popup entry point

const THEME_MEDIA = window.matchMedia("(prefers-color-scheme: light)");
let themePref = "auto"; // "auto" | "dark" | "light"

function resolveTheme(pref) {
  if (pref === "light" || pref === "dark") return pref;
  return THEME_MEDIA.matches ? "light" : "dark";
}

function applyTheme() {
  document.body.dataset.theme = resolveTheme(themePref);
}

function setThemePref(pref) {
  themePref = pref === "light" || pref === "dark" ? pref : "auto";
  applyTheme();
  syncThemeControls();
}

function syncThemeControls() {
  const buttons = document.querySelectorAll(".segmented .seg");
  if (!buttons.length) return;
  buttons.forEach((b) => {
    const active = b.dataset.theme === themePref;
    b.classList.toggle("is-active", active);
    b.setAttribute("aria-checked", active ? "true" : "false");
  });
  const summary = document.getElementById("theme-summary");
  if (summary) {
    if (themePref === "auto") summary.textContent = `Following system (${resolveTheme("auto")}).`;
    else if (themePref === "light") summary.textContent = "Pinned to the light theme.";
    else summary.textContent = "Pinned to the dark theme.";
  }
}

function show(id) {
  for (const v of document.querySelectorAll(".view")) v.hidden = v.id !== id;
  const lockBtn = document.getElementById("lock-btn");
  if (lockBtn) lockBtn.hidden = id !== "view-vault" && id !== "view-settings" && id !== "view-search" && id !== "view-quick-add" && id !== "view-audit" && id !== "view-duplicates";
  const searchBtn = document.getElementById("search-btn");
  if (searchBtn) searchBtn.hidden = id !== "view-vault";
  const addBtn = document.getElementById("add-btn");
  if (addBtn) addBtn.hidden = id !== "view-vault";
  const settingsBtn = document.getElementById("settings-btn");
  if (settingsBtn) settingsBtn.hidden = id === "view-settings" || id === "view-setup" || id === "view-lock" || id === "view-search" || id === "view-quick-add" || id === "view-audit" || id === "view-duplicates";
}

async function send(type, payload = {}) {
  const res = await chrome.runtime.sendMessage({ type, ...payload });
  if (!res?.ok) throw new Error(res?.error || "unknown error");
  return res.data;
}

/** Lightweight password strength heuristic — returns { score 0-4, label, pct }. */
function scorePassword(pw) {
  if (!pw) return { score: 0, label: "—", pct: 0 };
  let s = 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 12) s++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
  if (/\d/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  const score = Math.min(4, s);
  const labels = ["Too short", "Weak", "Okay", "Good", "Strong"];
  return { score, label: labels[score], pct: (score / 4) * 100 };
}

function bindStrength() {
  const pw = document.getElementById("setup-pw");
  const fill = document.getElementById("strength-fill");
  const label = document.getElementById("strength-label");
  if (!pw || !fill || !label) return;
  pw.addEventListener("input", () => {
    const { score, label: text, pct } = scorePassword(pw.value);
    fill.style.width = `${pct}%`;
    fill.dataset.score = String(score);
    label.textContent = text;
  });
}

function bindReveal() {
  for (const btn of document.querySelectorAll(".input-toggle")) {
    btn.addEventListener("click", () => {
      const id = btn.dataset.target;
      const input = id && document.getElementById(id);
      if (!input) return;
      input.type = input.type === "password" ? "text" : "password";
      btn.setAttribute(
        "aria-label",
        input.type === "password" ? "Show password" : "Hide password"
      );
    });
  }
}

function showError(msg) {
  const el = document.getElementById("setup-error");
  if (!el) return;
  if (!msg) { el.hidden = true; el.textContent = ""; return; }
  el.textContent = msg;
  el.hidden = false;
}

function bindSetupForm() {
  const form = document.getElementById("setup-form");
  const submit = document.getElementById("setup-submit");
  if (!form || !submit) return;
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    showError("");
    const pw = document.getElementById("setup-pw").value;
    const pw2 = document.getElementById("setup-pw2").value;
    if (pw.length < 8) return showError("Password must be at least 8 characters.");
    if (pw !== pw2) return showError("Passwords do not match.");
    submit.disabled = true;
    submit.classList.add("is-busy");
    try {
      await send("master:setup", { password: pw });
      // Clear inputs ASAP — we don't want plaintext lingering in the DOM.
      document.getElementById("setup-pw").value = "";
      document.getElementById("setup-pw2").value = "";
      show("view-vault");
      await refreshCurrentSite();
      maybeStartOnboardingTour({ force: true });
    } catch (err) {
      showError(String(err.message || err));
      submit.disabled = false;
      submit.classList.remove("is-busy");
    }
  });
}

function bindUnlockForm() {
  const form = document.getElementById("unlock-form");
  const submit = document.getElementById("unlock-submit");
  if (!form || !submit) return;
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const errEl = document.getElementById("unlock-error");
    if (errEl) { errEl.hidden = true; errEl.textContent = ""; }
    const input = document.getElementById("unlock-pw");
    const pw = input?.value || "";
    if (!pw) {
      if (errEl) { errEl.textContent = "Enter your master password."; errEl.hidden = false; }
      return;
    }
    submit.disabled = true;
    submit.classList.add("is-busy");
    try {
      await send("master:verify", { password: pw });
      if (input) input.value = "";
      show("view-vault");
      await refreshCurrentSite();
      maybeStartOnboardingTour();
    } catch (err) {
      const msg = String(err.message || err);
      const friendly = /verifier|decrypt|bad/i.test(msg) ? "Wrong password. Try again." : msg;
      if (errEl) { errEl.textContent = friendly; errEl.hidden = false; }
      form.animate(
        [{ transform: "translateX(0)" }, { transform: "translateX(-4px)" }, { transform: "translateX(4px)" }, { transform: "translateX(0)" }],
        { duration: 220, easing: "cubic-bezier(0.16, 1, 0.3, 1)" }
      );
      if (input) { input.select?.(); input.focus(); }
    } finally {
      submit.disabled = false;
      submit.classList.remove("is-busy");
    }
  });
}

function idleSummaryText(min) {
  if (!min || min <= 0) return "Auto-lock is off. The vault stays unlocked until you lock it manually.";
  if (min === 1) return "Locks the vault after 1 minute of inactivity.";
  if (min < 60) return `Locks the vault after ${min} minutes of inactivity.`;
  const h = min / 60;
  return `Locks the vault after ${h === 1 ? "1 hour" : `${h} hours`} of inactivity.`;
}

async function openSettings() {
  show("view-settings");
  const select = document.getElementById("idle-select");
  const summary = document.getElementById("idle-summary");
  const saved = document.getElementById("settings-saved");
  if (saved) saved.hidden = true;
  try {
    const settings = await send("settings:get");
    const min = Number(settings?.idleTimeoutMin ?? 5);
    if (select) {
      const opts = Array.from(select.options).map((o) => Number(o.value));
      const match = opts.includes(min) ? min : 5;
      select.value = String(match);
    }
    if (summary) summary.textContent = idleSummaryText(min);
    if (settings?.theme) setThemePref(settings.theme);
    syncThemeControls();
  } catch (err) {
    console.warn("[auth-notes] settings:get failed", err);
  }
}

function bindSettings() {
  const back = document.getElementById("settings-back");
  back?.addEventListener("click", async () => {
    show("view-vault");
    await refreshCurrentSite();
  });

  bindExport();
  bindImport();
  bindAudit();
  bindDuplicates();
  bindThemePicker();
  bindShortcutCard();
  document.getElementById("tour-replay")?.addEventListener("click", () => {
    maybeStartOnboardingTour({ force: true });
  });

  const select = document.getElementById("idle-select");
  const summary = document.getElementById("idle-summary");
  const saved = document.getElementById("settings-saved");
  select?.addEventListener("change", async () => {
    const min = Number(select.value);
    if (summary) summary.textContent = idleSummaryText(min);
    try {
      await send("settings:set", { settings: { idleTimeoutMin: min } });
      if (saved) {
        saved.hidden = false;
        saved.animate(
          [{ opacity: 0, transform: "translateY(2px)" }, { opacity: 1, transform: "translateY(0)" }],
          { duration: 200, easing: "cubic-bezier(0.16, 1, 0.3, 1)" }
        );
        clearTimeout(bindSettings._t);
        bindSettings._t = setTimeout(() => { saved.hidden = true; }, 1400);
      }
    } catch (err) {
      console.warn("[auth-notes] settings:set failed", err);
    }
  });
}

function bindThemePicker() {
  const buttons = document.querySelectorAll(".segmented .seg");
  const saved = document.getElementById("theme-saved");
  buttons.forEach((b) => {
    b.addEventListener("click", async () => {
      const next = b.dataset.theme;
      if (!next || next === themePref) return;
      setThemePref(next);
      try {
        await send("settings:set", { settings: { theme: next } });
        if (saved) {
          saved.hidden = false;
          saved.animate(
            [{ opacity: 0, transform: "translateY(2px)" }, { opacity: 1, transform: "translateY(0)" }],
            { duration: 200, easing: "cubic-bezier(0.16, 1, 0.3, 1)" }
          );
          clearTimeout(bindThemePicker._t);
          bindThemePicker._t = setTimeout(() => { saved.hidden = true; }, 1400);
        }
      } catch (err) {
        console.warn("[auth-notes] theme persist failed", err);
      }
    });
  });
}

// --- Encrypted backup export ----------------------------------------

function triggerDownload(filename, content, mime) {
  const blob = new Blob([content], { type: mime || "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoke after the click has been queued; some browsers need a tick.
  setTimeout(() => URL.revokeObjectURL(url), 1200);
}

function setExportStatus(text, tone) {
  const el = document.getElementById("export-status");
  if (!el) return;
  if (!text) { el.hidden = true; el.textContent = ""; el.removeAttribute("data-tone"); return; }
  el.textContent = text;
  el.hidden = false;
  if (tone) el.dataset.tone = tone; else el.removeAttribute("data-tone");
}

function isMacPlatform() {
  try {
    const p = (navigator.userAgentData?.platform || navigator.platform || "").toLowerCase();
    return p.includes("mac");
  } catch { return false; }
}

function shortcutsUrlForBrowser() {
  try {
    const ua = (navigator.userAgent || "").toLowerCase();
    if (ua.includes("edg/")) return "edge://extensions/shortcuts";
    if (ua.includes("opr/") || ua.includes("opera")) return "opera://extensions/shortcuts";
    if (ua.includes("brave")) return "brave://extensions/shortcuts";
  } catch { /* ignore */ }
  return "chrome://extensions/shortcuts";
}

function bindShortcutCard() {
  const modEl = document.getElementById("shortcut-mod");
  if (modEl) modEl.textContent = isMacPlatform() ? "\u2318" : "Ctrl";
  const status = document.getElementById("shortcut-status");
  const setStatus = (msg, tone) => {
    if (!status) return;
    if (!msg) { status.hidden = true; status.textContent = ""; status.removeAttribute("data-tone"); return; }
    status.textContent = msg;
    status.hidden = false;
    if (tone) status.dataset.tone = tone; else status.removeAttribute("data-tone");
  };

  // Reflect the live binding from chrome.commands if available.
  (async () => {
    try {
      const cmds = await chrome.commands?.getAll?.();
      if (!Array.isArray(cmds)) return;
      const action = cmds.find((c) => c.name === "_execute_action");
      if (action && action.shortcut && modEl?.parentElement) {
        renderShortcutKeys(modEl.parentElement, action.shortcut);
      } else if (action && !action.shortcut) {
        setStatus("No shortcut assigned yet \u2014 click Customize to set one.", "err");
      }
    } catch { /* MV3 popup may not expose chrome.commands.getAll on all builds */ }
  })();

  const btn = document.getElementById("shortcut-open");
  btn?.addEventListener("click", async () => {
    const url = shortcutsUrlForBrowser();
    try {
      await chrome.tabs.create({ url });
      setStatus("Opened the browser shortcuts page in a new tab.", "ok");
      clearTimeout(bindShortcutCard._t);
      bindShortcutCard._t = setTimeout(() => setStatus(""), 2400);
    } catch (err) {
      console.warn("[auth-notes] open shortcuts page failed", err);
      setStatus(`Copy this URL into a new tab: ${url}`, "err");
    }
  });
}

function renderShortcutKeys(host, shortcut) {
  if (!host) return;
  const parts = String(shortcut)
    .split("+")
    .map((p) => p.trim())
    .filter(Boolean)
    .map((p) => {
      if (p === "Command" || p === "MacCtrl") return "\u2318";
      if (p === "Ctrl" || p === "Control") return isMacPlatform() ? "\u2303" : "Ctrl";
      if (p === "Alt") return isMacPlatform() ? "\u2325" : "Alt";
      if (p === "Shift") return "Shift";
      return p.toUpperCase();
    });
  host.innerHTML = "";
  parts.forEach((label, i) => {
    if (i > 0) {
      const sep = document.createElement("span");
      sep.className = "shortcut-sep";
      sep.setAttribute("aria-hidden", "true");
      sep.textContent = "+";
      host.appendChild(sep);
    }
    const k = document.createElement("kbd");
    if (i === 0) k.id = "shortcut-mod";
    k.textContent = label;
    host.appendChild(k);
  });
}

function bindExport() {
  const btn = document.getElementById("export-btn");
  if (!btn) return;
  btn.addEventListener("click", async () => {
    btn.animate(
      [{ transform: "scale(1)" }, { transform: "scale(0.96)" }, { transform: "scale(1)" }],
      { duration: 220, easing: "cubic-bezier(0.16, 1, 0.3, 1)" }
    );
    btn.disabled = true;
    btn.classList.add("is-busy");
    setExportStatus("Preparing backup\u2026");
    try {
      const data = await send("backup:export");
      triggerDownload(data.filename, data.content, data.mime);
      const n = Number(data.count) || 0;
      setExportStatus(`Saved \u2014 ${n} note${n === 1 ? "" : "s"} sealed.`, "ok");
      clearTimeout(bindExport._t);
      bindExport._t = setTimeout(() => setExportStatus(""), 3200);
    } catch (err) {
      console.warn("[auth-notes] export failed", err);
      setExportStatus(`Export failed: ${err?.message || err}`, "err");
    } finally {
      btn.disabled = false;
      btn.classList.remove("is-busy");
    }
  });
}

// --- Encrypted backup import ----------------------------------------

const IMPORT_MAX_BYTES = 8 * 1024 * 1024;
let pendingImportContent = null;

function setImportStatus(text, tone) {
  const el = document.getElementById("import-status");
  if (!el) return;
  if (!text) { el.hidden = true; el.textContent = ""; el.removeAttribute("data-tone"); return; }
  el.textContent = text;
  el.hidden = false;
  if (tone) el.dataset.tone = tone; else el.removeAttribute("data-tone");
}

function resetImportUI({ keepStatus = false } = {}) {
  pendingImportContent = null;
  const name = document.getElementById("import-file-name");
  const pwField = document.getElementById("import-pw-field");
  const actions = document.getElementById("import-actions");
  const pw = document.getElementById("import-pw");
  const file = document.getElementById("import-file");
  if (name) { name.hidden = true; name.textContent = ""; }
  if (pwField) pwField.hidden = true;
  if (actions) actions.hidden = true;
  if (pw) pw.value = "";
  if (file) file.value = "";
  if (!keepStatus) setImportStatus("");
}

function readFileAsText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error || new Error("read failed"));
    reader.onload = () => resolve(String(reader.result || ""));
    reader.readAsText(file);
  });
}

function bindImport() {
  const trigger = document.getElementById("import-btn");
  const file = document.getElementById("import-file");
  const nameEl = document.getElementById("import-file-name");
  const pwField = document.getElementById("import-pw-field");
  const actions = document.getElementById("import-actions");
  const runBtn = document.getElementById("import-run");
  const pwInput = document.getElementById("import-pw");
  if (!trigger || !file || !runBtn) return;

  trigger.addEventListener("click", () => {
    trigger.animate(
      [{ transform: "scale(1)" }, { transform: "scale(0.96)" }, { transform: "scale(1)" }],
      { duration: 220, easing: "cubic-bezier(0.16, 1, 0.3, 1)" }
    );
    file.click();
  });

  file.addEventListener("change", async () => {
    const f = file.files && file.files[0];
    if (!f) return;
    if (f.size > IMPORT_MAX_BYTES) {
      setImportStatus("Backup file is too large.", "err");
      resetImportUI({ keepStatus: true });
      return;
    }
    try {
      pendingImportContent = await readFileAsText(f);
      if (nameEl) { nameEl.hidden = false; nameEl.textContent = f.name; }
      if (pwField) pwField.hidden = false;
      if (actions) actions.hidden = false;
      setImportStatus("Enter the password used when this backup was created.");
      setTimeout(() => pwInput?.focus(), 30);
    } catch (err) {
      console.warn("[auth-notes] read import failed", err);
      setImportStatus(`Couldn't read file: ${err?.message || err}`, "err");
      resetImportUI({ keepStatus: true });
    }
  });

  pwInput?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); runBtn.click(); }
  });

  runBtn.addEventListener("click", async () => {
    if (!pendingImportContent) {
      setImportStatus("Choose a backup file first.", "err");
      return;
    }
    const pw = pwInput?.value || "";
    if (!pw) {
      setImportStatus("Enter the backup's master password.", "err");
      pwInput?.focus();
      return;
    }
    const mode = document.querySelector('input[name="import-mode"]:checked')?.value || "merge";
    runBtn.disabled = true;
    runBtn.classList.add("is-busy");
    setImportStatus("Restoring\u2026");
    try {
      const res = await send("backup:import", {
        content: pendingImportContent,
        password: pw,
        mode,
      });
      const parts = [];
      if (res.added) parts.push(`${res.added} added`);
      if (res.replaced) parts.push(`${res.replaced} updated`);
      if (res.discarded) parts.push(`${res.discarded} discarded`);
      if (res.failed) parts.push(`${res.failed} skipped`);
      const summary = parts.length ? parts.join(" \u2022 ") : "nothing to do";
      setImportStatus(`Restored \u2014 ${summary}.`, "ok");
      resetImportUI({ keepStatus: true });
      await refreshCurrentSite();
    } catch (err) {
      console.warn("[auth-notes] import failed", err);
      const msg = String(err?.message || err);
      const friendly = /wrong password/i.test(msg) ? "Wrong password for this backup." : msg;
      setImportStatus(friendly, "err");
      if (/wrong password/i.test(msg)) {
        if (pwInput) { pwInput.select?.(); pwInput.focus(); }
      }
    } finally {
      runBtn.disabled = false;
      runBtn.classList.remove("is-busy");
    }
  });
}

// --- Audit log -------------------------------------------------------

const AUDIT_ICONS = {
  "setup":         '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14"/><path d="M5 12h14"/></svg>',
  "unlock":        '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10" width="16" height="10" rx="2.5"/><path d="M8 10V7a4 4 0 0 1 7.5-2"/></svg>',
  "lock":          '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10" width="16" height="10" rx="2.5"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>',
  "auto-lock":     '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="8"/><path d="M12 8v5l3 2"/></svg>',
  "note:create":   '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M5 4h11l3 3v13a1 1 0 0 1-1 1H5z"/><path d="M12 11v6M9 14h6"/></svg>',
  "note:update":   '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 4l6 6-11 11H3v-6z"/><path d="M13 5l6 6"/></svg>',
  "note:delete":   '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16"/><path d="M10 11v6M14 11v6"/><path d="M6 7l1 13a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-13"/></svg>',
  "note:view":     '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>',
  "backup:export": '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4v12"/><path d="M7 11l5 5 5-5"/><path d="M5 20h14"/></svg>',
  "backup:import": '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20V8"/><path d="M7 13l5-5 5 5"/><path d="M5 4h14"/></svg>',
  "audit:clear":   '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16"/><path d="M9 7V5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2"/></svg>',
};

const AUDIT_TITLES = {
  "setup": "Vault created",
  "unlock": "Vault unlocked",
  "lock": "Vault locked",
  "auto-lock": "Auto-locked",
  "note:create": "Note added",
  "note:update": "Note edited",
  "note:delete": "Note deleted",
  "note:view": "Note viewed",
  "backup:export": "Backup exported",
  "backup:import": "Backup restored",
  "audit:clear": "Audit log cleared",
};

function auditIcon(type) {
  return AUDIT_ICONS[type] || '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/></svg>';
}
function auditTitle(type) {
  return AUDIT_TITLES[type] || String(type || "event");
}
function formatAuditTime(ts) {
  if (!Number.isFinite(ts)) return "";
  const d = new Date(ts);
  const now = new Date();
  const sameDay = d.toDateString() === now.toDateString();
  const time = d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  if (sameDay) return time;
  const ms = now.getTime() - d.getTime();
  if (ms < 7 * 24 * 60 * 60 * 1000 && ms > 0) {
    return `${d.toLocaleDateString([], { weekday: "short" })} ${time}`;
  }
  return `${d.toLocaleDateString([], { month: "short", day: "numeric" })} ${time}`;
}

async function renderAuditLog() {
  const list = document.getElementById("audit-list");
  const empty = document.getElementById("audit-empty");
  const summary = document.getElementById("audit-summary");
  if (!list || !empty || !summary) return;
  let payload;
  try { payload = await send("audit:list", { limit: 200 }); }
  catch (err) {
    console.warn("[auth-notes] audit:list failed", err);
    list.innerHTML = "";
    empty.hidden = false;
    summary.textContent = "";
    return;
  }
  const events = Array.isArray(payload?.events) ? payload.events : [];
  list.innerHTML = "";
  if (events.length === 0) {
    empty.hidden = false;
    summary.textContent = "";
    return;
  }
  empty.hidden = true;
  const total = Number.isFinite(payload?.total) ? payload.total : events.length;
  summary.textContent = `${total} event${total === 1 ? "" : "s"} sealed${total > events.length ? ` • showing ${events.length}` : ""}`;
  const frag = document.createDocumentFragment();
  for (const ev of events) {
    const li = document.createElement("li");
    li.className = "audit-item";
    const subParts = [];
    if (ev.origin) subParts.push(ev.origin);
    if (ev.detail) subParts.push(ev.detail);
    const sub = subParts.join(" • ");
    li.innerHTML = `
      <span class="audit-icon" data-kind="${escapeHtml(ev.type)}" aria-hidden="true">${auditIcon(ev.type)}</span>
      <span class="audit-body">
        <span class="audit-title">${escapeHtml(auditTitle(ev.type))}</span>
        ${sub ? `<span class="audit-sub">${escapeHtml(sub)}</span>` : ""}
      </span>
      <span class="audit-time">${escapeHtml(formatAuditTime(ev.ts))}</span>
    `;
    frag.appendChild(li);
  }
  list.appendChild(frag);
}

async function openAuditLog() {
  show("view-audit");
  await renderAuditLog();
}

function bindDuplicates() {
  const opener = document.getElementById("dupes-open");
  opener?.addEventListener("click", () => {
    opener.animate(
      [{ transform: "scale(1)" }, { transform: "scale(0.96)" }, { transform: "scale(1)" }],
      { duration: 220, easing: "cubic-bezier(0.16, 1, 0.3, 1)" }
    );
    openDuplicates();
  });
  const back = document.getElementById("dupes-back");
  back?.addEventListener("click", () => openSettings());
  const list = document.getElementById("dupes-list");
  list?.addEventListener("click", async (e) => {
    const btn = e.target instanceof Element ? e.target.closest("[data-edit-id]") : null;
    if (!btn) return;
    e.preventDefault();
    const id = btn.getAttribute("data-edit-id");
    if (!id) return;
    try {
      const note = await send("notes:get", { id });
      if (note) { await openQuickAdd({ note }); return; }
    } catch (err) { console.warn("[auth-notes] dupes edit failed", err); }
  });
}

async function openDuplicates() {
  show("view-duplicates");
  await renderDuplicates();
}

async function renderDuplicates() {
  const list = document.getElementById("dupes-list");
  const empty = document.getElementById("dupes-empty");
  const summary = document.getElementById("dupes-summary");
  const emptyTitle = document.getElementById("dupes-empty-title");
  const emptySub = document.getElementById("dupes-empty-sub");
  if (!list || !empty || !summary) return;
  list.innerHTML = "";
  summary.textContent = "Scanning\u2026";
  empty.hidden = true;
  let payload;
  try { payload = await send("notes:duplicates"); }
  catch (err) {
    summary.textContent = "";
    empty.hidden = false;
    if (emptyTitle) emptyTitle.textContent = "Couldn\u2019t scan";
    if (emptySub) emptySub.textContent = String(err?.message || err);
    return;
  }
  const groups = Array.isArray(payload?.groups) ? payload.groups : [];
  const totalNotes = Number(payload?.totalNotes) || 0;
  if (groups.length === 0) {
    summary.textContent = `${totalNotes} note${totalNotes === 1 ? "" : "s"} scanned \u2014 no reused emails`;
    empty.hidden = false;
    if (emptyTitle) emptyTitle.textContent = totalNotes === 0 ? "Nothing to scan" : "No reused emails";
    if (emptySub) emptySub.textContent = totalNotes === 0
      ? "Add a few notes with email/identifier set, then come back."
      : "Every recorded identity is unique across your sites. Nice.";
    return;
  }
  const exposed = groups.reduce((sum, g) => sum + g.count, 0);
  summary.textContent = `${groups.length} reused email${groups.length === 1 ? "" : "s"} across ${exposed} of ${totalNotes} note${totalNotes === 1 ? "" : "s"}`;
  const frag = document.createDocumentFragment();
  for (const g of groups) {
    const li = document.createElement("li");
    li.className = "dupes-group";
    const items = g.notes.map((n) => {
      const fav = faviconHtml(n.origin, 24, n.label || displayOrigin(n.origin));
      const auth = prettyAuth(n.authMethod);
      const used = Number(n.lastUsedAt);
      const ref = Number.isFinite(used) && used > 0 ? used : Number(n.updatedAt) || 0;
      const rel = ref ? formatRelative(ref) : "";
      return `
        <li class="dupes-site">
          ${fav}
          <span class="dupes-site-meta">
            <span class="dupes-site-label">${escapeHtml(n.label || displayOrigin(n.origin))}</span>
            <span class="dupes-site-sub">${escapeHtml(displayOrigin(n.origin))}${rel ? ` \u2022 ${escapeHtml(rel)}` : ""}</span>
          </span>
          ${auth ? `<span class="chip" data-auth="${escapeHtml(String(n.authMethod || "").toLowerCase())}">${escapeHtml(auth)}</span>` : ""}
          <button type="button" class="icon-btn dupes-edit" data-edit-id="${escapeHtml(n.id)}" title="Edit note" aria-label="Edit note">
            <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M14 4l6 6-11 11H3v-6z"/><path d="M13 5l6 6"/>
            </svg>
          </button>
        </li>
      `;
    }).join("");
    li.innerHTML = `
      <div class="dupes-head">
        <span class="dupes-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="5" width="18" height="14" rx="2.5"/>
            <path d="M3.5 7l8.5 6 8.5-6"/>
          </svg>
        </span>
        <span class="dupes-email" title="${escapeHtml(g.email)}">${escapeHtml(g.email)}</span>
        <span class="dupes-count">${g.count} sites</span>
      </div>
      <ul class="dupes-sites">${items}</ul>
    `;
    frag.appendChild(li);
  }
  list.appendChild(frag);
}

function bindAudit() {
  const opener = document.getElementById("audit-open");
  opener?.addEventListener("click", () => {
    opener.animate(
      [{ transform: "scale(1)" }, { transform: "scale(0.96)" }, { transform: "scale(1)" }],
      { duration: 220, easing: "cubic-bezier(0.16, 1, 0.3, 1)" }
    );
    openAuditLog();
  });
  const back = document.getElementById("audit-back");
  back?.addEventListener("click", () => openSettings());
  const clear = document.getElementById("audit-clear");
  clear?.addEventListener("click", async () => {
    if (!confirm("Clear the audit log? A single 'cleared' entry remains.")) return;
    clear.disabled = true;
    try {
      await send("audit:clear");
      await renderAuditLog();
    } catch (err) {
      console.warn("[auth-notes] audit:clear failed", err);
    } finally {
      clear.disabled = false;
    }
  });
}

// --- Search ----------------------------------------------------------

const SEARCH_DEBOUNCE_MS = 140;
const SEARCH_LIMIT = 50;
let searchTimer = null;
let searchSeq = 0;

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>\"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

function highlight(text, query) {
  const t = String(text ?? "");
  if (!t) return "";
  const tokens = String(query || "").trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return escapeHtml(t);
  const lower = t.toLowerCase();
  const ranges = [];
  for (const tok of tokens) {
    let from = 0;
    while (from < lower.length) {
      const idx = lower.indexOf(tok, from);
      if (idx === -1) break;
      ranges.push([idx, idx + tok.length]);
      from = idx + tok.length;
    }
  }
  if (ranges.length === 0) return escapeHtml(t);
  ranges.sort((a, b) => a[0] - b[0]);
  const merged = [ranges[0].slice()];
  for (let i = 1; i < ranges.length; i++) {
    const last = merged[merged.length - 1];
    const [a, b] = ranges[i];
    if (a <= last[1]) last[1] = Math.max(last[1], b);
    else merged.push([a, b]);
  }
  let out = "";
  let cursor = 0;
  for (const [a, b] of merged) {
    out += escapeHtml(t.slice(cursor, a));
    out += `<mark>${escapeHtml(t.slice(a, b))}</mark>`;
    cursor = b;
  }
  out += escapeHtml(t.slice(cursor));
  return out;
}

function renderSearchResults(payload, query) {
  const list = document.getElementById("search-results");
  const empty = document.getElementById("search-empty");
  const summary = document.getElementById("search-summary");
  const emptyTitle = document.getElementById("search-empty-title");
  const emptySub = document.getElementById("search-empty-sub");
  if (!list || !empty || !summary) return;

  const results = Array.isArray(payload?.results) ? payload.results : [];
  list.innerHTML = "";
  searchVisibleIds = results.map((r) => r?.note?.id).filter(Boolean);
  if (bulkSelected.size > 0) {
    const visible = new Set(searchVisibleIds);
    for (const id of [...bulkSelected]) if (!visible.has(id)) bulkSelected.delete(id);
    updateBulkBarUI();
  }

  if (results.length === 0) {
    empty.hidden = false;
    summary.textContent = "";
    if (query) {
      if (emptyTitle) emptyTitle.textContent = "No matches";
      if (emptySub) emptySub.textContent = `Nothing in your vault matches \u201c${query}\u201d.`;
    } else {
      if (emptyTitle) emptyTitle.textContent = "No notes yet";
      if (emptySub) emptySub.textContent = "Add notes from a site, then search across everything here.";
    }
    return;
  }
  empty.hidden = true;
  const shown = results.length;
  const total = Number.isFinite(payload?.total) ? payload.total : shown;
  summary.textContent = query
    ? `${total} match${total === 1 ? "" : "es"}${total > shown ? ` \u2022 showing ${shown}` : ""}`
    : `${total} note${total === 1 ? "" : "s"} in vault`;

  const frag = document.createDocumentFragment();
  for (const { note, hits } of results) {
    const li = document.createElement("li");
    li.className = "search-item glass";
    li.setAttribute("role", "option");
    li.dataset.id = note.id || "";
    if (bulkSelected.has(note.id)) li.classList.add("is-selected");
    const label = note.label || displayOrigin(note.origin);
    const origin = displayOrigin(note.origin);
    const auth = prettyAuth(note.authMethod);
    const twofa = note.twofaBackup && note.twofaBackup !== "none"
      ? (note.twofaDetail
        ? `${prettyBackup(note.twofaBackup)} \u2014 ${note.twofaDetail}`
        : prettyBackup(note.twofaBackup))
      : "";
    const updated = formatRelative(note.updatedAt);
    const hitSet = new Set(Array.isArray(hits) ? hits : []);
    const showNotes = hitSet.has("notes") && note.notes;
    const tags = Array.isArray(note.tags) ? note.tags : [];

    li.innerHTML = `
      <div class="search-item-head">
        ${faviconHtml(note.origin)}
        <span class="search-item-label">${highlight(label, query)}</span>
        ${auth ? `<span class="chip" data-auth="${escapeHtml(String(note.authMethod || "").toLowerCase())}">${escapeHtml(auth)}</span>` : ""}
      </div>
      <div class="search-item-origin">${highlight(origin, query)}</div>
      ${note.email ? `<div class="search-item-line"><span class="search-item-key">Email</span><span>${highlight(note.email, query)}</span></div>` : ""}
      ${twofa ? `<div class="search-item-line"><span class="search-item-key">2FA</span><span>${highlight(twofa, query)}</span></div>` : ""}
      ${showNotes ? `<div class="search-item-line search-item-notes"><span class="search-item-key">Note</span><span>${highlight(note.notes, query)}</span></div>` : ""}
      ${tags.length ? `<div class="search-item-tags">${tags.map((t) => `<span class="tag-chip" data-tag="${escapeHtml(t)}">${escapeHtml(t)}</span>`).join("")}</div>` : ""}
      ${updated ? `<div class="search-item-foot">Updated ${escapeHtml(updated)}</div>` : ""}
    `;
    frag.appendChild(li);
  }
  list.appendChild(frag);
  applyBulkModeToList();
}

async function runSearch(query) {
  const seq = ++searchSeq;
  try {
    const payload = await send("notes:search", { query, limit: SEARCH_LIMIT });
    if (seq !== searchSeq) return; // stale
    renderSearchResults(payload, query);
  } catch (err) {
    if (seq !== searchSeq) return;
    console.warn("[auth-notes] search failed", err);
    renderSearchResults({ results: [], total: 0 }, query);
  }
}

function openSearch() {
  show("view-search");
  const input = document.getElementById("search-input");
  const clearBtn = document.getElementById("search-clear");
  if (input) {
    if (clearBtn) clearBtn.hidden = !input.value;
    setTimeout(() => input.focus(), 30);
  }
  refreshTagRail();
  runSearch(input?.value || "");
}

function parseTagTokens(query) {
  const out = new Set();
  for (const tok of String(query || "").split(/\s+/)) {
    if (tok.startsWith("tag:")) {
      const t = tok.slice(4).toLowerCase().trim();
      if (t) out.add(t);
    }
  }
  return out;
}

function toggleTagInQuery(query, tag) {
  const tokens = String(query || "").split(/\s+/).filter(Boolean);
  const wanted = `tag:${tag}`;
  const idx = tokens.findIndex((t) => t.toLowerCase() === wanted);
  if (idx >= 0) tokens.splice(idx, 1);
  else tokens.push(wanted);
  return tokens.join(" ");
}

async function refreshTagRail() {
  const rail = document.getElementById("search-tag-rail");
  const input = document.getElementById("search-input");
  if (!rail) return;
  let data;
  try { data = await send("notes:tags"); }
  catch (err) {
    console.warn("[auth-notes] notes:tags failed", err);
    rail.hidden = true;
    return;
  }
  const tags = Array.isArray(data?.tags) ? data.tags : [];
  if (tags.length === 0) {
    rail.hidden = true;
    rail.innerHTML = "";
    return;
  }
  const active = parseTagTokens(input?.value || "");
  rail.hidden = false;
  rail.innerHTML = tags.slice(0, 16).map(({ tag, count }) => {
    const on = active.has(tag);
    return `<button type="button" class="tag-chip tag-chip-btn${on ? " is-active" : ""}" data-tag="${escapeHtml(tag)}" aria-pressed="${on ? "true" : "false"}"><span>${escapeHtml(tag)}</span><span class="tag-chip-count">${count}</span></button>`;
  }).join("");
  for (const btn of rail.querySelectorAll(".tag-chip-btn")) {
    btn.addEventListener("click", () => {
      const tag = btn.dataset.tag;
      if (!tag || !input) return;
      const next = toggleTagInQuery(input.value, tag);
      input.value = next;
      const clearBtn = document.getElementById("search-clear");
      if (clearBtn) clearBtn.hidden = !input.value;
      refreshTagRail();
      runSearch(input.value);
    });
  }
}

// --- Bulk tag editor -------------------------------------------------

let bulkMode = false;
const bulkSelected = new Set();
let searchVisibleIds = [];

function setBulkStatus(text, tone) {
  const el = document.getElementById("bulk-status");
  if (!el) return;
  if (!text) { el.hidden = true; el.textContent = ""; el.removeAttribute("data-tone"); return; }
  el.textContent = text;
  el.hidden = false;
  if (tone) el.dataset.tone = tone; else el.removeAttribute("data-tone");
}

function parseTagsInput(value) {
  return String(value || "")
    .split(/[\s,]+/)
    .map((t) => t.trim().toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9._-]+/g, ""))
    .filter(Boolean);
}

function updateBulkBarUI() {
  const count = document.getElementById("bulk-count");
  const apply = document.getElementById("bulk-apply");
  const selAll = document.getElementById("bulk-select-all");
  const selAllLabel = document.getElementById("bulk-select-all-label");
  const addEl = document.getElementById("bulk-add");
  const remEl = document.getElementById("bulk-remove");
  const n = bulkSelected.size;
  if (count) count.textContent = `${n} selected`;
  const adds = addEl ? parseTagsInput(addEl.value) : [];
  const removes = remEl ? parseTagsInput(remEl.value) : [];
  if (apply) apply.disabled = n === 0 || (adds.length === 0 && removes.length === 0);
  if (selAllLabel) {
    const visible = searchVisibleIds.length;
    const allSelected = visible > 0 && bulkSelected.size === visible &&
      searchVisibleIds.every((id) => bulkSelected.has(id));
    selAllLabel.textContent = allSelected ? "Clear" : "Select all";
  }
  if (selAll) selAll.disabled = searchVisibleIds.length === 0;
}

function applyBulkModeToList() {
  const list = document.getElementById("search-results");
  if (!list) return;
  list.classList.toggle("is-bulk", bulkMode);
  for (const li of list.querySelectorAll(".search-item")) {
    const id = li.dataset.id;
    li.classList.toggle("is-selected", bulkMode && bulkSelected.has(id));
  }
}

function setBulkMode(on) {
  bulkMode = !!on;
  const bar = document.getElementById("bulk-bar");
  const toggle = document.getElementById("bulk-toggle");
  if (bar) bar.hidden = !bulkMode;
  if (toggle) toggle.setAttribute("aria-pressed", bulkMode ? "true" : "false");
  if (!bulkMode) bulkSelected.clear();
  setBulkStatus("");
  applyBulkModeToList();
  updateBulkBarUI();
}

function toggleBulkSelection(id) {
  if (!id) return;
  if (bulkSelected.has(id)) bulkSelected.delete(id);
  else bulkSelected.add(id);
  applyBulkModeToList();
  updateBulkBarUI();
}

function bindBulkEditor() {
  const toggle = document.getElementById("bulk-toggle");
  toggle?.addEventListener("click", () => {
    toggle.animate(
      [{ transform: "scale(1)" }, { transform: "scale(0.92)" }, { transform: "scale(1)" }],
      { duration: 200, easing: "cubic-bezier(0.16, 1, 0.3, 1)" }
    );
    setBulkMode(!bulkMode);
  });
  document.getElementById("bulk-cancel")?.addEventListener("click", () => setBulkMode(false));

  const list = document.getElementById("search-results");
  list?.addEventListener("click", (e) => {
    if (!bulkMode) return;
    const li = e.target.closest(".search-item");
    if (!li) return;
    e.preventDefault();
    toggleBulkSelection(li.dataset.id);
  });

  const selAll = document.getElementById("bulk-select-all");
  selAll?.addEventListener("click", () => {
    const allSelected = searchVisibleIds.length > 0 &&
      searchVisibleIds.every((id) => bulkSelected.has(id));
    if (allSelected) bulkSelected.clear();
    else for (const id of searchVisibleIds) bulkSelected.add(id);
    applyBulkModeToList();
    updateBulkBarUI();
  });

  const addEl = document.getElementById("bulk-add");
  const remEl = document.getElementById("bulk-remove");
  addEl?.addEventListener("input", updateBulkBarUI);
  remEl?.addEventListener("input", updateBulkBarUI);

  const apply = document.getElementById("bulk-apply");
  apply?.addEventListener("click", async () => {
    const ids = [...bulkSelected];
    const addTags = parseTagsInput(addEl?.value || "");
    const removeTags = parseTagsInput(remEl?.value || "");
    if (ids.length === 0) { setBulkStatus("Select notes first.", "err"); return; }
    if (addTags.length === 0 && removeTags.length === 0) {
      setBulkStatus("Add or remove at least one tag.", "err"); return;
    }
    apply.disabled = true;
    apply.classList.add("is-busy");
    setBulkStatus("Applying\u2026");
    try {
      const res = await send("notes:bulkTag", { ids, addTags, removeTags });
      const parts = [];
      if (res.added?.length) parts.push(`+${res.added.join(", ")}`);
      if (res.removed?.length) parts.push(`-${res.removed.join(", ")}`);
      setBulkStatus(`Updated ${res.changed}/${res.requested} \u2014 ${parts.join(" \u2022 ")}`, "ok");
      if (addEl) addEl.value = "";
      if (remEl) remEl.value = "";
      bulkSelected.clear();
      refreshTagRail();
      const input = document.getElementById("search-input");
      runSearch(input?.value || "");
      clearTimeout(bindBulkEditor._t);
      bindBulkEditor._t = setTimeout(() => setBulkStatus(""), 2600);
    } catch (err) {
      console.warn("[auth-notes] bulkTag failed", err);
      setBulkStatus(`Failed: ${err?.message || err}`, "err");
    } finally {
      apply.classList.remove("is-busy");
      updateBulkBarUI();
    }
  });
}

function bindSearch() {
  const btn = document.getElementById("search-btn");
  btn?.addEventListener("click", () => {
    btn.animate(
      [{ transform: "scale(1)" }, { transform: "scale(0.92)" }, { transform: "scale(1)" }],
      { duration: 220, easing: "cubic-bezier(0.16, 1, 0.3, 1)" }
    );
    openSearch();
  });
  const back = document.getElementById("search-back");
  back?.addEventListener("click", async () => {
    show("view-vault");
    await refreshCurrentSite();
  });
  const input = document.getElementById("search-input");
  const clearBtn = document.getElementById("search-clear");
  input?.addEventListener("input", () => {
    if (clearBtn) clearBtn.hidden = !input.value;
    clearTimeout(searchTimer);
    const q = input.value;
    refreshTagRail();
    searchTimer = setTimeout(() => runSearch(q), SEARCH_DEBOUNCE_MS);
  });
  input?.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (input.value) {
        input.value = "";
        if (clearBtn) clearBtn.hidden = true;
        runSearch("");
      } else {
        show("view-vault");
        refreshCurrentSite();
      }
    }
  });
  clearBtn?.addEventListener("click", () => {
    if (!input) return;
    input.value = "";
    clearBtn.hidden = true;
    input.focus();
    runSearch("");
  });
}

// --- Quick-add / edit ------------------------------------------------

let quickEditingId = null;
let quickPrefilledOrigin = "";

function setQuickError(msg) {
  const el = document.getElementById("quick-error");
  if (!el) return;
  if (!msg) { el.hidden = true; el.textContent = ""; return; }
  el.textContent = msg;
  el.hidden = false;
}

function updateQuick2faVisibility() {
  const sel = document.getElementById("quick-2fa");
  const field = document.getElementById("quick-2fa-detail-field");
  if (!sel || !field) return;
  field.hidden = !sel.value || sel.value === "none";
}

// --- Password-strength hint helpers --------------------------------
// We capture only a length bucket + a complexity tier. The actual password
// is never persisted; the optional probe field below derives the bucket
// in-memory and is wiped as soon as the user moves on.

const PW_BUCKETS = ["weak", "okay", "good", "strong"];
const PW_BUCKET_LABEL = { weak: "Weak", okay: "Okay", good: "Good", strong: "Strong" };

function deriveBucketFromPassword(pw) {
  if (!pw) return "";
  let s = 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 12) s++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
  if (/\d/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  const score = Math.min(4, s);
  if (score <= 1) return "weak";
  if (score === 2) return "okay";
  if (score === 3) return "good";
  return "strong";
}

function collectQuickPasswordHint() {
  const lenEl = document.getElementById("quick-pw-length");
  const complexityEl = document.getElementById("quick-pw-complexity");
  const lenRaw = lenEl ? lenEl.value.trim() : "";
  const lenNum = lenRaw === "" ? null : Number(lenRaw);
  const length = Number.isFinite(lenNum) && lenNum > 0 ? Math.min(256, Math.round(lenNum)) : null;
  const complexity = complexityEl ? String(complexityEl.value || "").toLowerCase() : "";
  const out = {};
  if (length != null) out.length = length;
  if (PW_BUCKETS.includes(complexity)) out.complexity = complexity;
  return Object.keys(out).length ? out : null;
}

function formatPasswordHint(hint) {
  if (!hint || typeof hint !== "object") return "";
  const parts = [];
  if (Number.isFinite(hint.length) && hint.length > 0) {
    parts.push(`${hint.length} chars`);
  }
  if (PW_BUCKETS.includes(hint.complexity)) {
    parts.push(PW_BUCKET_LABEL[hint.complexity]);
  }
  return parts.join(" \u00b7 ");
}

function bindQuickPasswordHint() {
  const probe = document.getElementById("quick-pw-probe");
  const complexitySel = document.getElementById("quick-pw-complexity");
  const lenEl = document.getElementById("quick-pw-length");
  const clearBtn = document.getElementById("quick-pw-probe-clear");
  if (probe && complexitySel && lenEl) {
    probe.addEventListener("input", () => {
      const v = probe.value;
      if (!v) return;
      lenEl.value = String(Math.min(256, v.length));
      const bucket = deriveBucketFromPassword(v);
      if (bucket) complexitySel.value = bucket;
    });
  }
  if (clearBtn && probe) {
    clearBtn.addEventListener("click", () => {
      probe.value = "";
      probe.focus();
    });
  }
}

async function openQuickAdd({ note = null, prefillOrigin = "" } = {}) {
  show("view-quick-add");
  setQuickError("");
  quickEditingId = note?.id || null;
  quickPrefilledOrigin = prefillOrigin || note?.origin || "";
  const title = document.getElementById("quick-title");
  if (title) title.textContent = note ? "Edit note" : "Add note";
  const submitLabel = document.querySelector("#quick-submit .btn-label");
  if (submitLabel) submitLabel.textContent = note ? "Save changes" : "Save note";
  const del = document.getElementById("quick-delete");
  if (del) del.hidden = !note;

  const setVal = (id, v) => { const el = document.getElementById(id); if (el) el.value = v || ""; };
  setVal("quick-origin", note?.origin || prefillOrigin || "");
  setVal("quick-label", note?.label && note.label !== note.origin ? note.label : "");
  setVal("quick-auth", note?.authMethod || "password");
  setVal("quick-email", note?.email || "");
  setVal("quick-2fa", note?.twofaBackup || "none");
  setVal("quick-2fa-detail", note?.twofaDetail || "");
  setVal("quick-tags", Array.isArray(note?.tags) ? note.tags.join(", ") : "");
  setVal("quick-notes", note?.notes || "");
  setVal("quick-codes", Array.isArray(note?.recoveryCodes) ? note.recoveryCodes.join("\n") : "");
  // Password-strength hint fields.
  const hint = note?.passwordHint || null;
  setVal("quick-pw-length", hint?.length ? String(hint.length) : "");
  setVal("quick-pw-complexity", hint?.complexity || "");
  setVal("quick-pw-probe", "");
  const probe = document.querySelector("#quick-pw-fieldset .pw-hint-probe");
  if (probe) probe.open = false;
  updateQuick2faVisibility();

  // Focus first field that needs the user — origin if empty, else email.
  setTimeout(() => {
    const target = (document.getElementById("quick-origin").value
      ? document.getElementById("quick-email")
      : document.getElementById("quick-origin"));
    target?.focus();
  }, 30);
}

async function startQuickAddFromCurrentTab() {
  let origin = "";
  try {
    const tab = await currentTab();
    if (tab?.url && isSupportedUrl(tab.url)) {
      origin = new URL(tab.url).hostname.toLowerCase();
    }
  } catch { /* leave origin empty */ }
  // If the current tab already has a note, prefer editing it.
  if (origin) {
    try {
      const matches = await send("notes:list", { origin });
      if (Array.isArray(matches) && matches.length > 0) {
        await openQuickAdd({ note: matches[0] });
        return;
      }
    } catch { /* fall through to add */ }
  }
  await openQuickAdd({ prefillOrigin: origin });
}

function bindQuickAdd() {
  const back = document.getElementById("quick-back");
  back?.addEventListener("click", async () => {
    const probe = document.getElementById("quick-pw-probe");
    if (probe) probe.value = "";
    show("view-vault");
    await refreshCurrentSite();
  });

  const addBtn = document.getElementById("add-btn");
  addBtn?.addEventListener("click", () => {
    addBtn.animate(
      [{ transform: "scale(1)" }, { transform: "scale(0.9)" }, { transform: "scale(1)" }],
      { duration: 200, easing: "cubic-bezier(0.16, 1, 0.3, 1)" }
    );
    startQuickAddFromCurrentTab();
  });

  const emptyAdd = document.getElementById("site-empty-add");
  emptyAdd?.addEventListener("click", () => startQuickAddFromCurrentTab());

  const editBtn = document.getElementById("match-edit");
  editBtn?.addEventListener("click", () => startQuickAddFromCurrentTab());

  const twofaSel = document.getElementById("quick-2fa");
  twofaSel?.addEventListener("change", updateQuick2faVisibility);

  bindQuickPasswordHint();

  const form = document.getElementById("quick-form");
  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    setQuickError("");
    const origin = document.getElementById("quick-origin").value.trim();
    if (!origin) {
      setQuickError("Site is required.");
      document.getElementById("quick-origin")?.focus();
      return;
    }
    const note = {
      origin,
      label: document.getElementById("quick-label").value.trim(),
      authMethod: document.getElementById("quick-auth").value,
      email: document.getElementById("quick-email").value.trim(),
      twofaBackup: document.getElementById("quick-2fa").value,
      twofaDetail: document.getElementById("quick-2fa-detail").value.trim(),
      tags: document.getElementById("quick-tags").value,
      notes: document.getElementById("quick-notes").value,
      recoveryCodes: document.getElementById("quick-codes").value,
      passwordHint: collectQuickPasswordHint(),
    };
    if (quickEditingId) note.id = quickEditingId;
    const submit = document.getElementById("quick-submit");
    submit?.classList.add("is-busy");
    if (submit) submit.disabled = true;
    try {
      await send("notes:upsert", { note });
      const probe = document.getElementById("quick-pw-probe");
      if (probe) probe.value = "";
      quickEditingId = null;
      show("view-vault");
      await refreshCurrentSite();
    } catch (err) {
      setQuickError(String(err?.message || err));
    } finally {
      submit?.classList.remove("is-busy");
      if (submit) submit.disabled = false;
    }
  });

  const del = document.getElementById("quick-delete");
  del?.addEventListener("click", async () => {
    if (!quickEditingId) return;
    if (!confirm("Delete this note? This can't be undone.")) return;
    del.disabled = true;
    try {
      await send("notes:delete", { id: quickEditingId });
      quickEditingId = null;
      show("view-vault");
      await refreshCurrentSite();
    } catch (err) {
      setQuickError(String(err?.message || err));
    } finally {
      del.disabled = false;
    }
  });
}

async function lockVault() {
  try { await send("master:lock"); }
  catch (err) { console.warn("[auth-notes] lock failed", err); }
  show("view-lock");
  const input = document.getElementById("unlock-pw");
  if (input) { input.value = ""; input.focus(); }
}

// --- Site detection ---------------------------------------------------

function isSupportedUrl(url) {
  if (!url) return false;
  try {
    const u = new URL(url);
    return (u.protocol === "http:" || u.protocol === "https:") && !!u.hostname;
  } catch { return false; }
}

function displayOrigin(origin) {
  const s = String(origin || "").toLowerCase();
  return s.startsWith("www.") ? s.slice(4) : s;
}

// --- Favicon helpers ------------------------------------------------
// Uses Chrome's local _favicon API (no network calls). The browser serves a
// cached favicon or a deterministic placeholder for the given pageUrl.
function faviconUrl(origin, size = 32) {
  const host = String(origin || "").trim().toLowerCase();
  if (!host) return "";
  const pageUrl = `https://${host}/`;
  try {
    const u = new URL(chrome.runtime.getURL("/_favicon/"));
    u.searchParams.set("pageUrl", pageUrl);
    u.searchParams.set("size", String(size));
    return u.toString();
  } catch {
    return "";
  }
}

function faviconHtml(origin, size = 32) {
  const url = faviconUrl(origin, size);
  if (!url) return "";
  const label = displayOrigin(origin) || "site";
  const initial = (label[0] || "?").toUpperCase();
  return `<span class="favicon" aria-hidden="true" data-initial="${escapeHtml(initial)}"><img class="favicon-img" src="${escapeHtml(url)}" alt="" loading="lazy" decoding="async" referrerpolicy="no-referrer"/></span>`;
}

// CSP forbids inline onerror — wire a single capturing listener to hide
// broken favicon <img>s so the data-initial fallback shows through.
let __faviconErrorBound = false;
function bindFaviconErrors() {
  if (__faviconErrorBound) return;
  __faviconErrorBound = true;
  document.addEventListener("error", (ev) => {
    const t = ev.target;
    if (t && t.classList && t.classList.contains("favicon-img")) {
      t.style.visibility = "hidden";
    }
  }, true);
}

async function currentTab() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    return tabs?.[0] || null;
  } catch { return null; }
}

function prettyAuth(method) {
  const m = String(method || "").toLowerCase();
  const map = {
    "password": "Password",
    "passkey": "Passkey",
    "magic-link": "Magic link",
    "google": "Google",
    "github": "GitHub",
    "apple": "Apple",
    "microsoft": "Microsoft",
    "sso": "SSO",
    "other": "Other",
  };
  return map[m] || (m ? m.charAt(0).toUpperCase() + m.slice(1) : "");
}

function prettyBackup(b) {
  const m = String(b || "").toLowerCase();
  const map = {
    "none": "None",
    "authenticator-app": "Authenticator app",
    "hardware-key": "Hardware key",
    "sms": "SMS",
    "email": "Email",
    "printed-codes": "Printed codes",
    "password-manager": "Password manager",
    "other": "Other",
  };
  return map[m] || m;
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text || "";
}

function setSiteState(name) {
  for (const id of ["site-loading", "site-unsupported", "site-empty", "site-match"]) {
    const el = document.getElementById(id);
    if (el) el.hidden = id !== name;
  }
}

function formatRelative(ts) {
  if (!Number.isFinite(ts)) return "";
  const diff = Date.now() - ts;
  const s = Math.max(0, Math.floor(diff / 1000));
  if (s < 60) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d}d ago`;
  const mo = Math.floor(d / 30);
  if (mo < 12) return `${mo}mo ago`;
  return `${Math.floor(mo / 12)}y ago`;
}

function renderMatch(note) {
  setSiteState("site-match");
  setText("match-label", note.label || displayOrigin(note.origin));
  const favWrap = document.getElementById("match-favicon");
  const favImg = document.getElementById("match-favicon-img");
  if (favWrap && favImg) {
    const label = displayOrigin(note.origin) || "site";
    favWrap.dataset.initial = (label[0] || "?").toUpperCase();
    const url = faviconUrl(note.origin, 64);
    if (url) { favImg.src = url; favImg.style.visibility = ""; }
    else { favImg.removeAttribute("src"); favImg.style.visibility = "hidden"; }
  }
  const authChip = document.getElementById("match-auth");
  if (authChip) {
    const txt = prettyAuth(note.authMethod);
    authChip.textContent = txt;
    authChip.hidden = !txt;
    authChip.dataset.auth = String(note.authMethod || "").toLowerCase();
  }

  const showRow = (rowId, valueId, value) => {
    const row = document.getElementById(rowId);
    const v = document.getElementById(valueId);
    if (!row || !v) return;
    if (value) { v.textContent = value; row.hidden = false; }
    else { row.hidden = true; }
  };
  showRow("match-row-email", "match-email", note.email);
  updateEmailCopyButton(note.email || "");
  updateEmailFillButton(note);
  const twofa = note.twofaBackup && note.twofaBackup !== "none"
    ? (note.twofaDetail ? `${prettyBackup(note.twofaBackup)} — ${note.twofaDetail}` : prettyBackup(note.twofaBackup))
    : "";
  showRow("match-row-2fa", "match-2fa", twofa);
  showRow("match-row-pw", "match-pw", formatPasswordHint(note.passwordHint));
  showRow("match-row-notes", "match-notes", note.notes);
  renderRecoveryCodes(Array.isArray(note.recoveryCodes) ? note.recoveryCodes : []);

  const foot = document.getElementById("match-foot");
  if (foot) {
    const used = Number(note.lastUsedAt);
    const usedRel = Number.isFinite(used) && used > 0 ? formatRelative(used) : "";
    const editRel = formatRelative(note.updatedAt);
    const parts = [];
    if (usedRel) parts.push(`Last used ${usedRel}`);
    if (editRel) parts.push(`edited ${editRel}`);
    foot.textContent = parts.join(" \u2022 ");
  }

  const tagsEl = document.getElementById("match-tags");
  if (tagsEl) {
    const tags = Array.isArray(note.tags) ? note.tags : [];
    if (tags.length === 0) {
      tagsEl.hidden = true;
      tagsEl.innerHTML = "";
    } else {
      tagsEl.hidden = false;
      tagsEl.innerHTML = tags.map((t) => `<span class="tag-chip" data-tag="${escapeHtml(t)}">${escapeHtml(t)}</span>`).join("");
    }
  }
}

function maskCode(code) {
  const s = String(code || "");
  if (!s) return "";
  if (s.length <= 4) return "\u2022".repeat(s.length);
  const head = s.slice(0, 2);
  const tail = s.slice(-2);
  const mid = "\u2022".repeat(Math.max(3, s.length - 4));
  return `${head}${mid}${tail}`;
}

let currentRecoveryCodes = [];
let recoveryRevealed = false;

// --- Quick-copy: email-used field --------------------------------
// Clipboard auto-clear: when the user copies the email, schedule a wipe in
// CLIPBOARD_CLEAR_MS milliseconds. If the same value is still on the
// clipboard we overwrite it with a single space (Chromium refuses an empty
// writeText) so the secret doesn't linger. If the user has copied something
// else in the meantime, we leave it alone.
const CLIPBOARD_CLEAR_MS = 20_000;
let clipboardClearTimer = null;
let clipboardClearValue = "";
let copyButtonResetTimer = null;

function updateEmailCopyButton(value) {
  const btn = document.getElementById("match-email-copy");
  if (!btn) return;
  const v = String(value || "").trim();
  btn.hidden = !v;
  btn.dataset.email = v;
  if (!v) {
    btn.dataset.state = "idle";
    const label = document.getElementById("match-email-copy-label");
    if (label) label.textContent = "Copy";
  }
}

function setCopyButtonState(state, labelText) {
  const btn = document.getElementById("match-email-copy");
  if (!btn) return;
  btn.dataset.state = state;
  const label = document.getElementById("match-email-copy-label");
  if (label) label.textContent = labelText;
  clearTimeout(copyButtonResetTimer);
  if (state !== "idle") {
    copyButtonResetTimer = setTimeout(() => {
      btn.dataset.state = "idle";
      if (label) label.textContent = "Copy";
    }, CLIPBOARD_CLEAR_MS);
  }
}

async function clearClipboardIfStale() {
  clipboardClearTimer = null;
  const stash = clipboardClearValue;
  clipboardClearValue = "";
  if (!stash) return;
  try {
    let current = "";
    try { current = await navigator.clipboard.readText(); }
    catch { current = stash; /* assume still there; safer to clear */ }
    if (current === stash) {
      // writeText("") is rejected on some platforms; a single space safely
      // overwrites the secret without leaving a discoverable empty entry.
      await navigator.clipboard.writeText(" ");
    }
  } catch (err) {
    console.warn("[auth-notes] clipboard clear failed", err);
  }
  const btn = document.getElementById("match-email-copy");
  if (btn && btn.dataset.state !== "idle") {
    btn.dataset.state = "idle";
    const label = document.getElementById("match-email-copy-label");
    if (label) label.textContent = "Copy";
  }
}

function scheduleClipboardClear(value) {
  clearTimeout(clipboardClearTimer);
  clipboardClearValue = value;
  clipboardClearTimer = setTimeout(clearClipboardIfStale, CLIPBOARD_CLEAR_MS);
}

async function copyEmailWithAutoClear() {
  const btn = document.getElementById("match-email-copy");
  if (!btn) return;
  const email = String(btn.dataset.email || "").trim();
  if (!email) return;
  btn.animate(
    [{ transform: "scale(1)" }, { transform: "scale(0.94)" }, { transform: "scale(1)" }],
    { duration: 200, easing: "cubic-bezier(0.16, 1, 0.3, 1)" }
  );
  try {
    await navigator.clipboard.writeText(email);
  } catch (err) {
    console.warn("[auth-notes] copy failed", err);
    setCopyButtonState("error", "Failed");
    return;
  }
  scheduleClipboardClear(email);
  setCopyButtonState("copied", "Copied — clears 20s");
}

function bindEmailCopy() {
  const btn = document.getElementById("match-email-copy");
  if (!btn) return;
  btn.addEventListener("click", (e) => {
    e.preventDefault();
    copyEmailWithAutoClear();
  });
}

// --- Auto-fill (opt-in) --------------------------------------------
// The popup never injects directly. It asks the background service worker
// to inject the value via chrome.scripting, after the SW has re-verified
// the vault is unlocked and the active tab matches the note's origin.

let autofillFeatureEnabled = false;

function setAutofillFeatureEnabled(on) {
  autofillFeatureEnabled = !!on;
  // Re-render the fill button against whatever note (if any) is currently
  // showing in the match view. dataset.note is stamped by updateEmailFillButton.
  const btn = document.getElementById("match-email-fill");
  if (!btn) return;
  if (!autofillFeatureEnabled) { btn.hidden = true; return; }
  // Re-evaluate from the stamped dataset if present.
  const value = btn.dataset.email || "";
  btn.hidden = !value;
}

function updateEmailFillButton(note) {
  const btn = document.getElementById("match-email-fill");
  if (!btn) return;
  const email = String(note?.email || "").trim();
  if (!autofillFeatureEnabled || !email || !note?.id) {
    btn.hidden = true;
    btn.dataset.state = "idle";
    btn.dataset.email = "";
    btn.dataset.noteId = "";
    const label = document.getElementById("match-email-fill-label");
    if (label) label.textContent = "Fill";
    return;
  }
  btn.hidden = false;
  btn.dataset.state = "idle";
  btn.dataset.email = email;
  btn.dataset.noteId = String(note.id);
  const label = document.getElementById("match-email-fill-label");
  if (label) label.textContent = "Fill";
}

function setFillButtonState(state, labelText, resetMs = 2400) {
  const btn = document.getElementById("match-email-fill");
  if (!btn) return;
  btn.dataset.state = state;
  const label = document.getElementById("match-email-fill-label");
  if (label) label.textContent = labelText;
  if (state !== "idle") {
    setTimeout(() => {
      if (btn.dataset.state === state) {
        btn.dataset.state = "idle";
        if (label) label.textContent = "Fill";
      }
    }, resetMs);
  }
}

async function autofillCurrentTab() {
  const btn = document.getElementById("match-email-fill");
  if (!btn || btn.hidden) return;
  const noteId = btn.dataset.noteId || "";
  if (!noteId) return;
  const tab = await currentTab();
  if (!tab?.id || !isSupportedUrl(tab.url)) {
    setFillButtonState("error", "No page");
    return;
  }
  let host = "";
  try { host = new URL(tab.url).hostname.toLowerCase(); } catch { /* unreachable */ }
  btn.animate(
    [{ transform: "scale(1)" }, { transform: "scale(0.94)" }, { transform: "scale(1)" }],
    { duration: 200, easing: "cubic-bezier(0.16, 1, 0.3, 1)" }
  );
  setFillButtonState("busy", "Filling…", 6000);
  try {
    const res = await send("notes:autofill", { id: noteId, tabId: tab.id, tabOrigin: host });
    setFillButtonState("copied", res?.target ? `Filled → ${res.target}` : "Filled");
  } catch (err) {
    const msg = String(err?.message || err);
    console.warn("[auth-notes] autofill failed", msg);
    setFillButtonState("error", msg.length > 28 ? "Failed" : msg);
  }
}

function bindEmailFill() {
  const btn = document.getElementById("match-email-fill");
  if (!btn) return;
  btn.addEventListener("click", (e) => {
    e.preventDefault();
    autofillCurrentTab();
  });
}

function paintRecoveryCodes() {
  const list = document.getElementById("match-codes-list");
  if (!list) return;
  list.dataset.revealed = recoveryRevealed ? "true" : "false";
  list.innerHTML = currentRecoveryCodes.map((code, i) => {
    const display = recoveryRevealed ? code : maskCode(code);
    return `<li class="codes-item"><span class="codes-index">${i + 1}</span><span class="codes-value">${escapeHtml(display)}</span></li>`;
  }).join("");
}

function renderRecoveryCodes(codes) {
  const row = document.getElementById("match-row-codes");
  const count = document.getElementById("match-codes-count");
  const toggle = document.getElementById("match-codes-toggle");
  if (!row || !toggle) return;
  currentRecoveryCodes = Array.isArray(codes) ? codes.filter((c) => typeof c === "string" && c.length > 0) : [];
  recoveryRevealed = false;
  if (currentRecoveryCodes.length === 0) {
    row.hidden = true;
    return;
  }
  row.hidden = false;
  if (count) {
    const n = currentRecoveryCodes.length;
    count.textContent = `${n} code${n === 1 ? "" : "s"} \u2014 masked`;
  }
  const label = toggle.querySelector(".btn-label");
  if (label) label.textContent = label.dataset.show || "Reveal";
  toggle.setAttribute("aria-expanded", "false");
  paintRecoveryCodes();
}

function bindRecoveryReveal() {
  const toggle = document.getElementById("match-codes-toggle");
  const count = document.getElementById("match-codes-count");
  if (!toggle) return;
  toggle.addEventListener("click", () => {
    toggle.animate(
      [{ transform: "scale(1)" }, { transform: "scale(0.96)" }, { transform: "scale(1)" }],
      { duration: 200, easing: "cubic-bezier(0.16, 1, 0.3, 1)" }
    );
    recoveryRevealed = !recoveryRevealed;
    const label = toggle.querySelector(".btn-label");
    if (label) label.textContent = recoveryRevealed ? (label.dataset.hide || "Hide") : (label.dataset.show || "Reveal");
    toggle.setAttribute("aria-expanded", recoveryRevealed ? "true" : "false");
    if (count) {
      const n = currentRecoveryCodes.length;
      count.textContent = recoveryRevealed
        ? `${n} code${n === 1 ? "" : "s"} \u2014 visible`
        : `${n} code${n === 1 ? "" : "s"} \u2014 masked`;
    }
    paintRecoveryCodes();
  });
}

async function refreshCurrentSite() {
  setSiteState("site-loading");
  setText("site-label", "Detecting…");
  setText("site-sub", "current tab");

  const tab = await currentTab();
  const url = tab?.url || "";
  if (!isSupportedUrl(url)) {
    setText("site-label", "No web page");
    setText("site-sub", "browser surface");
    setSiteState("site-unsupported");
    return;
  }

  let origin = "";
  try { origin = new URL(url).hostname.toLowerCase(); } catch { /* unreachable */ }
  setText("site-label", displayOrigin(origin));
  setText("site-sub", "current tab");

  try {
    const matches = await send("notes:list", { origin });
    if (Array.isArray(matches) && matches.length > 0) {
      renderMatch(matches[0]);
      // Fire-and-forget: bump lastUsedAt so this site rises on the next sort.
      // Debounced inside the service worker so a quick popup re-open is free.
      send("notes:touch", { id: matches[0].id }).catch(() => { /* best-effort */ });
    } else {
      setSiteState("site-empty");
    }
  } catch (err) {
    console.warn("[auth-notes] notes:list failed", err);
    setSiteState("site-empty");
  }
}

// --- Onboarding tour -------------------------------------------------

const TOUR_STEPS = [
  {
    title: "Welcome to Auth Notes",
    body: "A vault for the boring-but-vital details: which email you used, which 2FA method, where the recovery codes live. Everything stays sealed locally with AES-GCM.",
    art: `<svg viewBox="0 0 160 110" width="150" height="105" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
      <rect x="32" y="46" width="96" height="54" rx="10" opacity=".85"/>
      <path d="M52 46V32a28 28 0 0 1 56 0v14" opacity=".85"/>
      <circle cx="80" cy="72" r="5"/>
      <path d="M80 77v8"/>
      <path d="M18 24c4 4 8 4 12 0M130 24c4 4 8 4 12 0" opacity=".4"/>
      <circle cx="22" cy="60" r="2" opacity=".5"/>
      <circle cx="140" cy="54" r="2.5" opacity=".5"/>
    </svg>`,
  },
  {
    title: "Auto-detects the current tab",
    body: "Open the popup on any site and the matching note surfaces instantly. No searching, no hunting through a list.",
    art: `<svg viewBox="0 0 160 110" width="150" height="105" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
      <rect x="18" y="22" width="124" height="72" rx="10" opacity=".8"/>
      <path d="M18 38h124" opacity=".5"/>
      <circle cx="30" cy="30" r="2"/><circle cx="38" cy="30" r="2"/><circle cx="46" cy="30" r="2"/>
      <rect x="28" y="50" width="52" height="32" rx="6"/>
      <path d="M36 60h32M36 68h26M36 76h18" opacity=".5"/>
      <circle cx="112" cy="66" r="14"/>
      <path d="M105 66l5 5 9-9"/>
    </svg>`,
  },
  {
    title: "Quick-add from anywhere",
    body: "Hit the + button in the header to capture a new site: auth method, email, 2FA backup, tags, and an optional password-strength hint.",
    art: `<svg viewBox="0 0 160 110" width="150" height="105" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
      <rect x="24" y="22" width="112" height="72" rx="10" opacity=".8"/>
      <path d="M40 42h80M40 54h64M40 66h72M40 78h48" opacity=".45"/>
      <circle cx="122" cy="82" r="14"/>
      <path d="M122 76v12M116 82h12"/>
    </svg>`,
  },
  {
    title: "Search & bulk-tag everything",
    body: "The search view filters across labels, emails, and notes. Toggle bulk mode to apply tags to many sites at once.",
    art: `<svg viewBox="0 0 160 110" width="150" height="105" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="62" cy="54" r="24" opacity=".75"/>
      <path d="M80 72l20 20" opacity=".75"/>
      <path d="M50 54h24M62 42v24" opacity=".35"/>
      <rect x="96" y="22" width="44" height="12" rx="4"/>
      <rect x="96" y="42" width="34" height="12" rx="4" opacity=".7"/>
      <rect x="96" y="62" width="28" height="12" rx="4" opacity=".5"/>
    </svg>`,
  },
  {
    title: "You're in control",
    body: "Lock manually any time, set an idle auto-lock, export an encrypted backup, or scan for reused emails — all from Settings.",
    art: `<svg viewBox="0 0 160 110" width="150" height="105" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="80" cy="58" r="22"/>
      <path d="M80 58l14-6"/>
      <path d="M80 28v6M80 82v6M50 58h6M104 58h6M58 36l4 4M98 76l4 4M58 80l4-4M98 40l4-4" opacity=".55"/>
    </svg>`,
  },
];

let tourIndex = 0;
let tourActive = false;
let tourBound = false;
let tourFirstFocusable = null;

function renderTourStep() {
  const step = TOUR_STEPS[tourIndex];
  if (!step) return;
  const total = TOUR_STEPS.length;
  const stepEl = document.getElementById("tour-step");
  const titleEl = document.getElementById("tour-title");
  const bodyEl = document.getElementById("tour-body");
  const artEl = document.getElementById("tour-art");
  const dotsEl = document.getElementById("tour-dots");
  const prev = document.getElementById("tour-prev");
  const next = document.getElementById("tour-next");
  const nextLabel = document.getElementById("tour-next-label");
  if (stepEl) stepEl.textContent = `${tourIndex + 1} / ${total}`;
  if (titleEl) titleEl.textContent = step.title;
  if (bodyEl) bodyEl.textContent = step.body;
  if (artEl) artEl.innerHTML = step.art;
  if (prev) prev.disabled = tourIndex === 0;
  const isLast = tourIndex === total - 1;
  if (nextLabel) nextLabel.textContent = isLast ? "Finish" : "Next";
  if (next) next.dataset.last = isLast ? "true" : "false";
  if (dotsEl) {
    if (dotsEl.children.length !== total) {
      dotsEl.innerHTML = "";
      for (let i = 0; i < total; i++) {
        const dot = document.createElement("button");
        dot.type = "button";
        dot.className = "tour-dot";
        dot.setAttribute("role", "tab");
        dot.setAttribute("aria-label", `Step ${i + 1}`);
        dot.dataset.index = String(i);
        dot.addEventListener("click", () => {
          tourIndex = i;
          renderTourStep();
        });
        dotsEl.appendChild(dot);
      }
    }
    Array.from(dotsEl.children).forEach((d, i) => {
      d.setAttribute("aria-selected", i === tourIndex ? "true" : "false");
    });
  }
}

function bindTourOnce() {
  if (tourBound) return;
  tourBound = true;
  document.getElementById("tour-next")?.addEventListener("click", () => {
    if (tourIndex >= TOUR_STEPS.length - 1) { finishOnboardingTour(true); return; }
    tourIndex += 1;
    renderTourStep();
  });
  document.getElementById("tour-prev")?.addEventListener("click", () => {
    if (tourIndex > 0) { tourIndex -= 1; renderTourStep(); }
  });
  document.getElementById("tour-skip")?.addEventListener("click", () => finishOnboardingTour(true));
  document.addEventListener("keydown", (e) => {
    if (!tourActive) return;
    if (e.key === "Escape") { e.preventDefault(); finishOnboardingTour(true); }
    else if (e.key === "ArrowRight") { e.preventDefault(); document.getElementById("tour-next")?.click(); }
    else if (e.key === "ArrowLeft") { e.preventDefault(); document.getElementById("tour-prev")?.click(); }
  });
}

function openTour() {
  const root = document.getElementById("tour-root");
  if (!root) return;
  bindTourOnce();
  tourActive = true;
  tourIndex = 0;
  renderTourStep();
  root.hidden = false;
  tourFirstFocusable = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  setTimeout(() => document.getElementById("tour-next")?.focus(), 60);
}

async function finishOnboardingTour(persist) {
  const root = document.getElementById("tour-root");
  if (root) root.hidden = true;
  tourActive = false;
  if (persist) {
    try { await send("settings:set", { settings: { onboardingDoneAt: Date.now() } }); }
    catch (err) { console.warn("[auth-notes] persist onboarding flag failed", err); }
  }
  if (tourFirstFocusable && document.body.contains(tourFirstFocusable)) {
    try { tourFirstFocusable.focus(); } catch { /* noop */ }
  }
  tourFirstFocusable = null;
}

async function maybeStartOnboardingTour(opts) {
  const force = !!(opts && opts.force);
  try {
    if (!force) {
      const s = await send("settings:get");
      if (s && s.onboardingDoneAt) return;
    }
    openTour();
  } catch (err) {
    console.warn("[auth-notes] onboarding check failed", err);
  }
}

async function route() {
  try {
    const status = await send("master:status");
    if (!status.hasMaster) { show("view-setup"); return; }
    if (status.locked) {
      show("view-lock");
      const input = document.getElementById("unlock-pw");
      if (input) setTimeout(() => input.focus(), 30);
      return;
    }
    show("view-vault");
    await refreshCurrentSite();
    maybeStartOnboardingTour();
  } catch (err) {
    console.warn("[auth-notes] status failed", err);
    show("view-setup");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  applyTheme();
  THEME_MEDIA.addEventListener("change", () => {
    if (themePref === "auto") { applyTheme(); syncThemeControls(); }
  });
  // Load persisted pref ASAP (best effort).
  send("settings:get").then((s) => {
    if (s?.theme) setThemePref(s.theme);
    setAutofillFeatureEnabled(!!s?.autofillEnabled);
  }).catch(() => { /* not unlocked or background asleep; keep auto */ });

  bindStrength();
  bindReveal();
  bindFaviconErrors();
  bindRecoveryReveal();
  bindEmailCopy();
  bindEmailFill();
  bindSetupForm();
  bindUnlockForm();
  bindSettings();
  bindSearch();
  bindBulkEditor();
  bindQuickAdd();

  const lockBtn = document.getElementById("lock-btn");
  lockBtn?.addEventListener("click", () => {
    lockBtn.animate(
      [{ transform: "scale(1)" }, { transform: "scale(0.9)" }, { transform: "scale(1)" }],
      { duration: 200, easing: "cubic-bezier(0.16, 1, 0.3, 1)" }
    );
    lockVault();
  });

  const btn = document.getElementById("settings-btn");
  btn?.addEventListener("click", () => {
    btn.animate(
      [{ transform: "scale(1)" }, { transform: "scale(0.92)" }, { transform: "scale(1)" }],
      { duration: 220, easing: "cubic-bezier(0.16, 1, 0.3, 1)" }
    );
    openSettings();
  });

  route();
});
