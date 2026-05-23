// Auth Notes — popup entry point

function applyTheme() {
  const prefersLight = window.matchMedia("(prefers-color-scheme: light)").matches;
  document.body.dataset.theme = prefersLight ? "light" : "dark";
}

function show(id) {
  for (const v of document.querySelectorAll(".view")) v.hidden = v.id !== id;
  const lockBtn = document.getElementById("lock-btn");
  if (lockBtn) lockBtn.hidden = id !== "view-vault" && id !== "view-settings" && id !== "view-search";
  const searchBtn = document.getElementById("search-btn");
  if (searchBtn) searchBtn.hidden = id !== "view-vault";
  const settingsBtn = document.getElementById("settings-btn");
  if (settingsBtn) settingsBtn.hidden = id === "view-settings" || id === "view-setup" || id === "view-lock" || id === "view-search";
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

    li.innerHTML = `
      <div class="search-item-head">
        <span class="search-item-label">${highlight(label, query)}</span>
        ${auth ? `<span class="chip" data-auth="${escapeHtml(String(note.authMethod || "").toLowerCase())}">${escapeHtml(auth)}</span>` : ""}
      </div>
      <div class="search-item-origin">${highlight(origin, query)}</div>
      ${note.email ? `<div class="search-item-line"><span class="search-item-key">Email</span><span>${highlight(note.email, query)}</span></div>` : ""}
      ${twofa ? `<div class="search-item-line"><span class="search-item-key">2FA</span><span>${highlight(twofa, query)}</span></div>` : ""}
      ${showNotes ? `<div class="search-item-line search-item-notes"><span class="search-item-key">Note</span><span>${highlight(note.notes, query)}</span></div>` : ""}
      ${updated ? `<div class="search-item-foot">Updated ${escapeHtml(updated)}</div>` : ""}
    `;
    frag.appendChild(li);
  }
  list.appendChild(frag);
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
  runSearch(input?.value || "");
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
  const twofa = note.twofaBackup && note.twofaBackup !== "none"
    ? (note.twofaDetail ? `${prettyBackup(note.twofaBackup)} — ${note.twofaDetail}` : prettyBackup(note.twofaBackup))
    : "";
  showRow("match-row-2fa", "match-2fa", twofa);
  showRow("match-row-notes", "match-notes", note.notes);

  const foot = document.getElementById("match-foot");
  if (foot) {
    const rel = formatRelative(note.updatedAt);
    foot.textContent = rel ? `Updated ${rel}` : "";
  }
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
    } else {
      setSiteState("site-empty");
    }
  } catch (err) {
    console.warn("[auth-notes] notes:list failed", err);
    setSiteState("site-empty");
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
  } catch (err) {
    console.warn("[auth-notes] status failed", err);
    show("view-setup");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  applyTheme();
  window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", applyTheme);

  bindStrength();
  bindReveal();
  bindSetupForm();
  bindUnlockForm();
  bindSettings();
  bindSearch();

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
