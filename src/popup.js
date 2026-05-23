// Auth Notes — popup entry point

function applyTheme() {
  const prefersLight = window.matchMedia("(prefers-color-scheme: light)").matches;
  document.body.dataset.theme = prefersLight ? "light" : "dark";
}

function show(id) {
  for (const v of document.querySelectorAll(".view")) v.hidden = v.id !== id;
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

  const btn = document.getElementById("settings-btn");
  btn?.addEventListener("click", () => {
    btn.animate(
      [{ transform: "scale(1)" }, { transform: "scale(0.92)" }, { transform: "scale(1)" }],
      { duration: 220, easing: "cubic-bezier(0.16, 1, 0.3, 1)" }
    );
  });

  route();
});
