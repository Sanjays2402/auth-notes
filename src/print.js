// Print view — paper-friendly rendering of a single note. No glass.

const $ = (id) => document.getElementById(id);

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function displayOrigin(origin) {
  if (!origin) return "";
  try {
    const u = origin.includes("://") ? new URL(origin) : new URL(`https://${origin}`);
    return u.hostname || origin;
  } catch { return String(origin); }
}

function prettyAuth(method) {
  switch (String(method || "").toLowerCase()) {
    case "password": return "Password";
    case "passkey": return "Passkey";
    case "oauth": return "OAuth (Google, GitHub, etc.)";
    case "sso": return "SSO (Okta, Azure AD, etc.)";
    case "magic": return "Magic link";
    case "other": return "Other";
    default: return method ? String(method) : "";
  }
}

function prettyBackup(b) {
  switch (String(b || "").toLowerCase()) {
    case "app": return "Authenticator app";
    case "sms": return "SMS";
    case "email": return "Email";
    case "hardware-key": return "Hardware key";
    case "recovery-codes": return "Recovery codes";
    case "none": return "None";
    default: return b ? String(b) : "";
  }
}

function formatPasswordHint(hint) {
  if (!hint || typeof hint !== "object") return "";
  const parts = [];
  if (Number.isFinite(hint.length)) parts.push(`${hint.length} chars`);
  if (hint.complexity) parts.push(`${hint.complexity}`);
  return parts.join(" \u2022 ");
}

function formatDate(ts) {
  if (!Number.isFinite(ts) || ts <= 0) return "";
  try {
    return new Date(ts).toLocaleString(undefined, {
      year: "numeric", month: "short", day: "numeric",
      hour: "numeric", minute: "2-digit",
    });
  } catch { return ""; }
}

function showError(message) {
  const el = $("error");
  if (!el) return;
  el.textContent = message;
  el.hidden = false;
}

function setRow(rowId, valueId, content, { html = false } = {}) {
  const row = $(rowId);
  const v = $(valueId);
  if (!row || !v) return;
  const hasContent = typeof content === "string"
    ? content.trim().length > 0
    : !!content;
  if (!hasContent) { row.hidden = true; return; }
  if (html) v.innerHTML = content;
  else v.textContent = content;
  row.hidden = false;
}

async function load() {
  const params = new URLSearchParams(location.search);
  const id = params.get("id");
  if (!id) { showError("No note selected."); return; }

  let note;
  try {
    note = await chrome.runtime.sendMessage({ type: "notes:get", id });
  } catch (err) {
    showError("Couldn't reach the vault. Open the extension popup and unlock first.");
    return;
  }
  if (!note) {
    showError("Vault is locked or the note no longer exists. Open the extension popup, unlock, then retry.");
    return;
  }

  document.title = `Auth Notes — ${note.label || displayOrigin(note.origin)}`;
  $("note-label").textContent = note.label || displayOrigin(note.origin) || "Auth note";
  $("note-origin").textContent = displayOrigin(note.origin);

  setRow("row-auth", "val-auth", prettyAuth(note.authMethod));
  setRow("row-email", "val-email", note.email || "");

  const twofa = note.twofaBackup && note.twofaBackup !== "none"
    ? (note.twofaDetail ? `${prettyBackup(note.twofaBackup)} — ${note.twofaDetail}` : prettyBackup(note.twofaBackup))
    : "";
  setRow("row-2fa", "val-2fa", twofa);

  setRow("row-pw", "val-pw", formatPasswordHint(note.passwordHint));

  if (Array.isArray(note.tags) && note.tags.length) {
    const html = note.tags.map((t) => `<span class="tag-chip">${escapeHtml(t)}</span>`).join("");
    setRow("row-tags", "val-tags", html, { html: true });
  }

  if (Array.isArray(note.recoveryCodes) && note.recoveryCodes.length) {
    const html = note.recoveryCodes.map((c) => `<li>${escapeHtml(c)}</li>`).join("");
    setRow("row-codes", "val-codes", html, { html: true });
  }

  if (Array.isArray(note.customFields) && note.customFields.length) {
    const html = note.customFields.map((f) => `<li><span class="f-key">${escapeHtml(f.key)}</span><span class="f-val">${escapeHtml(f.value)}</span></li>`).join("");
    setRow("row-fields", "val-fields", html, { html: true });
  }

  if (note.notes && String(note.notes).trim()) {
    // Plain text — keep the print view literal, predictable, and link-free.
    setRow("row-notes", "val-notes", String(note.notes));
  }

  if (Array.isArray(note.attachments) && note.attachments.length) {
    const html = note.attachments.map((a) => {
      const name = escapeHtml(a.name || "attachment");
      const mime = escapeHtml(a.mimeType || "");
      const size = Number.isFinite(a.size) ? ` \u2022 ${Math.round(a.size / 1024)} KB` : "";
      const isImage = /^image\//.test(a.mimeType || "");
      const imgTag = isImage && a.data
        ? `<img alt="${name}" src="data:${mime};base64,${escapeHtml(a.data)}">`
        : "";
      return `<li><strong>${name}</strong><span> \u2022 ${mime}${size}</span>${imgTag}</li>`;
    }).join("");
    setRow("row-attachments", "val-attachments", html, { html: true });
  }

  const dates = [];
  if (note.createdAt) dates.push(`Created ${formatDate(note.createdAt)}`);
  if (note.updatedAt) dates.push(`Edited ${formatDate(note.updatedAt)}`);
  if (note.lastUsedAt) dates.push(`Last used ${formatDate(note.lastUsedAt)}`);
  $("foot-dates").textContent = dates.join("  \u2022  ");

  $("content").hidden = false;
}

document.addEventListener("DOMContentLoaded", () => {
  $("print-btn")?.addEventListener("click", () => window.print());
  $("close-btn")?.addEventListener("click", () => window.close());
  load();
});
