// Auth Notes — Options page (chrome://extensions → Details → Options).
// Mirrors the popup settings but renders standalone so the user gets the full
// page real estate for less common controls like PBKDF2 iterations / rekey.

const $ = (id) => document.getElementById(id);

function send(type, extra = {}) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type, ...extra }, (resp) => {
      const err = chrome.runtime.lastError;
      if (err) return reject(new Error(err.message));
      if (!resp || !resp.ok) return reject(new Error(resp?.error || "request failed"));
      resolve(resp.data);
    });
  });
}

// --- Theme ----------------------------------------------------------------
const mql = window.matchMedia?.("(prefers-color-scheme: dark)");
function resolveTheme(pref) {
  if (pref === "light" || pref === "dark") return pref;
  return mql?.matches ? "dark" : "light";
}
function applyTheme(pref) {
  document.body.dataset.theme = resolveTheme(pref);
}
mql?.addEventListener?.("change", () => {
  // Only re-apply when in auto mode.
  if (document.body.dataset.themePref === "auto") applyTheme("auto");
});

function paintSegmented(group, value) {
  const buttons = group.querySelectorAll(".seg");
  const pill = group.querySelector(".seg-pill");
  let activeBtn = null;
  buttons.forEach((b) => {
    const on = b.dataset.theme === value;
    b.setAttribute("aria-checked", on ? "true" : "false");
    if (on) activeBtn = b;
  });
  if (pill && activeBtn) {
    const groupRect = group.getBoundingClientRect();
    const btnRect = activeBtn.getBoundingClientRect();
    pill.style.width = `${btnRect.width}px`;
    pill.style.transform = `translateX(${btnRect.left - groupRect.left - 4}px)`;
  }
}

// --- Idle summary ---------------------------------------------------------
function idleSummaryText(min) {
  if (!min || min <= 0) return "Auto-lock is off. The vault stays unlocked until you lock it manually.";
  if (min === 1) return "Locks after 1 minute idle.";
  if (min < 60) return `Locks after ${min} minutes idle.`;
  if (min === 60) return "Locks after 1 hour idle.";
  return `Locks after ${(min / 60).toFixed(min % 60 ? 1 : 0)} hours idle.`;
}

function formatCount(n) {
  return Number(n).toLocaleString();
}

function fmtDate(ts) {
  if (!Number.isFinite(ts)) return "—";
  try { return new Date(ts).toLocaleString(); }
  catch { return new Date(ts).toISOString(); }
}

// --- Saved indicator ------------------------------------------------------
function flashSaved(el, text = "Saved.") {
  if (!el) return;
  el.textContent = text;
  el.classList.remove("err"); el.classList.add("ok");
  el.hidden = false;
  clearTimeout(flashSaved._t);
  flashSaved._t = setTimeout(() => { el.hidden = true; }, 1800);
}
function flashErr(el, text) {
  if (!el) return;
  el.textContent = text;
  el.classList.remove("ok"); el.classList.add("err");
  el.hidden = false;
}

// --- Theme binding --------------------------------------------------------
function bindTheme(initial) {
  const group = $("opt-theme");
  applyTheme(initial);
  document.body.dataset.themePref = initial;
  paintSegmented(group, initial);
  // Paint once layout settles, since the segmented control's pill needs real
  // measured widths.
  requestAnimationFrame(() => paintSegmented(group, initial));
  group.addEventListener("click", async (ev) => {
    const btn = ev.target.closest(".seg");
    if (!btn) return;
    const next = btn.dataset.theme;
    if (!next || next === document.body.dataset.themePref) return;
    document.body.dataset.themePref = next;
    applyTheme(next);
    paintSegmented(group, next);
    try {
      await send("settings:set", { settings: { theme: next } });
      flashSaved($("theme-saved"));
    } catch (err) {
      flashErr($("theme-saved"), err.message || "Couldn't save theme.");
    }
  });
}

// --- Idle binding ---------------------------------------------------------
function bindIdle(initialMin) {
  const select = $("opt-idle");
  const summary = $("idle-summary");
  select.value = String(initialMin ?? 5);
  summary.textContent = idleSummaryText(Number(select.value));
  select.addEventListener("change", async () => {
    const min = Math.max(0, Math.floor(Number(select.value) || 0));
    summary.textContent = idleSummaryText(min);
    try {
      await send("settings:set", { settings: { idleTimeoutMin: min } });
      flashSaved($("idle-saved"));
    } catch (err) {
      flashErr($("idle-saved"), err.message || "Couldn't save idle timeout.");
    }
  });
}

// --- KDF / rekey ----------------------------------------------------------
function bindKdf(settings) {
  const select = $("opt-iters");
  const choices = Array.isArray(settings.pbkdf2Choices) && settings.pbkdf2Choices.length
    ? settings.pbkdf2Choices
    : [100000, 250000, 500000, 1000000];
  const current = Number(settings.pbkdf2Iterations) || 250000;
  // Make sure the actual configured value is selectable even if it's not in
  // the recommended set (could happen if storage was hand-edited).
  const merged = [...new Set([...choices, current])].sort((a, b) => a - b);
  select.innerHTML = "";
  for (const n of merged) {
    const opt = document.createElement("option");
    opt.value = String(n);
    opt.textContent = `${formatCount(n)} iterations`;
    if (n === current) opt.selected = true;
    select.appendChild(opt);
  }
  $("kdf-current").textContent = `${formatCount(current)}`;
  $("kdf-default").textContent = `${formatCount(settings.pbkdf2Default || 250000)}`;

  // Persist preference immediately. Actual key rotation only happens via the
  // rekey button — the saved preference applies to the next master setup
  // (e.g. importing a backup over an empty vault).
  select.addEventListener("change", async () => {
    const n = Math.floor(Number(select.value) || 250000);
    try {
      await send("settings:set", { settings: { pbkdf2Iterations: n } });
    } catch (err) {
      console.warn("[auth-notes] save iters failed", err);
    }
  });

  const runBtn = $("rekey-run");
  const status = $("rekey-status");
  const pwInput = $("rekey-pw");
  runBtn.addEventListener("click", async () => {
    const target = Math.floor(Number(select.value) || 250000);
    const password = pwInput.value;
    if (!password) {
      flashErr(status, "Enter the current master password.");
      return;
    }
    runBtn.disabled = true;
    status.hidden = false;
    status.classList.remove("err", "ok");
    status.textContent = `Re-deriving key (${formatCount(target)} iterations)…`;
    try {
      const result = await send("master:rekey", { password, iterations: target });
      if (result.rekeyed === false) {
        flashSaved(status, "Already at the target iteration count.");
      } else {
        $("kdf-current").textContent = formatCount(result.iterations);
        pwInput.value = "";
        const extra = result.skipped ? ` (${result.skipped} entries unreadable)` : "";
        flashSaved(status, `Re-sealed ${result.notes} notes${extra}.`);
      }
    } catch (err) {
      flashErr(status, err.message || "Rekey failed.");
    } finally {
      runBtn.disabled = false;
    }
  });

  // Show/hide password
  document.querySelectorAll(".input-toggle").forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = document.getElementById(btn.dataset.target || "");
      if (!target) return;
      target.type = target.type === "password" ? "text" : "password";
    });
  });
}

// --- Change master password ----------------------------------------------
function bindChangePassword() {
  const runBtn = $("chpw-run");
  const status = $("chpw-status");
  const curEl = $("chpw-current");
  const newEl = $("chpw-new");
  const confirmEl = $("chpw-confirm");
  if (!runBtn || !status || !curEl || !newEl || !confirmEl) return;
  runBtn.addEventListener("click", async () => {
    const cur = curEl.value;
    const next = newEl.value;
    const confirm = confirmEl.value;
    if (!cur) { flashErr(status, "Enter the current master password."); return; }
    if (next.length < 8) { flashErr(status, "New password must be at least 8 characters."); return; }
    if (next !== confirm) { flashErr(status, "New password and confirmation don't match."); return; }
    if (next === cur) { flashErr(status, "New password must differ from the current one."); return; }
    runBtn.disabled = true;
    status.hidden = false;
    status.classList.remove("err", "ok");
    status.textContent = "Re-sealing vault under the new password\u2026";
    try {
      const result = await send("master:changePassword", {
        currentPassword: cur,
        newPassword: next,
      });
      curEl.value = ""; newEl.value = ""; confirmEl.value = "";
      const extra = result.skipped ? ` (${result.skipped} entries unreadable)` : "";
      flashSaved(status, `Master password changed \u2022 ${result.notes} notes resealed${extra}.`);
    } catch (err) {
      flashErr(status, err.message || "Couldn't change password.");
    } finally {
      runBtn.disabled = false;
    }
  });
}

// --- Meta -----------------------------------------------------------------
function bindMeta(meta, status) {
  $("meta-version").textContent = meta?.version || "—";
  $("meta-created").textContent = fmtDate(meta?.createdAt);
  if (!status?.hasMaster) {
    $("meta-status").textContent = "Not set up";
  } else if (status.locked) {
    $("meta-status").textContent = "Locked";
  } else {
    $("meta-status").textContent = "Unlocked";
  }
  if (status?.hasMaster && status?.locked) {
    $("lock-banner").hidden = false;
    $("rekey-run").disabled = true;
  } else if (!status?.hasMaster) {
    $("lock-banner").hidden = false;
    $("lock-banner").querySelector("span").textContent =
      "Master password isn't set yet. Open the popup to create one.";
    $("rekey-run").disabled = true;
  }
  // Change-password is also gated on an unlocked vault — the handler in the
  // service worker calls requireUnlocked().
  const chpwRun = $("chpw-run");
  if (chpwRun) {
    if (!status?.hasMaster || status?.locked) chpwRun.disabled = true;
    else chpwRun.disabled = false;
  }
}

// --- Boot -----------------------------------------------------------------
async function boot() {
  try {
    const [settings, meta, status] = await Promise.all([
      send("settings:get"),
      send("meta:get"),
      send("master:status"),
    ]);
    bindTheme(settings.theme || "auto");
    bindIdle(settings.idleTimeoutMin ?? 5);
    bindKdf(settings);
    bindChangePassword();
    bindMeta(meta, status);
  } catch (err) {
    console.error("[auth-notes] options boot failed", err);
    const status = $("rekey-status");
    if (status) flashErr(status, `Couldn't load settings: ${err.message}`);
  }
}

boot();
