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
    } catch (err) {
      showError(String(err.message || err));
      submit.disabled = false;
      submit.classList.remove("is-busy");
    }
  });
}

async function route() {
  try {
    const status = await send("master:status");
    show(status.hasMaster ? "view-vault" : "view-setup");
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
