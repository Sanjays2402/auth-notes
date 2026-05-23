// Auth Notes — popup entry point
// Scaffolding: theme detection, SW handshake. Real UI lands in subsequent items.

function applyTheme() {
  const prefersLight = window.matchMedia("(prefers-color-scheme: light)").matches;
  document.body.dataset.theme = prefersLight ? "light" : "dark";
}

async function ping() {
  try {
    const res = await chrome.runtime.sendMessage({ type: "ping" });
    if (res?.ok) console.log("[auth-notes] sw alive", res.data);
  } catch (err) {
    console.warn("[auth-notes] sw ping failed", err);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  applyTheme();
  window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", applyTheme);

  const btn = document.getElementById("settings-btn");
  btn?.addEventListener("click", () => {
    // Settings panel lands in a later roadmap item.
    btn.animate(
      [{ transform: "scale(1)" }, { transform: "scale(0.92)" }, { transform: "scale(1)" }],
      { duration: 220, easing: "cubic-bezier(0.16, 1, 0.3, 1)" }
    );
  });

  ping();
});
