// Auth Notes — MV3 service worker
// Scope: lifecycle, message routing, storage bootstrap. Crypto and notes
// logic land in subsequent roadmap items.

const VERSION = "0.1.0";
const STORAGE_KEY_META = "an:meta";

/** Bootstrap default metadata on first install. */
async function ensureMeta() {
  const got = await chrome.storage.local.get(STORAGE_KEY_META);
  if (got[STORAGE_KEY_META]) return got[STORAGE_KEY_META];
  const meta = {
    version: VERSION,
    createdAt: Date.now(),
    schema: 1,
    locked: true,
    hasMaster: false,
  };
  await chrome.storage.local.set({ [STORAGE_KEY_META]: meta });
  return meta;
}

chrome.runtime.onInstalled.addListener(async (details) => {
  try {
    await ensureMeta();
    console.log(`[auth-notes] installed (${details.reason}) v${VERSION}`);
  } catch (err) {
    console.error("[auth-notes] install bootstrap failed", err);
  }
});

chrome.runtime.onStartup?.addListener(() => {
  console.log(`[auth-notes] startup v${VERSION}`);
});

// Message router — features dispatch here by `type`. Always responds
// asynchronously with `{ ok, data?, error? }`.
const handlers = Object.create(null);

handlers["ping"] = async () => ({ pong: true, version: VERSION });
handlers["meta:get"] = async () => ensureMeta();

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  const type = msg && typeof msg === "object" ? msg.type : null;
  const fn = type && handlers[type];
  if (!fn) {
    sendResponse({ ok: false, error: `unknown message type: ${type}` });
    return false;
  }
  Promise.resolve()
    .then(() => fn(msg))
    .then((data) => sendResponse({ ok: true, data }))
    .catch((err) => sendResponse({ ok: false, error: String(err?.message || err) }));
  return true; // async
});

console.log(`[auth-notes] service worker booted v${VERSION}`);
