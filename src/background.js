// Auth Notes — MV3 service worker
// Scope: lifecycle, message routing, storage bootstrap, master-password setup.

import { buildSetupRecord, verifyPassword } from "./crypto.js";

const VERSION = "0.1.0";
const STORAGE_KEY_META = "an:meta";
const STORAGE_KEY_AUTH = "an:auth";

// In-memory only. Never persisted. Cleared on SW termination or lock.
let unlockedKey = null;

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

async function readMeta() {
  const got = await chrome.storage.local.get(STORAGE_KEY_META);
  return got[STORAGE_KEY_META] || (await ensureMeta());
}

async function writeMeta(patch) {
  const cur = await readMeta();
  const next = { ...cur, ...patch };
  await chrome.storage.local.set({ [STORAGE_KEY_META]: next });
  return next;
}

async function readAuth() {
  const got = await chrome.storage.local.get(STORAGE_KEY_AUTH);
  return got[STORAGE_KEY_AUTH] || null;
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
  // SW restart implies prior unlocked key is gone. Stay locked.
  unlockedKey = null;
  console.log(`[auth-notes] startup v${VERSION}`);
});

// Message router — features dispatch here by `type`. Always responds
// asynchronously with `{ ok, data?, error? }`.
const handlers = Object.create(null);

handlers["ping"] = async () => ({ pong: true, version: VERSION });
handlers["meta:get"] = async () => readMeta();

handlers["master:status"] = async () => {
  const meta = await readMeta();
  return {
    hasMaster: !!meta.hasMaster,
    locked: !unlockedKey,
  };
};

handlers["master:setup"] = async (msg) => {
  const meta = await readMeta();
  if (meta.hasMaster) throw new Error("master password already set");
  const password = msg?.password;
  if (typeof password !== "string" || password.length < 8) {
    throw new Error("password must be at least 8 characters");
  }
  const { record, key } = await buildSetupRecord(password);
  await chrome.storage.local.set({ [STORAGE_KEY_AUTH]: record });
  await writeMeta({ hasMaster: true, locked: false });
  unlockedKey = key;
  return { ok: true };
};

handlers["master:verify"] = async (msg) => {
  const auth = await readAuth();
  if (!auth) throw new Error("master password not set");
  const key = await verifyPassword(String(msg?.password || ""), auth);
  unlockedKey = key;
  await writeMeta({ locked: false });
  return { ok: true };
};

handlers["master:lock"] = async () => {
  unlockedKey = null;
  await writeMeta({ locked: true });
  return { ok: true };
};

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
