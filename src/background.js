// Auth Notes — MV3 service worker
// Scope: lifecycle, message routing, storage bootstrap, master-password setup.

import { buildSetupRecord, verifyPassword } from "./crypto.js";
import {
  AUTH_METHODS,
  TWOFA_BACKUPS,
  assertEnvelopeSealed,
  auditEnvelopes,
  decryptNote,
  encryptNote,
  normalizeNote,
  originOf,
  sortNotes,
} from "./notes.js";

const VERSION = "0.1.0";
const STORAGE_KEY_META = "an:meta";
const STORAGE_KEY_AUTH = "an:auth";
const STORAGE_KEY_NOTES = "an:notes";

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

// --- Notes CRUD --------------------------------------------------------

function requireUnlocked() {
  if (!unlockedKey) throw new Error("vault is locked");
  return unlockedKey;
}

async function readEnvelopes() {
  const got = await chrome.storage.local.get(STORAGE_KEY_NOTES);
  const list = got[STORAGE_KEY_NOTES];
  return Array.isArray(list) ? list : [];
}

async function writeEnvelopes(envelopes) {
  // Invariant: every note in chrome.storage.local must be sealed.
  // Any envelope containing plaintext sensitive fields is rejected before write.
  for (const env of envelopes) assertEnvelopeSealed(env);
  await chrome.storage.local.set({ [STORAGE_KEY_NOTES]: envelopes });
}

handlers["notes:audit"] = async () => {
  const envelopes = await readEnvelopes();
  return auditEnvelopes(envelopes);
};

handlers["notes:schema"] = async () => ({
  authMethods: AUTH_METHODS,
  twofaBackups: TWOFA_BACKUPS,
});

handlers["notes:list"] = async (msg) => {
  const key = requireUnlocked();
  const filter = msg?.origin ? originOf(msg.origin) : null;
  const envelopes = await readEnvelopes();
  const scoped = filter ? envelopes.filter((e) => e.origin === filter) : envelopes;
  const decrypted = [];
  for (const env of scoped) {
    try { decrypted.push(await decryptNote(key, env)); }
    catch (err) { console.warn("[auth-notes] skip undecryptable note", env.id, err); }
  }
  return sortNotes(decrypted);
};

handlers["notes:get"] = async (msg) => {
  const key = requireUnlocked();
  const id = String(msg?.id || "");
  if (!id) throw new Error("id is required");
  const envelopes = await readEnvelopes();
  const env = envelopes.find((e) => e.id === id);
  if (!env) return null;
  return decryptNote(key, env);
};

handlers["notes:upsert"] = async (msg) => {
  const key = requireUnlocked();
  const envelopes = await readEnvelopes();
  const existingIdx = msg?.note?.id ? envelopes.findIndex((e) => e.id === msg.note.id) : -1;
  const existing = existingIdx >= 0
    ? await decryptNote(key, envelopes[existingIdx]).catch(() => null)
    : null;
  const record = normalizeNote({
    ...(existing || {}),
    ...msg.note,
    createdAt: existing?.createdAt,
  });
  const envelope = await encryptNote(key, record);
  if (existingIdx >= 0) envelopes[existingIdx] = envelope;
  else envelopes.push(envelope);
  await writeEnvelopes(envelopes);
  return record;
};

handlers["notes:delete"] = async (msg) => {
  requireUnlocked();
  const id = String(msg?.id || "");
  if (!id) throw new Error("id is required");
  const envelopes = await readEnvelopes();
  const next = envelopes.filter((e) => e.id !== id);
  await writeEnvelopes(next);
  return { deleted: envelopes.length - next.length };
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
