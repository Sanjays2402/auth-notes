// Auth Notes — MV3 service worker
// Scope: lifecycle, message routing, storage bootstrap, master-password setup.

import { buildSetupRecord, verifyPassword } from "./crypto.js";
import {
  AUTH_METHODS,
  BACKUP_FORMAT,
  BACKUP_SCHEMA,
  TWOFA_BACKUPS,
  assertEnvelopeSealed,
  auditEnvelopes,
  decodeBackupContent,
  decryptNote,
  encryptNote,
  normalizeNote,
  originOf,
  planImport,
  sortNotes,
} from "./notes.js";

const VERSION = "0.1.0";
const STORAGE_KEY_META = "an:meta";
const STORAGE_KEY_AUTH = "an:auth";
const STORAGE_KEY_NOTES = "an:notes";
const STORAGE_KEY_SETTINGS = "an:settings";

// Backup file format identifier sourced from notes.js so importer + exporter
// agree on the layout.

// Auto-lock
const ALARM_AUTO_LOCK = "an:auto-lock-check";
const DEFAULT_IDLE_MIN = 5;
const MAX_IDLE_MIN = 1440; // 24h
const DEFAULT_SETTINGS = Object.freeze({ idleTimeoutMin: DEFAULT_IDLE_MIN });

// In-memory only. Never persisted. Cleared on SW termination or lock.
let unlockedKey = null;
let lastActivityAt = Date.now();

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

async function readSettings() {
  const got = await chrome.storage.local.get(STORAGE_KEY_SETTINGS);
  const raw = got[STORAGE_KEY_SETTINGS] || {};
  return { ...DEFAULT_SETTINGS, ...raw };
}

function sanitizeSettings(patch) {
  const out = {};
  if (patch && patch.idleTimeoutMin !== undefined) {
    const n = Number(patch.idleTimeoutMin);
    if (!Number.isFinite(n) || n < 0) out.idleTimeoutMin = 0;
    else out.idleTimeoutMin = Math.min(MAX_IDLE_MIN, Math.floor(n));
  }
  return out;
}

async function writeSettings(patch) {
  const cur = await readSettings();
  const next = { ...cur, ...sanitizeSettings(patch) };
  await chrome.storage.local.set({ [STORAGE_KEY_SETTINGS]: next });
  return next;
}

// --- Auto-lock idle timer -----------------------------------------------

function bumpActivity() {
  lastActivityAt = Date.now();
}

async function clearAutoLockAlarm() {
  try { await chrome.alarms?.clear?.(ALARM_AUTO_LOCK); } catch { /* noop */ }
}

async function scheduleAutoLockAlarm() {
  await clearAutoLockAlarm();
  if (!unlockedKey) return;
  const { idleTimeoutMin } = await readSettings();
  if (!idleTimeoutMin || idleTimeoutMin <= 0) return; // disabled
  // chrome.alarms minimum granularity is 1 min; we re-check elapsed each tick.
  chrome.alarms?.create?.(ALARM_AUTO_LOCK, { periodInMinutes: 1, delayInMinutes: 1 });
}

async function performAutoLock(reason = "idle") {
  if (!unlockedKey) return;
  unlockedKey = null;
  await clearAutoLockAlarm();
  await writeMeta({ locked: true });
  console.log(`[auth-notes] auto-locked (${reason})`);
}

chrome.alarms?.onAlarm.addListener(async (alarm) => {
  if (!alarm || alarm.name !== ALARM_AUTO_LOCK) return;
  if (!unlockedKey) { await clearAutoLockAlarm(); return; }
  const { idleTimeoutMin } = await readSettings();
  if (!idleTimeoutMin || idleTimeoutMin <= 0) { await clearAutoLockAlarm(); return; }
  const elapsedMs = Date.now() - lastActivityAt;
  if (elapsedMs >= idleTimeoutMin * 60_000) {
    await performAutoLock(`${idleTimeoutMin}m idle`);
  }
});

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
  bumpActivity();
  await scheduleAutoLockAlarm();
  return { ok: true };
};

handlers["master:verify"] = async (msg) => {
  const auth = await readAuth();
  if (!auth) throw new Error("master password not set");
  const key = await verifyPassword(String(msg?.password || ""), auth);
  unlockedKey = key;
  await writeMeta({ locked: false });
  bumpActivity();
  await scheduleAutoLockAlarm();
  return { ok: true };
};

handlers["master:lock"] = async () => {
  unlockedKey = null;
  await writeMeta({ locked: true });
  await clearAutoLockAlarm();
  return { ok: true };
};

handlers["settings:get"] = async () => readSettings();

handlers["settings:set"] = async (msg) => {
  const next = await writeSettings(msg?.settings || {});
  bumpActivity();
  await scheduleAutoLockAlarm();
  return next;
};

handlers["activity:ping"] = async () => {
  bumpActivity();
  return { lastActivityAt };
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

handlers["backup:export"] = async () => {
  // Vault must be unlocked so the user has just proven they hold the master
  // password — this prevents drive-by extensions / pages from prompting an
  // export of opaque-but-recoverable ciphertext.
  requireUnlocked();
  const auth = await readAuth();
  if (!auth) throw new Error("master password not set");
  const envelopes = await readEnvelopes();
  // Defense in depth: refuse to export anything that isn't fully sealed.
  for (const env of envelopes) assertEnvelopeSealed(env);
  const payload = {
    format: BACKUP_FORMAT,
    schema: BACKUP_SCHEMA,
    appVersion: VERSION,
    exportedAt: Date.now(),
    auth,
    envelopes,
  };
  const json = JSON.stringify(payload, null, 2);
  const ts = new Date(payload.exportedAt).toISOString().replace(/[:.]/g, "-").slice(0, 19);
  return {
    filename: `auth-notes-backup-${ts}.json.enc`,
    mime: "application/octet-stream",
    content: json,
    count: envelopes.length,
    exportedAt: payload.exportedAt,
  };
};

handlers["backup:import"] = async (msg) => {
  const currentKey = requireUnlocked();
  const content = typeof msg?.content === "string" ? msg.content : "";
  const password = typeof msg?.password === "string" ? msg.password : "";
  const mode = msg?.mode === "replace" ? "replace" : "merge";
  if (!password) throw new Error("backup password is required");
  const payload = decodeBackupContent(content);
  // Derive the backup's key from its own auth record. The current vault's
  // master password is intentionally not used here — backups may have been
  // taken under a different password.
  let backupKey;
  try { backupKey = await verifyPassword(password, payload.auth); }
  catch { throw new Error("wrong password for this backup"); }

  const existing = await readEnvelopes();
  const plan = planImport(existing, payload.envelopes, mode);

  // Decrypt each incoming envelope with the backup key, then re-encrypt with
  // the vault's currently unlocked key. This is what makes a backup taken
  // under a different password merge cleanly into the live vault.
  const reencrypted = [];
  let failed = 0;
  for (const env of payload.envelopes) {
    try {
      const note = await decryptNote(backupKey, env);
      const normalized = normalizeNote({
        ...note,
        createdAt: Number.isFinite(note.createdAt) ? note.createdAt : undefined,
      }, { now: Number.isFinite(note.updatedAt) ? note.updatedAt : Date.now() });
      reencrypted.push(await encryptNote(currentKey, normalized));
    } catch (err) {
      console.warn("[auth-notes] skipping unreadable backup entry", env?.id, err);
      failed++;
    }
  }

  let next;
  if (mode === "replace") {
    next = reencrypted;
  } else {
    const byId = new Map(existing.map((e) => [e.id, e]));
    for (const env of reencrypted) byId.set(env.id, env);
    next = [...byId.values()];
  }
  await writeEnvelopes(next);
  return {
    mode,
    total: plan.total,
    added: plan.added,
    replaced: plan.replaced,
    discarded: plan.discarded,
    failed,
    finalCount: next.length,
  };
};

handlers["notes:audit"] = async () => {
  const envelopes = await readEnvelopes();
  return auditEnvelopes(envelopes);
};

handlers["notes:schema"] = async () => ({
  authMethods: AUTH_METHODS,
  twofaBackups: TWOFA_BACKUPS,
});

handlers["notes:search"] = async (msg) => {
  const key = requireUnlocked();
  const q = String(msg?.query || "").trim().toLowerCase();
  const limit = Math.min(Math.max(Number(msg?.limit) || 50, 1), 200);
  const envelopes = await readEnvelopes();
  const decrypted = [];
  for (const env of envelopes) {
    try { decrypted.push(await decryptNote(key, env)); }
    catch (err) { console.warn("[auth-notes] skip undecryptable note", env.id, err); }
  }
  if (!q) {
    const sorted = sortNotes(decrypted);
    return { query: q, total: decrypted.length, results: sorted.slice(0, limit).map((n) => ({ note: n, score: 0, hits: [] })) };
  }
  // Tokenize once; AND-match across all tokens (each token must appear in at
  // least one searchable field). Weighted by which field matched.
  const tokens = q.split(/\s+/).filter(Boolean);
  const FIELD_WEIGHTS = [
    ["label", 5],
    ["origin", 4],
    ["email", 3],
    ["authMethod", 2],
    ["twofaBackup", 2],
    ["twofaDetail", 2],
    ["notes", 1],
  ];
  const scored = [];
  for (const note of decrypted) {
    const fields = Object.fromEntries(
      FIELD_WEIGHTS.map(([k]) => [k, String(note[k] || "").toLowerCase()])
    );
    let totalScore = 0;
    const hits = new Set();
    let allTokensMatched = true;
    for (const tok of tokens) {
      let tokenMatched = false;
      for (const [field, weight] of FIELD_WEIGHTS) {
        const idx = fields[field].indexOf(tok);
        if (idx === -1) continue;
        tokenMatched = true;
        hits.add(field);
        // Prefix-of-field gets a small bonus.
        totalScore += weight + (idx === 0 ? 1 : 0);
      }
      if (!tokenMatched) { allTokensMatched = false; break; }
    }
    if (allTokensMatched) scored.push({ note, score: totalScore, hits: [...hits] });
  }
  scored.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return (b.note.updatedAt || 0) - (a.note.updatedAt || 0);
  });
  return { query: q, total: scored.length, results: scored.slice(0, limit) };
};

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
  // Any inbound message from the popup counts as user activity once unlocked,
  // resetting the idle auto-lock countdown.
  if (unlockedKey && type !== "ping") bumpActivity();
  Promise.resolve()
    .then(() => fn(msg))
    .then((data) => sendResponse({ ok: true, data }))
    .catch((err) => sendResponse({ ok: false, error: String(err?.message || err) }));
  return true; // async
});

console.log(`[auth-notes] service worker booted v${VERSION}`);
