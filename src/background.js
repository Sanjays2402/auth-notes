// Auth Notes — MV3 service worker
// Scope: lifecycle, message routing, storage bootstrap, master-password setup.

import {
  PBKDF2_ITERATIONS,
  buildSetupRecord,
  bytesToB64,
  deriveKey,
  encryptString,
  randomBytes,
  CRYPTO_SCHEMA,
  SALT_BYTES,
  VERIFIER_PLAINTEXT,
  verifyPassword,
} from "./crypto.js";
import {
  AUDIT_MAX,
  AUTH_METHODS,
  BACKUP_FORMAT,
  BACKUP_SCHEMA,
  TAG_PRESETS,
  TWOFA_BACKUPS,
  applyBulkTags,
  assertAuditEnvelopeSealed,
  assertEnvelopeSealed,
  auditEnvelopes,
  collectTags,
  decodeBackupContent,
  decryptAuditEvent,
  decryptNote,
  encryptAuditEvent,
  encryptNote,
  findDuplicateEmails,
  normalizeAuditEvent,
  normalizeNote,
  normalizeTag,
  normalizeTags,
  originOf,
  planImport,
  sortNotes,
  trimAuditLog,
} from "./notes.js";

const VERSION = "0.1.0";
const STORAGE_KEY_META = "an:meta";
const STORAGE_KEY_AUTH = "an:auth";
const STORAGE_KEY_NOTES = "an:notes";
const STORAGE_KEY_SETTINGS = "an:settings";
const STORAGE_KEY_AUDIT = "an:audit";

// Backup file format identifier sourced from notes.js so importer + exporter
// agree on the layout.

// Auto-lock
const ALARM_AUTO_LOCK = "an:auto-lock-check";
const DEFAULT_IDLE_MIN = 5;
const MAX_IDLE_MIN = 1440; // 24h
const VALID_THEMES = Object.freeze(["auto", "dark", "light"]);
const DEFAULT_THEME = "auto";
// PBKDF2 iteration choices surfaced in the options page. The default matches
// the crypto module's baseline so existing vaults need no migration.
const PBKDF2_CHOICES = Object.freeze([100_000, 250_000, 500_000, 1_000_000]);
const MIN_PBKDF2 = 50_000;
const MAX_PBKDF2 = 4_000_000;
const DEFAULT_SETTINGS = Object.freeze({
  idleTimeoutMin: DEFAULT_IDLE_MIN,
  theme: DEFAULT_THEME,
  pbkdf2Iterations: PBKDF2_ITERATIONS,
  onboardingDoneAt: null,
});

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
  if (patch && patch.theme !== undefined) {
    const t = String(patch.theme).toLowerCase();
    out.theme = VALID_THEMES.includes(t) ? t : DEFAULT_THEME;
  }
  if (patch && patch.onboardingDoneAt !== undefined) {
    const v = patch.onboardingDoneAt;
    if (v === null || v === false) out.onboardingDoneAt = null;
    else {
      const n = Math.floor(Number(v));
      out.onboardingDoneAt = Number.isFinite(n) && n > 0 ? n : Date.now();
    }
  }
  if (patch && patch.pbkdf2Iterations !== undefined) {
    const n = Math.floor(Number(patch.pbkdf2Iterations));
    if (Number.isFinite(n) && n >= MIN_PBKDF2) {
      out.pbkdf2Iterations = Math.min(MAX_PBKDF2, n);
    } else {
      out.pbkdf2Iterations = PBKDF2_ITERATIONS;
    }
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
  // Record the auto-lock while we still hold the key, so the entry can be
  // sealed under the same vault key the user will unlock with next.
  try { await recordAuditEvent({ type: "auto-lock", detail: reason }); }
  catch (err) { console.warn("[auth-notes] audit auto-lock failed", err); }
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
  const settings = await readSettings();
  const { record, key } = await buildSetupRecord(password, settings.pbkdf2Iterations);
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

handlers["settings:get"] = async () => ({
  ...(await readSettings()),
  pbkdf2Choices: PBKDF2_CHOICES,
  pbkdf2Default: PBKDF2_ITERATIONS,
});

handlers["master:rekey"] = async (msg) => {
  // Re-derive the master key under a new iteration count and re-seal every
  // note + audit envelope. Requires the live password so we can decrypt all
  // existing ciphertext before rotating. The vault must already be unlocked.
  const currentKey = requireUnlocked();
  const password = String(msg?.password || "");
  if (!password) throw new Error("current master password required");
  const auth = await readAuth();
  if (!auth) throw new Error("master password not set");
  // Confirm the password actually opens the live vault. Throws on mismatch.
  await verifyPassword(password, auth);
  const targetIters = sanitizeSettings({ pbkdf2Iterations: msg?.iterations }).pbkdf2Iterations
    || (await readSettings()).pbkdf2Iterations;
  if (targetIters === auth.iterations) {
    return { rekeyed: false, reason: "already-at-target", iterations: targetIters };
  }

  // Decrypt note envelopes with the live key, then re-encrypt with the new key.
  const envelopes = await readEnvelopes();
  const auditEnvelopesIn = await readAuditEnvelopes();

  const { record: newAuth, key: newKey } = await buildSetupRecord(password, targetIters);

  const newNoteEnvelopes = [];
  let noteFails = 0;
  for (const env of envelopes) {
    try {
      const note = await decryptNote(currentKey, env);
      newNoteEnvelopes.push(await encryptNote(newKey, note));
    } catch (err) {
      console.warn("[auth-notes] rekey skipped unreadable note", env?.id, err);
      noteFails++;
    }
  }
  const newAuditEnvelopes = [];
  let auditFails = 0;
  for (const env of auditEnvelopesIn) {
    try {
      const event = await decryptAuditEvent(currentKey, env);
      newAuditEnvelopes.push(await encryptAuditEvent(newKey, event));
    } catch (err) {
      console.warn("[auth-notes] rekey skipped unreadable audit event", env?.id, err);
      auditFails++;
    }
  }

  // Commit atomically-ish: write auth + notes + audit together, then swap the
  // in-memory key. If any step throws above we have not touched storage yet.
  await chrome.storage.local.set({
    [STORAGE_KEY_AUTH]: newAuth,
    [STORAGE_KEY_NOTES]: newNoteEnvelopes,
    [STORAGE_KEY_AUDIT]: newAuditEnvelopes,
  });
  unlockedKey = newKey;
  await writeSettings({ pbkdf2Iterations: targetIters });
  try {
    await recordAuditEvent({
      type: "setup",
      detail: `rekey \u2192 ${targetIters.toLocaleString()} iters\u00b7${newNoteEnvelopes.length} notes` + (noteFails || auditFails ? ` (${noteFails + auditFails} unreadable)` : ""),
    });
  } catch (err) { console.warn("[auth-notes] audit rekey failed", err); }
  bumpActivity();
  await scheduleAutoLockAlarm();
  return {
    rekeyed: true,
    iterations: targetIters,
    notes: newNoteEnvelopes.length,
    auditEvents: newAuditEnvelopes.length,
    skipped: noteFails + auditFails,
  };
};

handlers["master:changePassword"] = async (msg) => {
  // Rotate the master password. Requires the live (unlocked) key and the
  // current password. Decrypts every note + audit envelope under the
  // current key, then re-encrypts them under a key derived from the new
  // password. Storage is committed in a single set() so a crash mid-rotation
  // either leaves the vault on the old password (handlers above this point
  // threw) or on the new one (set() completed).
  const currentKey = requireUnlocked();
  const currentPw = String(msg?.currentPassword || "");
  const newPw = String(msg?.newPassword || "");
  if (!currentPw) throw new Error("current master password required");
  if (newPw.length < 8) throw new Error("new password must be at least 8 characters");
  if (newPw === currentPw) throw new Error("new password must differ from current");
  const auth = await readAuth();
  if (!auth) throw new Error("master password not set");
  // Confirms `currentPw` actually opens the live vault. Throws on mismatch.
  await verifyPassword(currentPw, auth);

  const settings = await readSettings();
  const requestedIters = msg?.iterations != null
    ? sanitizeSettings({ pbkdf2Iterations: msg.iterations }).pbkdf2Iterations
    : null;
  const targetIters = requestedIters || settings.pbkdf2Iterations || auth.iterations || PBKDF2_ITERATIONS;

  const envelopes = await readEnvelopes();
  const auditEnvelopesIn = await readAuditEnvelopes();

  const { record: newAuth, key: newKey } = await buildSetupRecord(newPw, targetIters);

  const newNoteEnvelopes = [];
  let noteFails = 0;
  for (const env of envelopes) {
    try {
      const note = await decryptNote(currentKey, env);
      newNoteEnvelopes.push(await encryptNote(newKey, note));
    } catch (err) {
      console.warn("[auth-notes] changePassword skipped unreadable note", env?.id, err);
      noteFails++;
    }
  }
  const newAuditEnvelopes = [];
  let auditFails = 0;
  for (const env of auditEnvelopesIn) {
    try {
      const event = await decryptAuditEvent(currentKey, env);
      newAuditEnvelopes.push(await encryptAuditEvent(newKey, event));
    } catch (err) {
      console.warn("[auth-notes] changePassword skipped unreadable audit event", env?.id, err);
      auditFails++;
    }
  }

  await chrome.storage.local.set({
    [STORAGE_KEY_AUTH]: newAuth,
    [STORAGE_KEY_NOTES]: newNoteEnvelopes,
    [STORAGE_KEY_AUDIT]: newAuditEnvelopes,
  });
  unlockedKey = newKey;
  if (requestedIters && requestedIters !== settings.pbkdf2Iterations) {
    await writeSettings({ pbkdf2Iterations: requestedIters });
  }
  try {
    await recordAuditEvent({
      type: "setup",
      detail: `master password changed \u2022 ${newNoteEnvelopes.length} notes resealed`
        + (noteFails || auditFails ? ` (${noteFails + auditFails} unreadable)` : ""),
    });
  } catch (err) { console.warn("[auth-notes] audit changePassword failed", err); }
  bumpActivity();
  await scheduleAutoLockAlarm();
  return {
    changed: true,
    iterations: targetIters,
    notes: newNoteEnvelopes.length,
    auditEvents: newAuditEnvelopes.length,
    skipped: noteFails + auditFails,
  };
};

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
  await recordAuditEvent({ type: "backup:export", detail: `${envelopes.length} notes` });
  return {
    filename: `auth-notes-backup-${ts}.json.enc`,
    mime: "application/octet-stream",
    content: json,
    count: envelopes.length,
    exportedAt: payload.exportedAt,
  };
};

handlers["audit:list"] = async (msg) => {
  const key = requireUnlocked();
  const limit = Math.min(Math.max(Number(msg?.limit) || 100, 1), AUDIT_MAX);
  const envelopes = await readAuditEnvelopes();
  // Newest first.
  const sorted = envelopes.slice().sort((a, b) => (b.ts || 0) - (a.ts || 0));
  const out = [];
  for (const env of sorted) {
    if (out.length >= limit) break;
    try { out.push(await decryptAuditEvent(key, env)); }
    catch (err) { console.warn("[auth-notes] skip undecryptable audit", env.id, err); }
  }
  return { total: envelopes.length, events: out };
};

handlers["audit:clear"] = async () => {
  requireUnlocked();
  const prior = (await readAuditEnvelopes()).length;
  await chrome.storage.local.set({ [STORAGE_KEY_AUDIT]: [] });
  // Seed one sealed entry recording the clear so the log isn't silently empty.
  await recordAuditEvent({ type: "audit:clear", detail: `cleared ${prior} entries` });
  return { cleared: prior };
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
  await recordAuditEvent({
    type: "backup:import",
    detail: `${mode} • +${plan.added} ~${plan.replaced}${plan.discarded ? ` -${plan.discarded}` : ""}${failed ? ` (${failed} skipped)` : ""}`,
  });
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

handlers["notes:duplicates"] = async () => {
  const key = requireUnlocked();
  const envelopes = await readEnvelopes();
  const decrypted = [];
  for (const env of envelopes) {
    try { decrypted.push(await decryptNote(key, env)); }
    catch (err) { console.warn("[auth-notes] skip undecryptable note", env.id, err); }
  }
  const groups = findDuplicateEmails(decrypted).map((g) => ({
    email: g.email,
    count: g.count,
    notes: g.notes.map((n) => ({
      id: n.id,
      origin: n.origin,
      label: n.label || n.origin,
      authMethod: n.authMethod || "",
      twofaBackup: n.twofaBackup || "none",
      updatedAt: n.updatedAt || 0,
      lastUsedAt: Number.isFinite(n.lastUsedAt) ? n.lastUsedAt : null,
    })),
  }));
  return { groups, totalNotes: decrypted.length, totalGroups: groups.length };
};

handlers["notes:audit"] = async () => {
  const envelopes = await readEnvelopes();
  return auditEnvelopes(envelopes);
};

handlers["notes:schema"] = async () => ({
  authMethods: AUTH_METHODS,
  twofaBackups: TWOFA_BACKUPS,
  tagPresets: TAG_PRESETS,
});

handlers["notes:tags"] = async () => {
  const key = requireUnlocked();
  const envelopes = await readEnvelopes();
  const decrypted = [];
  for (const env of envelopes) {
    try { decrypted.push(await decryptNote(key, env)); }
    catch (err) { console.warn("[auth-notes] skip undecryptable note", env.id, err); }
  }
  return { tags: collectTags(decrypted), presets: TAG_PRESETS };
};

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
  // least one searchable field). `tag:foo` tokens are matched exactly against
  // the note's tags array. Other tokens fuzzy-match weighted fields.
  const rawTokens = q.split(/\s+/).filter(Boolean);
  const requiredTags = [];
  const tokens = [];
  for (const t of rawTokens) {
    if (t.startsWith("tag:")) {
      const tag = normalizeTag(t.slice(4));
      if (tag) requiredTags.push(tag);
    } else {
      tokens.push(t);
    }
  }
  const FIELD_WEIGHTS = [
    ["label", 5],
    ["origin", 4],
    ["email", 3],
    ["tags", 3],
    ["authMethod", 2],
    ["twofaBackup", 2],
    ["twofaDetail", 2],
    ["notes", 1],
  ];
  const scored = [];
  for (const note of decrypted) {
    const noteTags = Array.isArray(note.tags) ? note.tags.map((t) => String(t).toLowerCase()) : [];
    if (requiredTags.length > 0 && !requiredTags.every((t) => noteTags.includes(t))) continue;
    const fields = Object.fromEntries(
      FIELD_WEIGHTS.map(([k]) => [k, k === "tags" ? noteTags.join(" ") : String(note[k] || "").toLowerCase()])
    );
    let totalScore = requiredTags.length * 4; // baseline for matching required tags
    const hits = new Set();
    if (requiredTags.length > 0) hits.add("tags");
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
    if (allTokensMatched && (tokens.length > 0 || requiredTags.length > 0)) {
      scored.push({ note, score: totalScore, hits: [...hits] });
    }
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

/**
 * Bulk tag editor — apply an add/remove tag set to a list of notes by id.
 * The vault must be unlocked; each affected note is decrypted, mutated via
 * {@link applyBulkTags}, then re-sealed under the live key. A single audit
 * entry summarizes the change so the audit log doesn't flood with per-note
 * `note:update` events for one user action.
 */
handlers["notes:bulkTag"] = async (msg) => {
  const key = requireUnlocked();
  const ids = Array.isArray(msg?.ids) ? msg.ids.map((x) => String(x || "")).filter(Boolean) : [];
  if (ids.length === 0) throw new Error("select at least one note");
  const addList = normalizeTags(msg?.addTags);
  const removeList = normalizeTags(msg?.removeTags);
  if (addList.length === 0 && removeList.length === 0) {
    throw new Error("no tag changes specified");
  }
  const envelopes = await readEnvelopes();
  const now = Date.now();
  const idSet = new Set(ids);
  let changed = 0;
  let skipped = 0;
  for (let i = 0; i < envelopes.length; i++) {
    const env = envelopes[i];
    if (!idSet.has(env.id)) continue;
    let note;
    try { note = await decryptNote(key, env); }
    catch { skipped++; continue; }
    const result = applyBulkTags(note, { add: addList, remove: removeList, now });
    if (!result.changed) continue;
    envelopes[i] = await encryptNote(key, result.note);
    changed++;
  }
  if (changed > 0) await writeEnvelopes(envelopes);
  const parts = [];
  if (addList.length) parts.push(`+${addList.join(",")}`);
  if (removeList.length) parts.push(`-${removeList.join(",")}`);
  try {
    await recordAuditEvent({
      type: "note:update",
      detail: `bulk ${parts.join(" ")} \u2022 ${changed}/${ids.length} notes`,
    });
  } catch (err) { console.warn("[auth-notes] audit bulkTag failed", err); }
  return { requested: ids.length, changed, skipped, added: addList, removed: removeList };
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

/**
 * Bump a note's `lastUsedAt` timestamp. Called when the popup surfaces a
 * matching note for the current tab so the auto-sort puts frequently-revisited
 * sites at the top. The whole record is re-sealed under the unlocked key —
 * the storage envelope stays plaintext-clean by construction.
 *
 * Debounced at the envelope level: if the existing `lastUsedAt` is within the
 * minimum interval (30s) the call is a no-op to avoid storage churn every
 * time the popup is opened.
 */
const TOUCH_DEBOUNCE_MS = 30_000;
handlers["notes:touch"] = async (msg) => {
  const key = requireUnlocked();
  const id = String(msg?.id || "");
  if (!id) throw new Error("id is required");
  const envelopes = await readEnvelopes();
  const idx = envelopes.findIndex((e) => e.id === id);
  if (idx < 0) return { touched: false, reason: "not-found" };
  let note;
  try { note = await decryptNote(key, envelopes[idx]); }
  catch { return { touched: false, reason: "undecryptable" }; }
  const now = Date.now();
  if (Number.isFinite(note.lastUsedAt) && now - Number(note.lastUsedAt) < TOUCH_DEBOUNCE_MS) {
    return { touched: false, reason: "debounced", lastUsedAt: note.lastUsedAt };
  }
  const bumped = touchNoteLastUsed(note, { now });
  envelopes[idx] = await encryptNote(key, bumped);
  await writeEnvelopes(envelopes);
  return { touched: true, lastUsedAt: bumped.lastUsedAt };
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
