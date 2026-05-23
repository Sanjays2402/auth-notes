// Auth Notes — per-site note record model
//
// A note captures, for a single site (origin), the auth method used,
// the email/identifier registered, where the 2FA backup is stored,
// and free-form notes. Each record is encrypted as a single AES-GCM
// blob before it ever touches chrome.storage.local.

import { encryptString, decryptString } from "./crypto.js";

export const NOTES_SCHEMA = 1;

/** Valid auth methods. Kept loose — UI can extend with `custom`. */
export const AUTH_METHODS = Object.freeze([
  "password",
  "passkey",
  "magic-link",
  "google",
  "github",
  "apple",
  "microsoft",
  "sso",
  "other",
]);

/** Suggested tag presets — UI surfaces these on quick-add and as filter chips. */
export const TAG_PRESETS = Object.freeze([
  "work",
  "personal",
  "banking",
  "shopping",
  "social",
  "dev",
  "infra",
  "family",
  "finance",
  "health",
]);

/** Password strength buckets. UI maps these onto the 0-4 strength score
 *  (`weak` covers scores 0-1, `okay` is 2, `good` is 3, `strong` is 4). */
export const PW_COMPLEXITY_BUCKETS = Object.freeze(["weak", "okay", "good", "strong"]);

/** Hard limit on the recorded password length. The number captures only
 *  *how long* a password is, never the password itself. */
export const PW_LENGTH_MAX = 256;

/** Normalize a password-strength hint input. Returns `null` when there is
 *  nothing useful to record so the caller can omit the field entirely.
 *  The hint stores ONLY a length bucket and a complexity bucket — never the
 *  password itself. The whole record still rides inside the AES-GCM payload,
 *  this just guarantees we cannot accidentally persist plaintext secrets. */
export function normalizePasswordHint(input) {
  if (input == null) return null;
  if (typeof input !== "object") return null;
  let length = null;
  if (input.length != null && input.length !== "") {
    const n = Number(input.length);
    if (Number.isFinite(n) && n > 0) {
      length = Math.max(1, Math.min(PW_LENGTH_MAX, Math.round(n)));
    }
  }
  let complexity = "";
  if (input.complexity != null) {
    const c = String(input.complexity).toLowerCase().trim();
    if (PW_COMPLEXITY_BUCKETS.includes(c)) complexity = c;
  }
  if (length == null && !complexity) return null;
  const out = {};
  if (length != null) out.length = length;
  if (complexity) out.complexity = complexity;
  return out;
}

/** Derive a complexity bucket from a password string. Used only at input
 *  time so the user doesn't have to pick the bucket by hand. The password
 *  string itself MUST be discarded by the caller immediately after. */
export function bucketForPassword(pw) {
  if (!pw) return "";
  let s = 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 12) s++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
  if (/\d/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  const score = Math.min(4, s);
  if (score <= 1) return "weak";
  if (score === 2) return "okay";
  if (score === 3) return "good";
  return "strong";
}

/** Hard limits on the tag field. Tags live inside the encrypted payload
 *  (never on the storage envelope) so these guard payload size, not crypto. */
export const TAG_MAX_COUNT = 12;
export const TAG_MAX_LEN = 32;

/** Hard limits on per-note custom fields (key/value pairs). Custom fields
 *  live inside the encrypted payload (never on the envelope). These caps
 *  guard payload size only; AES-GCM still seals the whole record. */
export const CUSTOM_FIELD_MAX_COUNT = 16;
export const CUSTOM_FIELD_KEY_MAX = 64;
export const CUSTOM_FIELD_VALUE_MAX = 2048;

/** Normalize a single custom-field key: trim, collapse internal whitespace,
 *  clip to {@link CUSTOM_FIELD_KEY_MAX}. Returns empty string for inputs
 *  that aren't useful as keys. Case is preserved so the user's casing
 *  ("API Key", "Account #") survives a round-trip. */
export function normalizeCustomFieldKey(input) {
  if (input == null) return "";
  const s = String(input).replace(/\s+/g, " ").trim();
  if (!s) return "";
  return s.length > CUSTOM_FIELD_KEY_MAX ? s.slice(0, CUSTOM_FIELD_KEY_MAX) : s;
}

/** Normalize a custom-fields input → array of { key, value }. Accepts an
 *  array of {key,value} entries, an array of [key,value] tuples, or a
 *  plain object. Entries with empty keys are dropped. Duplicate keys are
 *  resolved last-wins, preserving the order of first occurrence. Values
 *  are clipped to {@link CUSTOM_FIELD_VALUE_MAX}. */
export function normalizeCustomFields(input) {
  if (input == null || input === "") return [];
  let pairs;
  if (Array.isArray(input)) {
    pairs = input.map((entry) => {
      if (Array.isArray(entry)) return [entry[0], entry[1]];
      if (entry && typeof entry === "object") return [entry.key, entry.value];
      return [null, null];
    });
  } else if (typeof input === "object") {
    pairs = Object.entries(input);
  } else {
    return [];
  }
  const order = [];
  const byKey = new Map();
  for (const [rawKey, rawValue] of pairs) {
    const key = normalizeCustomFieldKey(rawKey);
    if (!key) continue;
    let value = rawValue == null ? "" : String(rawValue);
    if (value.length > CUSTOM_FIELD_VALUE_MAX) value = value.slice(0, CUSTOM_FIELD_VALUE_MAX);
    if (!byKey.has(key)) order.push(key);
    byKey.set(key, value);
    if (order.length > CUSTOM_FIELD_MAX_COUNT) break;
  }
  const out = [];
  for (const key of order) {
    if (out.length >= CUSTOM_FIELD_MAX_COUNT) break;
    out.push({ key, value: byKey.get(key) });
  }
  return out;
}

/** Hard limits on the recovery-codes field. Codes live inside the encrypted
 *  payload (never on the envelope). These caps guard payload size only;
 *  AES-GCM still seals the whole record. */
export const RECOVERY_CODE_MAX_COUNT = 32;
export const RECOVERY_CODE_MAX_LEN = 64;

/** Normalize a recovery-codes input (array | newline/comma string) → array.
 *  Trims, drops empties, dedups while preserving order. */
export function normalizeRecoveryCodes(input) {
  if (input == null || input === "") return [];
  let raw;
  if (Array.isArray(input)) raw = input;
  else if (typeof input === "string") raw = input.split(/[\r\n,]+/);
  else return [];
  const seen = new Set();
  const out = [];
  for (const item of raw) {
    if (item == null) continue;
    const code = String(item).trim();
    if (!code) continue;
    const clipped = code.length > RECOVERY_CODE_MAX_LEN ? code.slice(0, RECOVERY_CODE_MAX_LEN) : code;
    if (seen.has(clipped)) continue;
    seen.add(clipped);
    out.push(clipped);
    if (out.length >= RECOVERY_CODE_MAX_COUNT) break;
  }
  return out;
}

/** Render a code with most characters replaced by a masked dot. Keeps the
 *  first two and last two glyphs so the user can still tell codes apart at
 *  a glance without exposing the secret. */
export function maskRecoveryCode(code) {
  const s = String(code || "");
  if (!s) return "";
  if (s.length <= 4) return "\u2022".repeat(s.length);
  const head = s.slice(0, 2);
  const tail = s.slice(-2);
  const mid = "\u2022".repeat(Math.max(3, s.length - 4));
  return `${head}${mid}${tail}`;
}

/** Normalize a single tag: trim, lowercase, collapse whitespace, slug-ish.
 *  Returns empty string for inputs that aren't useful as tags. */
export function normalizeTag(input) {
  if (input == null) return "";
  const s = String(input).toLowerCase().trim().replace(/\s+/g, "-");
  // Allow letters, digits, dash, underscore, dot. Strip everything else.
  const cleaned = s.replace(/[^a-z0-9._-]+/g, "");
  if (!cleaned) return "";
  if (cleaned.length > TAG_MAX_LEN) return cleaned.slice(0, TAG_MAX_LEN);
  return cleaned;
}

/** Normalize a tags input (array | comma string | undefined) → deduped array. */
export function normalizeTags(input) {
  if (input == null || input === "") return [];
  let raw;
  if (Array.isArray(input)) raw = input;
  else if (typeof input === "string") raw = input.split(/[,\s]+/);
  else return [];
  const seen = new Set();
  const out = [];
  for (const item of raw) {
    const tag = normalizeTag(item);
    if (!tag || seen.has(tag)) continue;
    seen.add(tag);
    out.push(tag);
    if (out.length >= TAG_MAX_COUNT) break;
  }
  return out;
}

/** Aggregate tag usage across a list of decrypted notes. */
export function collectTags(notes) {
  const counts = new Map();
  if (!Array.isArray(notes)) return [];
  for (const n of notes) {
    if (!n || !Array.isArray(n.tags)) continue;
    for (const t of n.tags) {
      const tag = normalizeTag(t);
      if (!tag) continue;
      counts.set(tag, (counts.get(tag) || 0) + 1);
    }
  }
  return [...counts.entries()]
    .map(([tag, count]) => ({ tag, count }))
    .sort((a, b) => (b.count - a.count) || a.tag.localeCompare(b.tag));
}

/** Allowed 2FA backup locations. */
export const TWOFA_BACKUPS = Object.freeze([
  "none",
  "authenticator-app",
  "hardware-key",
  "sms",
  "email",
  "printed-codes",
  "password-manager",
  "other",
]);

const MAX_FIELD = 4096;
const MAX_LABEL = 200;
const MAX_ORIGIN = 512;

function trimStr(v, max) {
  if (v == null) return "";
  const s = String(v).trim();
  if (s.length > max) throw new Error(`field exceeds ${max} chars`);
  return s;
}

/** Best-effort hostname extraction for an arbitrary URL or hostname string. */
export function originOf(input) {
  if (!input) return "";
  const raw = String(input).trim();
  if (!raw) return "";
  try {
    const u = new URL(raw.includes("://") ? raw : `https://${raw}`);
    return u.hostname.toLowerCase();
  } catch {
    return raw.toLowerCase();
  }
}

/**
 * True when the URL targets a regular web page we can surface notes for.
 * Excludes chrome://, about:, file://, view-source:, devtools, extension pages, etc.
 */
export function isSupportedUrl(input) {
  if (!input) return false;
  let u;
  try { u = new URL(String(input)); }
  catch { return false; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return false;
  if (!u.hostname) return false;
  return true;
}

/** Strip a leading `www.` for display purposes only. Storage origin is unchanged. */
export function displayOrigin(origin) {
  const s = String(origin || "").toLowerCase();
  return s.startsWith("www.") ? s.slice(4) : s;
}

/** Generate a short, unguessable id. 16 random bytes → 22-char base64url. */
export function newId() {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

/**
 * Normalize and validate a note payload. Throws on invalid input.
 * Returns a fresh record with timestamps and a guaranteed id.
 */
export function normalizeNote(input, { now = Date.now() } = {}) {
  if (!input || typeof input !== "object") throw new Error("note must be an object");
  const origin = originOf(input.origin);
  if (!origin) throw new Error("origin is required");
  if (origin.length > MAX_ORIGIN) throw new Error("origin too long");

  const authMethod = trimStr(input.authMethod || "other", 64).toLowerCase();
  const twofaBackup = trimStr(input.twofaBackup || "none", 64).toLowerCase();

  const record = {
    id: typeof input.id === "string" && input.id ? input.id : newId(),
    schema: NOTES_SCHEMA,
    origin,
    label: trimStr(input.label || origin, MAX_LABEL),
    authMethod,
    email: trimStr(input.email, MAX_FIELD),
    twofaBackup,
    twofaDetail: trimStr(input.twofaDetail, MAX_FIELD),
    notes: trimStr(input.notes, MAX_FIELD * 4),
    tags: normalizeTags(input.tags),
    createdAt: Number.isFinite(input.createdAt) ? input.createdAt : now,
    updatedAt: now,
  };
  const hint = normalizePasswordHint(input.passwordHint);
  if (hint) record.passwordHint = hint;
  const codes = normalizeRecoveryCodes(input.recoveryCodes);
  if (codes.length) record.recoveryCodes = codes;
  const customFields = normalizeCustomFields(input.customFields);
  if (customFields.length) record.customFields = customFields;
  if (Number.isFinite(input.lastUsedAt)) {
    // Don't allow future-dated timestamps; clamp to `now`.
    record.lastUsedAt = Math.min(Number(input.lastUsedAt), now);
  }
  return record;
}

/** Apply a bulk tag mutation to a note: returns a new note with `add` tags
 *  unioned in (preserving existing order) and `remove` tags filtered out.
 *  Tag inputs are normalized via {@link normalizeTags}. The total tag count is
 *  capped at {@link TAG_MAX_COUNT}; overflow is dropped silently. The result
 *  bumps `updatedAt` to `now` because the note's payload changed. */
export function applyBulkTags(note, { add = [], remove = [], now = Date.now() } = {}) {
  if (!note || typeof note !== "object") throw new Error("note required");
  const current = Array.isArray(note.tags) ? note.tags : [];
  const addList = normalizeTags(add);
  const removeSet = new Set(normalizeTags(remove));
  const seen = new Set();
  const next = [];
  const push = (tag) => {
    const t = normalizeTag(tag);
    if (!t || removeSet.has(t) || seen.has(t)) return;
    seen.add(t);
    next.push(t);
  };
  for (const t of current) push(t);
  for (const t of addList) push(t);
  const capped = next.slice(0, TAG_MAX_COUNT);
  const changed =
    capped.length !== current.length ||
    capped.some((t, i) => t !== current[i]);
  return { note: { ...note, tags: capped, updatedAt: changed ? now : (note.updatedAt || now) }, changed };
}

/** Bump a note's `lastUsedAt` to `now` without mutating other fields. Returns
 *  a fresh record so callers can re-encrypt without aliasing surprises. The
 *  caller is responsible for re-sealing the result; this never touches
 *  `updatedAt` because "last used" is a separate axis from "last edited". */
export function touchNoteLastUsed(record, { now = Date.now() } = {}) {
  if (!record || typeof record !== "object") throw new Error("record required");
  return { ...record, lastUsedAt: now };
}

/** Encrypt a normalized note → { id, origin, iv, ct }. Origin is kept in plaintext
 *  ONLY for fast indexed lookup; sensitive fields live inside the ciphertext. */
export async function encryptNote(key, record) {
  const json = JSON.stringify(record);
  const payload = await encryptString(key, json);
  return { id: record.id, origin: record.origin, iv: payload.iv, ct: payload.ct };
}

/** Decrypt a stored note envelope back into a full record. */
export async function decryptNote(key, envelope) {
  if (!envelope || typeof envelope !== "object") throw new Error("bad envelope");
  const json = await decryptString(key, { iv: envelope.iv, ct: envelope.ct });
  const obj = JSON.parse(json);
  if (!obj || typeof obj !== "object") throw new Error("bad note payload");
  return obj;
}

/** Fields that are allowed to appear on a stored envelope. Anything else
 *  is treated as a plaintext leak and rejected before write. */
export const ENVELOPE_ALLOWED_KEYS = Object.freeze(["id", "origin", "iv", "ct"]);

/** Fields that must NEVER appear in plaintext at rest. */
export const ENVELOPE_FORBIDDEN_KEYS = Object.freeze([
  "label",
  "email",
  "authMethod",
  "twofaBackup",
  "twofaDetail",
  "notes",
  "tags",
  "passwordHint",
  "recoveryCodes",
  "customFields",
  "createdAt",
  "updatedAt",
]);

/**
 * Throws if the envelope shape would leak plaintext sensitive fields at rest.
 * Only `id`, `origin`, `iv`, `ct` are permitted. The first three are indexes;
 * `ct` is the AES-GCM ciphertext. Everything else is forbidden.
 */
export function assertEnvelopeSealed(envelope) {
  if (!envelope || typeof envelope !== "object") {
    throw new Error("envelope must be an object");
  }
  for (const k of ENVELOPE_ALLOWED_KEYS) {
    if (typeof envelope[k] !== "string" || envelope[k].length === 0) {
      throw new Error(`envelope missing required field: ${k}`);
    }
  }
  for (const k of Object.keys(envelope)) {
    if (!ENVELOPE_ALLOWED_KEYS.includes(k)) {
      throw new Error(`envelope leaks plaintext field: ${k}`);
    }
  }
}

/**
 * Audit a list of stored envelopes. Returns { total, leaks, sealed }.
 * `leaks` lists envelopes with any forbidden plaintext keys.
 */
export function auditEnvelopes(envelopes) {
  const list = Array.isArray(envelopes) ? envelopes : [];
  const leaks = [];
  for (const env of list) {
    if (!env || typeof env !== "object") continue;
    const bad = Object.keys(env).filter((k) => !ENVELOPE_ALLOWED_KEYS.includes(k));
    if (bad.length > 0) leaks.push({ id: env.id || null, fields: bad });
  }
  return { total: list.length, leaks, sealed: list.length - leaks.length };
}

/** Backup file constants. Must match the exporter in background.js. */
export const BACKUP_FORMAT = "auth-notes-backup";
export const BACKUP_SCHEMA = 1;
const BACKUP_MAX_BYTES = 8 * 1024 * 1024; // 8 MiB sanity cap

/**
 * Parse and validate a backup file's textual contents. Returns the parsed
 * payload, or throws a descriptive Error if the file is unrecognized.
 * This intentionally does NO crypto — call {@link verifyPassword} with
 * the returned `auth` record to obtain the backup's derived key.
 */
export function decodeBackupContent(content) {
  if (typeof content !== "string" || content.length === 0) {
    throw new Error("backup file is empty");
  }
  if (content.length > BACKUP_MAX_BYTES) {
    throw new Error("backup file is too large");
  }
  let payload;
  try { payload = JSON.parse(content); }
  catch { throw new Error("backup file is not valid JSON"); }
  if (!payload || typeof payload !== "object") {
    throw new Error("backup payload malformed");
  }
  if (payload.format !== BACKUP_FORMAT) {
    throw new Error("not an Auth Notes backup file");
  }
  if (payload.schema !== BACKUP_SCHEMA) {
    throw new Error(`unsupported backup schema: ${payload.schema}`);
  }
  if (!payload.auth || typeof payload.auth !== "object" ||
      typeof payload.auth.salt !== "string" ||
      !payload.auth.verifier || typeof payload.auth.verifier !== "object") {
    throw new Error("backup is missing its auth record");
  }
  if (!Array.isArray(payload.envelopes)) {
    throw new Error("backup is missing its envelopes");
  }
  // Sealed-at-rest invariant: a legitimate export never carries plaintext.
  for (const env of payload.envelopes) assertEnvelopeSealed(env);
  return payload;
}

/**
 * Plan an import: given the existing envelopes and the backup's envelopes,
 * decide which incoming entries replace existing ones (by id) and which are
 * appended. In `replace` mode the existing set is discarded entirely.
 * Returns counts only — the caller is responsible for the actual re-encrypt
 * step because keys must never leave the service worker boundary.
 */
export function planImport(existing, incoming, mode = "merge") {
  const cur = Array.isArray(existing) ? existing : [];
  const inc = Array.isArray(incoming) ? incoming : [];
  if (mode !== "merge" && mode !== "replace") {
    throw new Error(`unknown import mode: ${mode}`);
  }
  const existingIds = new Set(cur.map((e) => e && e.id).filter(Boolean));
  let replaced = 0;
  let added = 0;
  for (const env of inc) {
    if (!env || typeof env.id !== "string") continue;
    if (mode === "merge" && existingIds.has(env.id)) replaced++;
    else added++;
  }
  return {
    mode,
    total: inc.length,
    added,
    replaced,
    discarded: mode === "replace" ? cur.length : 0,
  };
}

// --- Audit log --------------------------------------------------------

/** Recognised audit event types. Anything else is rejected to keep the log
 *  small and predictable. */
export const AUDIT_EVENT_TYPES = Object.freeze([
  "setup",
  "unlock",
  "lock",
  "auto-lock",
  "note:create",
  "note:update",
  "note:delete",
  "note:view",
  "backup:export",
  "backup:import",
  "audit:clear",
]);

export const AUDIT_SCHEMA = 1;
/** Hard cap on stored audit envelopes. Old entries roll off FIFO. */
export const AUDIT_MAX = 500;
const AUDIT_DETAIL_MAX = 256;

/** Fields allowed on a stored audit envelope. `ts` is plaintext so the log
 *  can be sorted/paginated without decrypting every entry; everything that
 *  reveals user data lives inside `ct`. */
export const AUDIT_ENVELOPE_ALLOWED_KEYS = Object.freeze(["id", "ts", "iv", "ct"]);

/** Normalize an audit event input → record. Throws on unknown type. */
export function normalizeAuditEvent(input, { now = Date.now() } = {}) {
  if (!input || typeof input !== "object") throw new Error("audit event must be an object");
  const type = String(input.type || "").toLowerCase();
  if (!AUDIT_EVENT_TYPES.includes(type)) throw new Error(`unknown audit event type: ${type}`);
  const ts = Number.isFinite(input.ts) ? input.ts : now;
  const record = {
    id: typeof input.id === "string" && input.id ? input.id : newId(),
    schema: AUDIT_SCHEMA,
    type,
    ts,
  };
  if (input.origin) {
    const o = originOf(input.origin);
    if (o) record.origin = o.slice(0, MAX_ORIGIN);
  }
  if (input.noteId) record.noteId = String(input.noteId).slice(0, 64);
  if (input.detail != null && input.detail !== "") {
    record.detail = String(input.detail).slice(0, AUDIT_DETAIL_MAX);
  }
  return record;
}

/** Encrypt an audit record → { id, ts, iv, ct }. ts stays plaintext so the
 *  popup can render times without decrypting. */
export async function encryptAuditEvent(key, record) {
  const json = JSON.stringify(record);
  const payload = await encryptString(key, json);
  return { id: record.id, ts: record.ts, iv: payload.iv, ct: payload.ct };
}

/** Decrypt an audit envelope back into its record. */
export async function decryptAuditEvent(key, envelope) {
  if (!envelope || typeof envelope !== "object") throw new Error("bad audit envelope");
  const json = await decryptString(key, { iv: envelope.iv, ct: envelope.ct });
  const obj = JSON.parse(json);
  if (!obj || typeof obj !== "object") throw new Error("bad audit payload");
  return obj;
}

/** Throws if an audit envelope would leak sensitive plaintext at rest. */
export function assertAuditEnvelopeSealed(envelope) {
  if (!envelope || typeof envelope !== "object") {
    throw new Error("audit envelope must be an object");
  }
  for (const k of AUDIT_ENVELOPE_ALLOWED_KEYS) {
    if (k === "ts") {
      if (!Number.isFinite(envelope.ts)) throw new Error("audit envelope missing required field: ts");
    } else if (typeof envelope[k] !== "string" || envelope[k].length === 0) {
      throw new Error(`audit envelope missing required field: ${k}`);
    }
  }
  for (const k of Object.keys(envelope)) {
    if (!AUDIT_ENVELOPE_ALLOWED_KEYS.includes(k)) {
      throw new Error(`audit envelope leaks plaintext field: ${k}`);
    }
  }
}

/** Trim an audit envelope list to `AUDIT_MAX`, keeping newest by `ts`. */
export function trimAuditLog(envelopes, max = AUDIT_MAX) {
  const list = Array.isArray(envelopes) ? envelopes.slice() : [];
  list.sort((a, b) => (a.ts || 0) - (b.ts || 0));
  if (list.length <= max) return list;
  return list.slice(list.length - max);
}

/** Sort a list of decrypted notes by recency. `lastUsedAt` wins when present,
 *  otherwise the note's `updatedAt` carries the slot. Ties break on label asc. */
export function recencyOf(note) {
  if (!note) return 0;
  const used = Number(note.lastUsedAt);
  if (Number.isFinite(used) && used > 0) return used;
  return Number(note.updatedAt) || 0;
}

/** Find groups of decrypted notes sharing the same email/identifier. Useful
 *  as a security-hygiene check: spotting reused identities across sites flags
 *  blast-radius risks (one compromised inbox unlocks many places). Email is
 *  matched case-insensitively after trimming surrounding whitespace; empty
 *  emails are ignored. Groups are returned sorted by group size desc, then
 *  alphabetically by email. Notes inside each group keep their input order. */
export function findDuplicateEmails(notes, { minCount = 2 } = {}) {
  if (!Array.isArray(notes)) return [];
  const min = Math.max(2, Math.floor(Number(minCount) || 2));
  const groups = new Map();
  for (const note of notes) {
    if (!note || typeof note !== "object") continue;
    const raw = String(note.email || "").trim();
    if (!raw) continue;
    const key = raw.toLowerCase();
    let g = groups.get(key);
    if (!g) { g = { email: raw, notes: [] }; groups.set(key, g); }
    g.notes.push(note);
  }
  const out = [];
  for (const g of groups.values()) {
    if (g.notes.length < min) continue;
    out.push({ email: g.email, count: g.notes.length, notes: g.notes });
  }
  out.sort((a, b) => (b.count - a.count) || a.email.localeCompare(b.email));
  return out;
}

/**
 * Compute a snapshot of vault-wide statistics from a list of decrypted notes.
 * Pure function — does not touch storage or crypto. The popup renders this
 * straight into the Vault Stats dashboard.
 *
 * Returned shape:
 *  - total: number of notes
 *  - twofa: { covered, uncovered, coveragePct, byBackup: [{ key, count, pct }] }
 *  - byAuthMethod: [{ key, count, pct }] — sorted desc by count
 *  - oldest, newest: { id, label, origin, createdAt } | null
 *  - mostStale: { id, label, origin, updatedAt } | null — oldest by updatedAt
 *  - tags: { unique, total }
 *  - recoveryCodes: count of notes with at least one recovery code
 *  - passkey: count of notes whose authMethod is `passkey`
 *  - duplicateEmails: number of reused-email groups
 *  - emails: { withEmail, withoutEmail }
 */
export function computeVaultStats(notes) {
  const list = Array.isArray(notes) ? notes.filter((n) => n && typeof n === "object") : [];
  const total = list.length;
  const byAuth = new Map();
  const byBackup = new Map();
  const tagSet = new Set();
  let tagTotal = 0;
  let covered = 0;
  let recoveryCount = 0;
  let passkeyCount = 0;
  let withEmail = 0;
  let oldest = null;
  let newest = null;
  let stale = null;
  for (const n of list) {
    const auth = String(n.authMethod || "other").toLowerCase() || "other";
    byAuth.set(auth, (byAuth.get(auth) || 0) + 1);
    const backup = String(n.twofaBackup || "none").toLowerCase() || "none";
    byBackup.set(backup, (byBackup.get(backup) || 0) + 1);
    if (backup !== "none") covered++;
    if (auth === "passkey") passkeyCount++;
    if (Array.isArray(n.recoveryCodes) && n.recoveryCodes.length > 0) recoveryCount++;
    if (String(n.email || "").trim()) withEmail++;
    if (Array.isArray(n.tags)) {
      tagTotal += n.tags.length;
      for (const t of n.tags) if (t) tagSet.add(t);
    }
    const created = Number(n.createdAt);
    if (Number.isFinite(created)) {
      const stamp = { id: n.id, label: n.label || n.origin, origin: n.origin, createdAt: created };
      if (!oldest || created < oldest.createdAt) oldest = stamp;
      if (!newest || created > newest.createdAt) newest = stamp;
    }
    const updated = Number(n.updatedAt);
    if (Number.isFinite(updated)) {
      const stamp = { id: n.id, label: n.label || n.origin, origin: n.origin, updatedAt: updated };
      if (!stale || updated < stale.updatedAt) stale = stamp;
    }
  }
  const toBreakdown = (m) => Array.from(m.entries())
    .map(([key, count]) => ({
      key,
      count,
      pct: total > 0 ? Math.round((count / total) * 100) : 0,
    }))
    .sort((a, b) => (b.count - a.count) || a.key.localeCompare(b.key));
  return {
    total,
    twofa: {
      covered,
      uncovered: total - covered,
      coveragePct: total > 0 ? Math.round((covered / total) * 100) : 0,
      byBackup: toBreakdown(byBackup),
    },
    byAuthMethod: toBreakdown(byAuth),
    oldest,
    newest,
    mostStale: stale,
    tags: { unique: tagSet.size, total: tagTotal },
    recoveryCodes: recoveryCount,
    passkey: passkeyCount,
    duplicateEmails: findDuplicateEmails(list).length,
    emails: { withEmail, withoutEmail: total - withEmail },
  };
}

export function sortNotes(list) {
  return [...list].sort((a, b) => {
    const dt = recencyOf(b) - recencyOf(a);
    if (dt !== 0) return dt;
    return String(a.label || "").localeCompare(String(b.label || ""));
  });
}
