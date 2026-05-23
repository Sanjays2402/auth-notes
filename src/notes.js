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

/** Auth-method filter groups. Used by the search view's quick-filter chips
 *  and by background search to interpret `auth:<group>` tokens. Each group
 *  maps a user-facing label onto one or more underlying `authMethod` values. */
export const AUTH_FILTER_GROUPS = Object.freeze([
  Object.freeze({ id: "password", label: "Password", methods: Object.freeze(["password"]) }),
  Object.freeze({ id: "passkey", label: "Passkey", methods: Object.freeze(["passkey"]) }),
  Object.freeze({ id: "oauth", label: "OAuth", methods: Object.freeze(["google", "github", "apple", "microsoft"]) }),
  Object.freeze({ id: "sso", label: "SSO", methods: Object.freeze(["sso"]) }),
]);

/** Resolve an auth-filter group id (e.g. "oauth") to the set of underlying
 *  authMethod values it covers. Returns null for unknown ids. */
export function authMethodsForFilterGroup(id) {
  const norm = String(id || "").trim().toLowerCase();
  if (!norm) return null;
  const g = AUTH_FILTER_GROUPS.find((x) => x.id === norm);
  return g ? [...g.methods] : null;
}

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

/** How many recent edits we keep per note. The diff log rides inside the
 *  AES-GCM payload (never the envelope) so older edits stay sealed at rest. */
export const HISTORY_MAX = 5;

/** Cap on the size of any single from/to value captured in a diff. Anything
 *  longer is clipped with a trailing ellipsis so a 4 KiB notes body doesn't
 *  balloon a 5-entry history into 40 KiB of payload. */
export const HISTORY_VALUE_MAX = 512;

/** Fields whose changes we record in the per-note edit log. The password
 *  hint, recovery codes and custom fields are intentionally treated as
 *  opaque "changed" markers in the diff so we never log secret material in
 *  the from/to fields. */
export const HISTORY_TRACKED_FIELDS = Object.freeze([
  "label", "origin", "authMethod", "email",
  "twofaBackup", "twofaDetail", "notes", "tags",
  "pinned", "passwordHint", "recoveryCodes", "customFields", "attachments",
]);

const HISTORY_OPAQUE_FIELDS = new Set(["passwordHint", "recoveryCodes", "customFields", "attachments"]);

function _clipForHistory(v) {
  if (v == null) return null;
  if (typeof v === "string") {
    return v.length > HISTORY_VALUE_MAX ? v.slice(0, HISTORY_VALUE_MAX) + "\u2026" : v;
  }
  if (Array.isArray(v)) return v.slice(0, TAG_MAX_COUNT).map((x) => _clipForHistory(x));
  if (typeof v === "object") return v; // opaque branch handles these
  return v;
}

function _sameHistoryValue(a, b) {
  if (a === b) return true;
  if (a == null && b == null) return true;
  if (a == null || b == null) return false;
  try { return JSON.stringify(a) === JSON.stringify(b); }
  catch { return false; }
}

/** Diff two note records → array of { field, from, to } changes for the
 *  subset of fields we track in the edit log. Secret-bearing fields are
 *  emitted as { field, changed: true } so the log never stores the value. */
export function diffNoteFields(prev, next) {
  const a = prev && typeof prev === "object" ? prev : {};
  const b = next && typeof next === "object" ? next : {};
  const out = [];
  for (const f of HISTORY_TRACKED_FIELDS) {
    const va = a[f];
    const vb = b[f];
    if (_sameHistoryValue(va == null ? null : va, vb == null ? null : vb)) continue;
    if (HISTORY_OPAQUE_FIELDS.has(f)) {
      out.push({ field: f, changed: true });
    } else {
      out.push({ field: f, from: _clipForHistory(va ?? null), to: _clipForHistory(vb ?? null) });
    }
  }
  return out;
}

/** Sanitize an arbitrary history array (e.g. from an imported payload) so
 *  forged fields can't ride into storage. Drops entries with no `changes`. */
export function normalizeHistory(input, { max = HISTORY_MAX } = {}) {
  if (!Array.isArray(input)) return [];
  const out = [];
  for (const entry of input) {
    if (!entry || typeof entry !== "object") continue;
    const ts = Number(entry.ts);
    if (!Number.isFinite(ts) || ts <= 0) continue;
    const rawChanges = Array.isArray(entry.changes) ? entry.changes : [];
    const changes = [];
    for (const c of rawChanges) {
      if (!c || typeof c !== "object") continue;
      const field = String(c.field || "");
      if (!HISTORY_TRACKED_FIELDS.includes(field)) continue;
      if (HISTORY_OPAQUE_FIELDS.has(field)) {
        changes.push({ field, changed: true });
      } else {
        changes.push({
          field,
          from: _clipForHistory(c.from == null ? null : c.from),
          to: _clipForHistory(c.to == null ? null : c.to),
        });
      }
    }
    if (changes.length === 0) continue;
    out.push({ ts, changes });
  }
  out.sort((x, y) => x.ts - y.ts);
  if (out.length > max) return out.slice(out.length - max);
  return out;
}

/** Append a diff entry capturing the prev→next transition to the prior
 *  note's history. Returns a fresh array bounded to `max` entries; the
 *  oldest entries roll off FIFO. Returns the prior history unchanged when
 *  the diff is empty so a no-op upsert doesn't pollute the log. */
export function appendNoteHistory(prev, next, { now = Date.now(), max = HISTORY_MAX } = {}) {
  const changes = diffNoteFields(prev || {}, next || {});
  const existing = normalizeHistory(prev?.history, { max });
  if (changes.length === 0) return existing;
  const entry = { ts: Number.isFinite(now) ? now : Date.now(), changes };
  const out = [...existing, entry];
  return out.length > max ? out.slice(out.length - max) : out;
}

/** Hard limits on per-note attachments (base64-encoded blobs like recovery
 *  code screenshots). Attachments live inside the encrypted payload (never
 *  on the envelope) so they ride the same AES-GCM seal as the rest of the
 *  note. These caps guard payload size; the whole record is still sealed. */
export const ATTACHMENT_MAX_COUNT = 4;
export const ATTACHMENT_NAME_MAX = 120;
export const ATTACHMENT_BYTES_MAX = 256 * 1024; // 256 KiB per attachment
export const ATTACHMENT_TOTAL_BYTES_MAX = 512 * 1024; // 512 KiB summed
export const ATTACHMENT_ALLOWED_MIME = Object.freeze([
  "image/png", "image/jpeg", "image/webp", "image/gif", "application/pdf", "text/plain",
]);

function _b64Bytes(b64) {
  if (typeof b64 !== "string" || !b64) return 0;
  // Strict-ish: count only base64 chars to estimate decoded length.
  const clean = b64.replace(/[^A-Za-z0-9+/=]/g, "");
  if (!clean) return 0;
  let pad = 0;
  if (clean.endsWith("==")) pad = 2;
  else if (clean.endsWith("=")) pad = 1;
  return Math.max(0, Math.floor((clean.length * 3) / 4) - pad);
}

function _normalizeAttachmentName(input, fallback = "attachment") {
  const s = String(input == null ? "" : input).replace(/[\r\n\t]+/g, " ").trim();
  const safe = (s || fallback).replace(/[\\/]+/g, "_");
  return safe.length > ATTACHMENT_NAME_MAX ? safe.slice(0, ATTACHMENT_NAME_MAX) : safe;
}

/** Normalize a single attachment entry. Returns null when the entry is
 *  unusable (missing data, oversized, wrong MIME). */
export function normalizeAttachment(input, { now = Date.now() } = {}) {
  if (!input || typeof input !== "object") return null;
  const mimeRaw = String(input.mimeType || "").trim().toLowerCase();
  if (!ATTACHMENT_ALLOWED_MIME.includes(mimeRaw)) return null;
  const data = typeof input.data === "string" ? input.data : "";
  if (!data) return null;
  const bytes = Number.isFinite(input.size) && input.size > 0 ? Math.round(input.size) : _b64Bytes(data);
  if (!bytes || bytes > ATTACHMENT_BYTES_MAX) return null;
  const name = _normalizeAttachmentName(input.name, mimeRaw.startsWith("image/") ? "screenshot" : "file");
  const addedAt = Number.isFinite(input.addedAt) ? Math.min(Number(input.addedAt), now) : now;
  return { name, mimeType: mimeRaw, data, size: bytes, addedAt };
}

/** Normalize a list of attachment entries. Drops invalid entries, caps by
 *  count and by total bytes, preserves insertion order. */
export function normalizeAttachments(input, { now = Date.now() } = {}) {
  if (input == null || input === "") return [];
  const raw = Array.isArray(input) ? input : [input];
  const out = [];
  let total = 0;
  for (const entry of raw) {
    const norm = normalizeAttachment(entry, { now });
    if (!norm) continue;
    if (total + norm.size > ATTACHMENT_TOTAL_BYTES_MAX) continue;
    out.push(norm);
    total += norm.size;
    if (out.length >= ATTACHMENT_MAX_COUNT) break;
  }
  return out;
}

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
  const attachments = normalizeAttachments(input.attachments, { now });
  if (attachments.length) record.attachments = attachments;
  if (Number.isFinite(input.lastUsedAt)) {
    // Don't allow future-dated timestamps; clamp to `now`.
    record.lastUsedAt = Math.min(Number(input.lastUsedAt), now);
  }
  if (input.pinned === true || input.pinned === "true" || input.pinned === 1) {
    record.pinned = true;
  }
  const history = normalizeHistory(input.history);
  if (history.length) record.history = history;
  if (Number.isFinite(input.deletedAt) && Number(input.deletedAt) > 0) {
    // Clamp to `now` so a forged future timestamp can't keep a note in trash
    // past the 30-day retention window.
    record.deletedAt = Math.min(Number(input.deletedAt), now);
  }
  return record;
}

/** Soft-delete retention: how long a trashed note lingers before becoming
 *  eligible for permanent purge. 30 days in milliseconds. */
export const TRASH_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;

/** True when a decrypted note carries a non-zero `deletedAt` stamp. Trashed
 *  notes are hidden from the main vault but kept sealed at rest until they
 *  are restored or permanently purged. */
export function isTrashed(note) {
  if (!note || typeof note !== "object") return false;
  const t = Number(note.deletedAt);
  return Number.isFinite(t) && t > 0;
}

/** Partition a list of decrypted notes into `active`, `trashed`, and
 *  `expired` buckets. `expired` is the subset of `trashed` whose retention
 *  window has elapsed and is therefore eligible for hard purge. */
export function partitionTrash(notes, { now = Date.now(), retentionMs = TRASH_RETENTION_MS } = {}) {
  const list = Array.isArray(notes) ? notes : [];
  const active = [];
  const trashed = [];
  const expired = [];
  for (const n of list) {
    if (!n || typeof n !== "object") continue;
    if (isTrashed(n)) {
      trashed.push(n);
      if (now - Number(n.deletedAt) >= retentionMs) expired.push(n);
    } else {
      active.push(n);
    }
  }
  return { active, trashed, expired };
}

/** Compute the time remaining (ms) before a trashed note auto-purges. Returns
 *  0 for items past the window. Non-trashed notes return null. */
export function trashTtlMs(note, { now = Date.now(), retentionMs = TRASH_RETENTION_MS } = {}) {
  if (!isTrashed(note)) return null;
  const left = retentionMs - (now - Number(note.deletedAt));
  return left > 0 ? left : 0;
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
  "attachments",
  "history",
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

/**
 * Vault Health Score — weighted security signals rolled into a single 0–100
 * read on the vault's hygiene.
 *
 * Pure function. Takes the same `notes` list `computeVaultStats` does
 * (decrypted, active — trashed notes already filtered upstream). Returns
 *
 *   {
 *     score: 0..100,            // weighted, signal-applicable aware
 *     grade: 'A+'..'F',
 *     total: notes.length,
 *     signals: [
 *       { id, label, weight, score, detail, applicable, total }
 *     ],
 *   }
 *
 * Signals (drop out of the denominator when `applicable === 0`):
 *  - twofa            (w 25): share of notes with a 2FA factor (passkey OR backup != none).
 *  - recoveryCodes    (w 20): share of 2FA notes that have at least one recovery code.
 *  - uniqueEmail      (w 20): share of email-bearing notes whose email isn't reused anywhere else.
 *  - passkey          (w 15): share of notes using a passkey (strongest auth signal).
 *  - passwordStrength (w 10): share of `password`-auth notes whose recorded hint bucket is good or strong.
 *  - freshness        (w 10): share of notes touched within the last 365 days.
 *
 * Score is `Σ(weight * signalScore) / Σ(weight where applicable)`, all on
 * 0..100. Empty vaults score 0 with `grade: '—'`. Each signal score is
 * itself a 0..100 share for readable per-row bars in the dashboard.
 */
export const VAULT_HEALTH_SIGNALS = Object.freeze([
  { id: "twofa", label: "2FA coverage", weight: 25 },
  { id: "recoveryCodes", label: "Recovery codes saved", weight: 20 },
  { id: "uniqueEmail", label: "Unique emails", weight: 20 },
  { id: "passkey", label: "Passkey adoption", weight: 15 },
  { id: "passwordStrength", label: "Strong passwords", weight: 10 },
  { id: "freshness", label: "Recently reviewed", weight: 10 },
]);

export const VAULT_HEALTH_FRESHNESS_MS = 365 * 24 * 60 * 60 * 1000;

function gradeForScore(score) {
  if (!Number.isFinite(score)) return "—";
  if (score >= 95) return "A+";
  if (score >= 90) return "A";
  if (score >= 85) return "A-";
  if (score >= 80) return "B+";
  if (score >= 75) return "B";
  if (score >= 70) return "B-";
  if (score >= 65) return "C+";
  if (score >= 60) return "C";
  if (score >= 55) return "C-";
  if (score >= 50) return "D";
  return "F";
}

export function computeVaultHealth(notes, { now = Date.now() } = {}) {
  const list = Array.isArray(notes) ? notes.filter((n) => n && typeof n === "object") : [];
  const total = list.length;
  if (total === 0) {
    return {
      score: 0,
      grade: "—",
      total: 0,
      signals: VAULT_HEALTH_SIGNALS.map((s) => ({
        ...s,
        score: 0,
        applicable: 0,
        total: 0,
        detail: "Add notes to start scoring.",
      })),
    };
  }

  // Pre-index reused emails (case-insensitive) so unique-email is O(n).
  const emailCount = new Map();
  for (const n of list) {
    const e = String(n.email || "").trim().toLowerCase();
    if (!e) continue;
    emailCount.set(e, (emailCount.get(e) || 0) + 1);
  }

  let twofaPass = 0;
  let twofaTotal = total;
  let recoveryPass = 0;
  let recoveryTotal = 0;
  let uniqueEmailPass = 0;
  let uniqueEmailTotal = 0;
  let passkeyPass = 0;
  let pwGoodPass = 0;
  let pwTotal = 0;
  let freshPass = 0;
  let freshTotal = 0;

  for (const n of list) {
    const auth = String(n.authMethod || "").toLowerCase();
    const backup = String(n.twofaBackup || "none").toLowerCase();
    const hasTwofa = auth === "passkey" || (backup && backup !== "none");
    if (hasTwofa) twofaPass++;
    if (hasTwofa) {
      recoveryTotal++;
      const codes = Array.isArray(n.recoveryCodes) ? n.recoveryCodes.filter(Boolean) : [];
      if (codes.length > 0) recoveryPass++;
    }
    const email = String(n.email || "").trim().toLowerCase();
    if (email) {
      uniqueEmailTotal++;
      if ((emailCount.get(email) || 0) <= 1) uniqueEmailPass++;
    }
    if (auth === "passkey") passkeyPass++;
    if (auth === "password") {
      pwTotal++;
      const bucket = String(n.passwordHint?.complexity || "").toLowerCase();
      if (bucket === "good" || bucket === "strong") pwGoodPass++;
    }
    const updated = Number(n.updatedAt);
    if (Number.isFinite(updated)) {
      freshTotal++;
      if (now - updated <= VAULT_HEALTH_FRESHNESS_MS) freshPass++;
    }
  }

  const pct = (a, b) => (b > 0 ? Math.round((a / b) * 100) : 0);
  const reusedGroups = Array.from(emailCount.values()).filter((c) => c > 1).length;
  const olderCount = freshTotal - freshPass;

  const detailFor = (id) => {
    switch (id) {
      case "twofa":
        return twofaPass === total
          ? `All ${total} note${total === 1 ? "" : "s"} have a 2FA factor.`
          : `${twofaTotal - twofaPass} of ${twofaTotal} note${twofaTotal === 1 ? "" : "s"} have no 2FA recorded.`;
      case "recoveryCodes":
        if (recoveryTotal === 0) return "No 2FA notes yet — nothing to back up.";
        return recoveryPass === recoveryTotal
          ? `Backup codes saved for all ${recoveryTotal} 2FA note${recoveryTotal === 1 ? "" : "s"}.`
          : `${recoveryTotal - recoveryPass} of ${recoveryTotal} 2FA note${recoveryTotal === 1 ? "" : "s"} missing recovery codes.`;
      case "uniqueEmail":
        if (uniqueEmailTotal === 0) return "No emails recorded.";
        return reusedGroups === 0
          ? `All ${uniqueEmailTotal} recorded email${uniqueEmailTotal === 1 ? " is" : "s are"} unique.`
          : `${reusedGroups} email${reusedGroups === 1 ? "" : "s"} reused across multiple sites.`;
      case "passkey":
        return passkeyPass > 0
          ? `${passkeyPass} of ${total} note${total === 1 ? "" : "s"} use a passkey.`
          : "No passkeys recorded — adopt where supported.";
      case "passwordStrength":
        if (pwTotal === 0) return "No password-auth notes — nothing to grade.";
        return pwGoodPass === pwTotal
          ? `All ${pwTotal} password note${pwTotal === 1 ? "" : "s"} rated good or strong.`
          : `${pwTotal - pwGoodPass} of ${pwTotal} password note${pwTotal === 1 ? "" : "s"} are weak or okay.`;
      case "freshness":
        if (freshTotal === 0) return "No timestamps yet.";
        return olderCount === 0
          ? `All notes touched in the last 12 months.`
          : `${olderCount} note${olderCount === 1 ? " hasn't" : "s haven't"} been reviewed in a year.`;
      default: return "";
    }
  };

  const signals = VAULT_HEALTH_SIGNALS.map((s) => {
    let pass = 0;
    let denom = 0;
    if (s.id === "twofa") { pass = twofaPass; denom = twofaTotal; }
    else if (s.id === "recoveryCodes") { pass = recoveryPass; denom = recoveryTotal; }
    else if (s.id === "uniqueEmail") { pass = uniqueEmailPass; denom = uniqueEmailTotal; }
    else if (s.id === "passkey") { pass = passkeyPass; denom = total; }
    else if (s.id === "passwordStrength") { pass = pwGoodPass; denom = pwTotal; }
    else if (s.id === "freshness") { pass = freshPass; denom = freshTotal; }
    const sig = {
      id: s.id,
      label: s.label,
      weight: s.weight,
      score: pct(pass, denom),
      applicable: denom,
      total: pass,
      detail: detailFor(s.id),
    };
    return sig;
  });

  let weighted = 0;
  let weightTotal = 0;
  for (const sig of signals) {
    if (sig.applicable === 0) continue;
    weighted += sig.weight * sig.score;
    weightTotal += sig.weight;
  }
  const score = weightTotal > 0 ? Math.round(weighted / weightTotal) : 0;
  return {
    score,
    grade: gradeForScore(score),
    total,
    signals,
  };
}

/**
 * Per-site security checklist. Given a single decrypted note and the full
 * (decrypted, active) list it lives in, return a pass/fail breakdown for the
 * three hygiene questions surfaced in the popup: is 2FA on?, is the email
 * used here unique across the vault?, and are recovery codes saved?
 *
 * Pure function — no storage, no crypto. Safe to call on every render.
 *
 *  - twofa: passes when the note's `authMethod` is `passkey` (the passkey IS
 *    the 2nd factor) OR `twofaBackup` is anything other than `none`/empty.
 *  - uniqueEmail: passes when `email` is set AND no OTHER active note in the
 *    vault uses the same email (case-insensitive). Notes without an email
 *    fail with an explanatory detail. Skipped (status "na") when the auth
 *    method is one where an email isn't meaningful (e.g. `passkey`, `sso`).
 *  - recoveryCodes: passes when `recoveryCodes` has at least one entry.
 *    Skipped when there is no 2FA configured (nothing to recover).
 *
 * Each item carries: { id, label, status, detail }. `status` is one of
 * `pass`, `fail`, `na`. Helpers below derive aggregate counts and a percent.
 */
export const SECURITY_CHECKLIST_IDS = Object.freeze(["twofa", "uniqueEmail", "recoveryCodes"]);

export function computeSecurityChecklist(note, allNotes = []) {
  if (!note || typeof note !== "object") {
    throw new Error("note must be an object");
  }
  const list = Array.isArray(allNotes) ? allNotes : [];
  const auth = String(note.authMethod || "").toLowerCase();
  const backup = String(note.twofaBackup || "none").toLowerCase();
  const hasTwofa = auth === "passkey" || (backup && backup !== "none");
  const codes = Array.isArray(note.recoveryCodes) ? note.recoveryCodes.filter(Boolean) : [];
  const emailRaw = String(note.email || "").trim();
  const emailKey = emailRaw.toLowerCase();

  // 2FA item
  const twofaItem = hasTwofa
    ? {
        id: "twofa",
        label: "2FA enabled",
        status: "pass",
        detail: auth === "passkey"
          ? "Passkey acts as the second factor"
          : `Backup via ${backup.replace(/-/g, " ")}`,
      }
    : {
        id: "twofa",
        label: "2FA enabled",
        status: "fail",
        detail: "No 2FA method recorded for this site",
      };

  // Unique email item
  let emailItem;
  if (auth === "passkey" || auth === "sso") {
    emailItem = {
      id: "uniqueEmail",
      label: "Unique email",
      status: "na",
      detail: `Not meaningful for ${auth === "sso" ? "SSO" : "passkey"} sign-in`,
    };
  } else if (!emailRaw) {
    emailItem = {
      id: "uniqueEmail",
      label: "Unique email",
      status: "fail",
      detail: "No email recorded",
    };
  } else {
    let sharedWith = 0;
    for (const other of list) {
      if (!other || typeof other !== "object") continue;
      if (other.id === note.id) continue;
      if (isTrashed(other)) continue;
      const otherEmail = String(other.email || "").trim().toLowerCase();
      if (otherEmail && otherEmail === emailKey) sharedWith++;
    }
    emailItem = sharedWith === 0
      ? {
          id: "uniqueEmail",
          label: "Unique email",
          status: "pass",
          detail: "Not reused on any other site in the vault",
        }
      : {
          id: "uniqueEmail",
          label: "Unique email",
          status: "fail",
          detail: `Also used on ${sharedWith} other site${sharedWith === 1 ? "" : "s"}`,
        };
  }

  // Recovery codes item
  let codesItem;
  if (!hasTwofa) {
    codesItem = {
      id: "recoveryCodes",
      label: "Recovery codes saved",
      status: "na",
      detail: "No 2FA configured — nothing to recover",
    };
  } else if (codes.length > 0) {
    codesItem = {
      id: "recoveryCodes",
      label: "Recovery codes saved",
      status: "pass",
      detail: `${codes.length} code${codes.length === 1 ? "" : "s"} stored`,
    };
  } else {
    codesItem = {
      id: "recoveryCodes",
      label: "Recovery codes saved",
      status: "fail",
      detail: "Add backup codes so a lost 2FA factor can't lock you out",
    };
  }

  const items = [twofaItem, emailItem, codesItem];
  const pass = items.filter((i) => i.status === "pass").length;
  const fail = items.filter((i) => i.status === "fail").length;
  const na = items.filter((i) => i.status === "na").length;
  const applicable = items.length - na;
  const score = applicable > 0 ? Math.round((pass / applicable) * 100) : 100;
  return { items, pass, fail, na, total: items.length, applicable, score };
}

export function sortNotes(list) {
  return [...list].sort((a, b) => {
    const pa = a && a.pinned ? 1 : 0;
    const pb = b && b.pinned ? 1 : 0;
    if (pa !== pb) return pb - pa;
    const dt = recencyOf(b) - recencyOf(a);
    if (dt !== 0) return dt;
    return String(a.label || "").localeCompare(String(b.label || ""));
  });
}

/** Partition a decrypted, already-sorted notes list into pinned/unpinned
 *  groups. Order within each group is preserved. */
export function partitionPinned(notes) {
  const list = Array.isArray(notes) ? notes : [];
  const pinned = [];
  const rest = [];
  for (const n of list) {
    if (n && n.pinned) pinned.push(n);
    else rest.push(n);
  }
  return { pinned, rest };
}
