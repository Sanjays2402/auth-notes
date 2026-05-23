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
    createdAt: Number.isFinite(input.createdAt) ? input.createdAt : now,
    updatedAt: now,
  };
  return record;
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

/** Sort a list of decrypted notes by updatedAt desc, then label asc. */
export function sortNotes(list) {
  return [...list].sort((a, b) => {
    const dt = (b.updatedAt || 0) - (a.updatedAt || 0);
    if (dt !== 0) return dt;
    return String(a.label || "").localeCompare(String(b.label || ""));
  });
}
