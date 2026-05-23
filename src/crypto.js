// Auth Notes — crypto primitives
// PBKDF2 (SHA-256) → AES-GCM 256. All key material stays in memory only.
// Persisted state: salt, iteration count, schema, and an encrypted verifier
// canary used to confirm a candidate password unlocks the vault.

export const CRYPTO_SCHEMA = 1;
export const PBKDF2_ITERATIONS = 250_000;
export const SALT_BYTES = 16;
export const IV_BYTES = 12;
export const VERIFIER_PLAINTEXT = "auth-notes://verifier/v1";

const enc = new TextEncoder();
const dec = new TextDecoder();

/** Convert Uint8Array → base64 (works in DOM + service worker). */
export function bytesToB64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

/** Convert base64 → Uint8Array. */
export function b64ToBytes(b64) {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/** Generate `n` cryptographically random bytes. */
export function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

/** Import a UTF-8 password as a non-extractable PBKDF2 base key. */
async function importPasswordKey(password) {
  return crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
}

/**
 * Derive an AES-GCM 256 key from a password + salt.
 * Returns a non-extractable CryptoKey suitable for encrypt/decrypt.
 */
export async function deriveKey(password, salt, iterations = PBKDF2_ITERATIONS) {
  if (typeof password !== "string" || password.length === 0) {
    throw new Error("password must be a non-empty string");
  }
  if (!(salt instanceof Uint8Array) || salt.length < 8) {
    throw new Error("salt must be a Uint8Array of >=8 bytes");
  }
  const base = await importPasswordKey(password);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/** Encrypt UTF-8 plaintext with AES-GCM. Returns { iv, ct } as base64 strings. */
export async function encryptString(key, plaintext) {
  const iv = randomBytes(IV_BYTES);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext))
  );
  return { iv: bytesToB64(iv), ct: bytesToB64(ct) };
}

/** Decrypt an { iv, ct } record produced by `encryptString`. */
export async function decryptString(key, payload) {
  if (!payload || typeof payload.iv !== "string" || typeof payload.ct !== "string") {
    throw new Error("invalid ciphertext payload");
  }
  const iv = b64ToBytes(payload.iv);
  const ct = b64ToBytes(payload.ct);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return dec.decode(pt);
}

/**
 * Build the persistable setup record from a fresh master password.
 * Stores the salt + iteration count + an encrypted canary verifier.
 * The derived key is returned separately and should be held in memory only.
 */
export async function buildSetupRecord(password) {
  const salt = randomBytes(SALT_BYTES);
  const key = await deriveKey(password, salt);
  const verifier = await encryptString(key, VERIFIER_PLAINTEXT);
  return {
    record: {
      schema: CRYPTO_SCHEMA,
      kdf: "PBKDF2-SHA256",
      iterations: PBKDF2_ITERATIONS,
      salt: bytesToB64(salt),
      verifier,
      createdAt: Date.now(),
    },
    key,
  };
}

/**
 * Verify a candidate password against a previously stored setup record.
 * Resolves to the derived CryptoKey on success, throws on failure.
 */
export async function verifyPassword(password, record) {
  if (!record || typeof record !== "object") throw new Error("missing record");
  const salt = b64ToBytes(record.salt);
  const key = await deriveKey(password, salt, record.iterations || PBKDF2_ITERATIONS);
  const plain = await decryptString(key, record.verifier);
  if (plain !== VERIFIER_PLAINTEXT) throw new Error("verifier mismatch");
  return key;
}
