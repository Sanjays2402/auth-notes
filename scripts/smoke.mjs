// Smoke test: validates manifest shape, required files, and crypto round-trip.
import fs from "node:fs";

// --- Manifest + file presence ---
const m = JSON.parse(fs.readFileSync("manifest.json", "utf8"));
const must = ["manifest_version", "name", "version", "description"];
for (const k of must) if (!m[k]) { console.error("missing manifest key:", k); process.exit(1); }
if (m.manifest_version !== 3) { console.error("manifest_version must be 3"); process.exit(1); }
for (const p of [
  "src/popup.html",
  "src/popup.js",
  "src/popup.css",
  "src/background.js",
  "src/crypto.js",
  "src/notes.js",
]) if (!fs.existsSync(p)) { console.error("missing file:", p); process.exit(1); }
for (const sz of [16, 32, 48, 128])
  if (!fs.existsSync(`icons/icon-${sz}.png`)) { console.error("missing icon:", sz); process.exit(1); }

// --- Crypto round-trip (WebCrypto available in Node 20+) ---
if (typeof crypto?.subtle?.deriveKey !== "function") {
  console.error("WebCrypto subtle.deriveKey unavailable in this Node runtime");
  process.exit(1);
}

const mod = await import("../src/crypto.js");
const password = "correct-horse-battery-staple";

// Fast iteration count for tests — crypto module exposes deriveKey with override.
const { record, key } = await mod.buildSetupRecord(password);
if (record.schema !== mod.CRYPTO_SCHEMA) { console.error("schema mismatch"); process.exit(1); }
if (!record.salt || !record.verifier?.iv || !record.verifier?.ct) {
  console.error("setup record missing fields"); process.exit(1);
}

// Verify correct password unlocks
const key2 = await mod.verifyPassword(password, record);
const probe = await mod.encryptString(key, "hello");
const out = await mod.decryptString(key2, probe);
if (out !== "hello") { console.error("crypto round-trip failed"); process.exit(1); }

// Verify wrong password fails
let rejected = false;
try { await mod.verifyPassword("wrong-password", record); }
catch { rejected = true; }
if (!rejected) { console.error("wrong password should have failed"); process.exit(1); }

// --- Notes model round-trip ---
const notes = await import("../src/notes.js");
const norm = notes.normalizeNote({
  origin: "https://github.com/login",
  authMethod: "passkey",
  email: "me@example.com",
  twofaBackup: "hardware-key",
  twofaDetail: "YubiKey 5C in desk drawer",
  notes: "primary identity",
});
if (norm.origin !== "github.com") { console.error("origin not normalized"); process.exit(1); }
if (!norm.id || norm.id.length < 10) { console.error("missing id"); process.exit(1); }
if (!norm.createdAt || !norm.updatedAt) { console.error("missing timestamps"); process.exit(1); }

const env = await notes.encryptNote(key, norm);
if (env.origin !== "github.com") { console.error("envelope origin"); process.exit(1); }
if (!env.iv || !env.ct) { console.error("envelope missing ciphertext"); process.exit(1); }
if (env.email || env.notes || env.twofaDetail) {
  console.error("sensitive fields leaked into envelope"); process.exit(1);
}
const back = await notes.decryptNote(key, env);
if (back.email !== "me@example.com" || back.twofaDetail !== "YubiKey 5C in desk drawer") {
  console.error("note round-trip mismatch"); process.exit(1);
}

let originRejected = false;
try { notes.normalizeNote({ origin: "", authMethod: "password" }); }
catch { originRejected = true; }
if (!originRejected) { console.error("empty origin should reject"); process.exit(1); }

const sorted = notes.sortNotes([
  { label: "a", updatedAt: 1 },
  { label: "b", updatedAt: 5 },
  { label: "c", updatedAt: 3 },
]);
if (sorted[0].label !== "b" || sorted[2].label !== "a") {
  console.error("sort order wrong"); process.exit(1);
}

// --- Encrypted-at-rest invariants ---
notes.assertEnvelopeSealed(env);

let leakRejected = false;
try { notes.assertEnvelopeSealed({ ...env, email: "leak@example.com" }); }
catch { leakRejected = true; }
if (!leakRejected) { console.error("sealed-envelope leak should reject"); process.exit(1); }

let missingRejected = false;
try { notes.assertEnvelopeSealed({ id: env.id, origin: env.origin, iv: env.iv }); }
catch { missingRejected = true; }
if (!missingRejected) { console.error("missing ct should reject"); process.exit(1); }

const audit = notes.auditEnvelopes([env, { id: "x", origin: "a", iv: "i", ct: "c", notes: "plaintext!" }]);
if (audit.total !== 2 || audit.sealed !== 1 || audit.leaks.length !== 1) {
  console.error("auditEnvelopes wrong", audit); process.exit(1);
}
if (!audit.leaks[0].fields.includes("notes")) {
  console.error("audit leak field missing", audit.leaks[0]); process.exit(1);
}

// --- Lock/unlock UI wiring (static check) ---
const popupHtml = fs.readFileSync("src/popup.html", "utf8");
const popupJs = fs.readFileSync("src/popup.js", "utf8");
for (const needle of ["view-lock", "unlock-form", "unlock-pw", "lock-btn"]) {
  if (!popupHtml.includes(needle)) { console.error("popup.html missing", needle); process.exit(1); }
}
for (const needle of ["master:verify", "master:lock", "bindUnlockForm", "lockVault"]) {
  if (!popupJs.includes(needle)) { console.error("popup.js missing", needle); process.exit(1); }
}

// --- Auto-lock idle settings ---
const manifestText = fs.readFileSync("manifest.json", "utf8");
const manifest = JSON.parse(manifestText);
if (!Array.isArray(manifest.permissions) || !manifest.permissions.includes("alarms")) {
  console.error("manifest missing 'alarms' permission for auto-lock"); process.exit(1);
}
const bgSrc = fs.readFileSync("src/background.js", "utf8");
for (const needle of [
  "settings:get", "settings:set", "chrome.alarms", "scheduleAutoLockAlarm",
  "performAutoLock", "lastActivityAt", "idleTimeoutMin",
]) {
  if (!bgSrc.includes(needle)) { console.error("background.js missing", needle); process.exit(1); }
}
for (const needle of ["view-settings", "idle-select", "settings-back"]) {
  if (!popupHtml.includes(needle)) { console.error("popup.html missing", needle); process.exit(1); }
}
for (const needle of ["settings:get", "settings:set", "openSettings", "idleSummaryText"]) {
  if (!popupJs.includes(needle)) { console.error("popup.js missing", needle); process.exit(1); }
}

// --- Encrypted backup export ---
for (const needle of ["backup:export", "BACKUP_FORMAT", "BACKUP_SCHEMA"]) {
  if (!bgSrc.includes(needle)) { console.error("background.js missing", needle); process.exit(1); }
}
for (const needle of ["export-btn", "export-status"]) {
  if (!popupHtml.includes(needle)) { console.error("popup.html missing", needle); process.exit(1); }
}
for (const needle of ["backup:export", "triggerDownload", "bindExport"]) {
  if (!popupJs.includes(needle)) { console.error("popup.js missing", needle); process.exit(1); }
}

// Simulate the export payload assembly to ensure the shape is sound and that
// sealed envelopes survive a JSON round-trip + decrypt with the same key.
const envelopes = [env];
const exportPayload = {
  format: "auth-notes-backup",
  schema: 1,
  appVersion: m.version,
  exportedAt: Date.now(),
  auth: record,
  envelopes,
};
for (const e of exportPayload.envelopes) notes.assertEnvelopeSealed(e);
const exportJson = JSON.stringify(exportPayload);
if (exportJson.includes("me@example.com") || exportJson.includes("YubiKey")) {
  console.error("export payload leaked plaintext sensitive fields");
  process.exit(1);
}
const restored = JSON.parse(exportJson);
if (restored.format !== "auth-notes-backup" || restored.schema !== 1) {
  console.error("export payload header malformed"); process.exit(1);
}
if (!restored.auth?.salt || !restored.auth?.verifier?.ct) {
  console.error("export payload missing auth record"); process.exit(1);
}
if (!Array.isArray(restored.envelopes) || restored.envelopes.length !== 1) {
  console.error("export payload envelopes missing"); process.exit(1);
}
const restoredKey = await mod.verifyPassword(password, restored.auth);
const restoredNote = await notes.decryptNote(restoredKey, restored.envelopes[0]);
if (restoredNote.email !== "me@example.com") {
  console.error("export round-trip decrypt failed"); process.exit(1);
}

// --- Encrypted backup import ----------------------------------------
for (const needle of ["backup:import", "decodeBackupContent", "planImport"]) {
  if (!bgSrc.includes(needle)) { console.error("background.js missing", needle); process.exit(1); }
}
for (const needle of ["import-btn", "import-file", "import-pw", "import-run", "import-actions"]) {
  if (!popupHtml.includes(needle)) { console.error("popup.html missing", needle); process.exit(1); }
}
for (const needle of ["backup:import", "bindImport", "pendingImportContent"]) {
  if (!popupJs.includes(needle)) { console.error("popup.js missing", needle); process.exit(1); }
}

// Bad payloads must be rejected by the decoder.
const rejects = [
  ["empty", ""],
  ["non-json", "not json at all"],
  ["wrong format", JSON.stringify({ format: "other", schema: 1, auth: {}, envelopes: [] })],
  ["wrong schema", JSON.stringify({ format: "auth-notes-backup", schema: 999, auth: { salt: "x", verifier: {} }, envelopes: [] })],
  ["no auth", JSON.stringify({ format: "auth-notes-backup", schema: 1, envelopes: [] })],
  ["no envelopes", JSON.stringify({ format: "auth-notes-backup", schema: 1, auth: { salt: "x", verifier: { iv: "i", ct: "c" } } })],
  ["leaked envelope", JSON.stringify({
    format: "auth-notes-backup", schema: 1,
    auth: { salt: "x", verifier: { iv: "i", ct: "c" } },
    envelopes: [{ id: "a", origin: "b", iv: "c", ct: "d", email: "leak" }],
  })],
];
for (const [name, body] of rejects) {
  let threw = false;
  try { notes.decodeBackupContent(body); }
  catch { threw = true; }
  if (!threw) { console.error("decodeBackupContent should reject:", name); process.exit(1); }
}

// Happy path: the exporter's JSON we built above must decode cleanly.
const decoded = notes.decodeBackupContent(exportJson);
if (decoded.format !== "auth-notes-backup" || decoded.envelopes.length !== 1) {
  console.error("decodeBackupContent failed on valid payload"); process.exit(1);
}
if (notes.BACKUP_FORMAT !== "auth-notes-backup" || notes.BACKUP_SCHEMA !== 1) {
  console.error("BACKUP_FORMAT/SCHEMA constants drifted"); process.exit(1);
}

// planImport: merge updates by id, replace discards existing.
const existingEnv = [
  { id: "a", origin: "x", iv: "1", ct: "1" },
  { id: "b", origin: "y", iv: "2", ct: "2" },
];
const incomingEnv = [
  { id: "b", origin: "y", iv: "3", ct: "3" }, // replaces a known id
  { id: "c", origin: "z", iv: "4", ct: "4" }, // brand new
];
const merge = notes.planImport(existingEnv, incomingEnv, "merge");
if (merge.added !== 1 || merge.replaced !== 1 || merge.discarded !== 0) {
  console.error("planImport merge wrong", merge); process.exit(1);
}
const replace = notes.planImport(existingEnv, incomingEnv, "replace");
if (replace.added !== 2 || replace.replaced !== 0 || replace.discarded !== 2) {
  console.error("planImport replace wrong", replace); process.exit(1);
}
let badModeThrew = false;
try { notes.planImport(existingEnv, incomingEnv, "bogus"); }
catch { badModeThrew = true; }
if (!badModeThrew) { console.error("planImport should reject unknown mode"); process.exit(1); }

// Full re-encrypt round-trip: a backup created with one password can be
// decrypted with that password's key and re-encrypted under a different one.
const altPassword = "different-master-password";
const { record: altRecord, key: altKey } = await mod.buildSetupRecord(altPassword);
const backupKey = await mod.verifyPassword(password, decoded.auth);
const decryptedFromBackup = await notes.decryptNote(backupKey, decoded.envelopes[0]);
const renormalized = notes.normalizeNote({
  ...decryptedFromBackup,
  createdAt: decryptedFromBackup.createdAt,
}, { now: decryptedFromBackup.updatedAt });
const resealed = await notes.encryptNote(altKey, renormalized);
notes.assertEnvelopeSealed(resealed);
const final = await notes.decryptNote(altKey, resealed);
if (final.email !== "me@example.com" || final.id !== decryptedFromBackup.id) {
  console.error("import re-encrypt round-trip failed"); process.exit(1);
}
void altRecord;

console.log("\u2713 smoke ok");
