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
  tags: ["Work", "dev", "work", "Has Space", "!!!", ""],
});
if (norm.origin !== "github.com") { console.error("origin not normalized"); process.exit(1); }
if (!norm.id || norm.id.length < 10) { console.error("missing id"); process.exit(1); }
if (!norm.createdAt || !norm.updatedAt) { console.error("missing timestamps"); process.exit(1); }
if (!Array.isArray(norm.tags) || norm.tags.join(",") !== "work,dev,has-space") {
  console.error("tags not normalized", norm.tags); process.exit(1);
}
if (notes.normalizeTag("  Foo BAR  ") !== "foo-bar") { console.error("normalizeTag wrong"); process.exit(1); }
if (notes.normalizeTags("work, personal,banking").join(",") !== "work,personal,banking") {
  console.error("normalizeTags string wrong"); process.exit(1);
}
const tagAgg = notes.collectTags([
  { tags: ["work", "dev"] }, { tags: ["work"] }, { tags: ["personal"] }, {},
]);
if (tagAgg[0].tag !== "work" || tagAgg[0].count !== 2) {
  console.error("collectTags wrong", tagAgg); process.exit(1);
}
if (!Array.isArray(notes.TAG_PRESETS) || !notes.TAG_PRESETS.includes("work")) {
  console.error("TAG_PRESETS missing"); process.exit(1);
}

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
if (!Array.isArray(back.tags) || !back.tags.includes("work") || !back.tags.includes("dev")) {
  console.error("tag round-trip lost tags", back.tags); process.exit(1);
}

// --- Password-strength hint (length + complexity bucket) ----------
if (!Array.isArray(notes.PW_COMPLEXITY_BUCKETS) || notes.PW_COMPLEXITY_BUCKETS.join(",") !== "weak,okay,good,strong") {
  console.error("PW_COMPLEXITY_BUCKETS wrong"); process.exit(1);
}
if (notes.normalizePasswordHint(null) !== null) { console.error("normalizePasswordHint(null) should be null"); process.exit(1); }
if (notes.normalizePasswordHint({}) !== null) { console.error("normalizePasswordHint({}) should be null"); process.exit(1); }
if (notes.normalizePasswordHint({ length: "-3", complexity: "nope" }) !== null) {
  console.error("normalizePasswordHint should drop invalid fields"); process.exit(1);
}
const hint1 = notes.normalizePasswordHint({ length: 18.7, complexity: "GOOD" });
if (!hint1 || hint1.length !== 19 || hint1.complexity !== "good") {
  console.error("normalizePasswordHint normalize failed", hint1); process.exit(1);
}
const hint2 = notes.normalizePasswordHint({ length: 9999 });
if (!hint2 || hint2.length !== notes.PW_LENGTH_MAX || hint2.complexity != null) {
  console.error("normalizePasswordHint clamp failed", hint2); process.exit(1);
}
if (notes.bucketForPassword("abc") !== "weak") { console.error("bucketForPassword weak"); process.exit(1); }
if (notes.bucketForPassword("abcdefgh") !== "weak") { console.error("bucketForPassword len-only"); process.exit(1); }
if (notes.bucketForPassword("Abcdef1!xyzQ") !== "strong") {
  console.error("bucketForPassword strong", notes.bucketForPassword("Abcdef1!xyzQ")); process.exit(1);
}

const hinted = notes.normalizeNote({
  origin: "https://bank.example.com/login",
  authMethod: "password",
  email: "me@example.com",
  passwordHint: { length: 22, complexity: "strong" },
});
if (!hinted.passwordHint || hinted.passwordHint.length !== 22 || hinted.passwordHint.complexity !== "strong") {
  console.error("normalizeNote did not carry passwordHint", hinted.passwordHint); process.exit(1);
}
// Sealed envelope must NEVER contain the hint in plaintext.
const hintedEnv = await notes.encryptNote(key, hinted);
notes.assertEnvelopeSealed(hintedEnv);
const hintedEnvJson = JSON.stringify(hintedEnv);
if (hintedEnvJson.includes("strong") || hintedEnvJson.includes("\"length\":22")) {
  console.error("password hint leaked into envelope"); process.exit(1);
}
const hintedBack = await notes.decryptNote(key, hintedEnv);
if (!hintedBack.passwordHint || hintedBack.passwordHint.length !== 22 || hintedBack.passwordHint.complexity !== "strong") {
  console.error("passwordHint round-trip failed", hintedBack.passwordHint); process.exit(1);
}
// A note without a hint must omit the field entirely.
const unhinted = notes.normalizeNote({ origin: "a.example", authMethod: "passkey" });
if ("passwordHint" in unhinted) { console.error("unhinted note should omit passwordHint"); process.exit(1); }

// Popup must wire up the new password-hint UI.
const _hintPopupHtml = fs.readFileSync("src/popup.html", "utf8");
const _hintPopupJs = fs.readFileSync("src/popup.js", "utf8");
for (const needle of [
  "quick-pw-fieldset", "quick-pw-length", "quick-pw-complexity", "quick-pw-probe",
  "match-row-pw", "match-pw",
]) {
  if (!_hintPopupHtml.includes(needle)) { console.error("popup.html missing", needle); process.exit(1); }
}
for (const needle of [
  "collectQuickPasswordHint", "formatPasswordHint", "bindQuickPasswordHint",
  "deriveBucketFromPassword",
]) {
  if (!_hintPopupJs.includes(needle)) { console.error("popup.js missing", needle); process.exit(1); }
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

// Tags must be a forbidden plaintext envelope field too.
let tagsLeakRejected = false;
try { notes.assertEnvelopeSealed({ ...env, tags: ["leak"] }); }
catch { tagsLeakRejected = true; }
if (!tagsLeakRejected) { console.error("tags should be forbidden on envelope"); process.exit(1); }

// --- Lock/unlock UI wiring (static check) ---
const popupHtml = fs.readFileSync("src/popup.html", "utf8");
const popupJs = fs.readFileSync("src/popup.js", "utf8");
for (const needle of ["view-lock", "unlock-form", "unlock-pw", "lock-btn"]) {
  if (!popupHtml.includes(needle)) { console.error("popup.html missing", needle); process.exit(1); }
}
for (const needle of ["master:verify", "master:lock", "bindUnlockForm", "lockVault"]) {
  if (!popupJs.includes(needle)) { console.error("popup.js missing", needle); process.exit(1); }
}

// --- Quick-lock keyboard shortcut ---
const manifestForCmd = JSON.parse(fs.readFileSync("manifest.json", "utf8"));
if (!manifestForCmd.commands || !manifestForCmd.commands["quick-lock"]) {
  console.error("manifest missing 'quick-lock' command"); process.exit(1);
}
const qlCmd = manifestForCmd.commands["quick-lock"];
if (qlCmd.suggested_key?.default !== "Ctrl+Shift+L" || qlCmd.suggested_key?.mac !== "Command+Shift+L") {
  console.error("quick-lock command must bind Cmd/Ctrl+Shift+L"); process.exit(1);
}
const bgForCmd = fs.readFileSync("src/background.js", "utf8");
for (const needle of ["chrome.commands", "onCommand", "quick-lock"]) {
  if (!bgForCmd.includes(needle)) { console.error("background.js missing quick-lock wiring:", needle); process.exit(1); }
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

// --- Quick-add UI wiring (static check) -----------------------------
for (const needle of [
  "view-quick-add", "quick-form", "quick-origin", "quick-auth", "quick-2fa",
  "quick-tags", "quick-notes", "quick-submit", "add-btn", "site-empty-add", "match-edit",
]) {
  if (!popupHtml.includes(needle)) { console.error("popup.html missing", needle); process.exit(1); }
}
for (const needle of [
  "bindQuickAdd", "openQuickAdd", "startQuickAddFromCurrentTab", "notes:upsert", "notes:delete",
]) {
  if (!popupJs.includes(needle)) { console.error("popup.js missing", needle); process.exit(1); }
}

// --- Encrypted audit log -------------------------------------------
for (const needle of [
  "audit:list", "audit:clear", "recordAuditEvent", "assertAuditEnvelopeSealed",
  "STORAGE_KEY_AUDIT", "normalizeAuditEvent", "encryptAuditEvent", "decryptAuditEvent",
]) {
  if (!bgSrc.includes(needle)) { console.error("background.js missing", needle); process.exit(1); }
}
for (const needle of ["audit-open", "audit-clear", "audit-list", "view-audit"]) {
  if (!popupHtml.includes(needle)) { console.error("popup.html missing", needle); process.exit(1); }
}
for (const needle of ["bindAudit", "openAuditLog", "renderAuditLog", "audit:list", "audit:clear"]) {
  if (!popupJs.includes(needle)) { console.error("popup.js missing", needle); process.exit(1); }
}

if (!Array.isArray(notes.AUDIT_EVENT_TYPES) || !notes.AUDIT_EVENT_TYPES.includes("unlock")) {
  console.error("AUDIT_EVENT_TYPES missing"); process.exit(1);
}
if (notes.AUDIT_MAX !== 500) { console.error("AUDIT_MAX drift"); process.exit(1); }

const auditNow = 1_700_000_000_000;
const auditNorm = notes.normalizeAuditEvent({
  type: "note:update",
  origin: "https://github.com/login",
  noteId: "abc123",
  detail: "renamed label",
}, { now: auditNow });
if (auditNorm.type !== "note:update" || auditNorm.origin !== "github.com") {
  console.error("normalizeAuditEvent wrong", auditNorm); process.exit(1);
}
if (auditNorm.ts !== auditNow) { console.error("audit ts not honored"); process.exit(1); }

let badAuditThrew = false;
try { notes.normalizeAuditEvent({ type: "nope" }); } catch { badAuditThrew = true; }
if (!badAuditThrew) { console.error("unknown audit type should reject"); process.exit(1); }

const auditEnv = await notes.encryptAuditEvent(key, auditNorm);
notes.assertAuditEnvelopeSealed(auditEnv);
const auditBack = await notes.decryptAuditEvent(key, auditEnv);
if (auditBack.type !== "note:update" || auditBack.noteId !== "abc123" || auditBack.detail !== "renamed label") {
  console.error("audit round-trip failed", auditBack); process.exit(1);
}

// Envelope must NOT carry plaintext type/origin/detail/noteId.
const auditEnvJson = JSON.stringify(auditEnv);
if (auditEnvJson.includes("renamed label") || auditEnvJson.includes("github.com") || auditEnvJson.includes("note:update")) {
  console.error("audit envelope leaked plaintext"); process.exit(1);
}

let auditLeakRejected = false;
try { notes.assertAuditEnvelopeSealed({ ...auditEnv, type: "unlock" }); } catch { auditLeakRejected = true; }
if (!auditLeakRejected) { console.error("audit envelope leak must be rejected"); process.exit(1); }

let auditMissingRejected = false;
try { notes.assertAuditEnvelopeSealed({ id: "x", iv: "i", ct: "c" }); } catch { auditMissingRejected = true; }
if (!auditMissingRejected) { console.error("audit envelope missing ts must reject"); process.exit(1); }

// trimAuditLog keeps newest-by-ts up to the cap.
const many = [];
for (let i = 0; i < 12; i++) many.push({ id: `e${i}`, ts: i, iv: "i", ct: "c" });
const trimmed = notes.trimAuditLog(many, 5);
if (trimmed.length !== 5 || trimmed[0].ts !== 7 || trimmed[4].ts !== 11) {
  console.error("trimAuditLog wrong", trimmed.map((e) => e.ts)); process.exit(1);
}

// --- Theme settings: UI presence ---
const themePopupHtml = fs.readFileSync("src/popup.html", "utf8");
if (!themePopupHtml.includes("theme-summary") || !themePopupHtml.includes("data-theme=\"light\"") || !themePopupHtml.includes("data-theme=\"dark\"") || !themePopupHtml.includes("data-theme=\"auto\"")) {
  console.error("theme picker missing from popup.html"); process.exit(1);
}
const themePopupCss = fs.readFileSync("src/popup.css", "utf8");
if (!themePopupCss.includes(".segmented")) { console.error("segmented control CSS missing"); process.exit(1); }
const themePopupJs = fs.readFileSync("src/popup.js", "utf8");
if (!themePopupJs.includes("setThemePref") || !themePopupJs.includes("resolveTheme")) {
  console.error("theme handling missing from popup.js"); process.exit(1);
}
const themeBgSrc = fs.readFileSync("src/background.js", "utf8");
if (!themeBgSrc.includes("VALID_THEMES") || !themeBgSrc.includes("theme: DEFAULT_THEME")) {
  console.error("theme handling missing from background.js"); process.exit(1);
}

// --- Bulk tag editor (multi-select) ---
const notesMod = await import("../src/notes.js");
if (typeof notesMod.applyBulkTags !== "function") {
  console.error("applyBulkTags missing from notes.js"); process.exit(1);
}
const bulkBase = notesMod.normalizeNote({ label: "Acme", origin: "https://acme.test", tags: ["work", "infra"] });
const added = notesMod.applyBulkTags(bulkBase, { add: ["BANKING", "work"], remove: ["infra"], now: bulkBase.updatedAt + 1000 });
if (!added.changed) { console.error("bulk tags should report change"); process.exit(1); }
if (!added.note.tags.includes("banking") || !added.note.tags.includes("work") || added.note.tags.includes("infra")) {
  console.error("bulk tags add/remove wrong:", added.note.tags); process.exit(1);
}
const noop = notesMod.applyBulkTags(added.note, { add: ["work"], remove: ["missing"] });
if (noop.changed) { console.error("bulk tags no-op should not change"); process.exit(1); }
if (!themeBgSrc.includes('handlers["notes:bulkTag"]')) {
  console.error("notes:bulkTag handler missing"); process.exit(1);
}

// --- Favicon thumbnail wiring ---------------------------------------
if (!Array.isArray(manifest.permissions) || !manifest.permissions.includes("favicon")) {
  console.error("manifest missing 'favicon' permission"); process.exit(1);
}
const favPopupJs = fs.readFileSync("src/popup.js", "utf8");
if (!favPopupJs.includes("faviconUrl(") || !favPopupJs.includes("faviconHtml(") || !favPopupJs.includes("_favicon")) {
  console.error("favicon helpers missing from popup.js"); process.exit(1);
}
const favPopupHtml = fs.readFileSync("src/popup.html", "utf8");
if (!favPopupHtml.includes("match-favicon")) {
  console.error("match-favicon node missing from popup.html"); process.exit(1);
}
const favPopupCss = fs.readFileSync("src/popup.css", "utf8");
if (!favPopupCss.includes(".favicon") || !favPopupCss.includes(".favicon-img")) {
  console.error("favicon CSS missing"); process.exit(1);
}
const bulkPopupHtml = fs.readFileSync("src/popup.html", "utf8");
if (!bulkPopupHtml.includes("id=\"bulk-bar\"") || !bulkPopupHtml.includes("id=\"bulk-toggle\"")) {
  console.error("bulk editor UI missing from popup.html"); process.exit(1);
}
const bulkPopupJs = fs.readFileSync("src/popup.js", "utf8");
if (!bulkPopupJs.includes("notes:bulkTag") || !bulkPopupJs.includes("bindBulkEditor")) {
  console.error("bulk editor wiring missing from popup.js"); process.exit(1);
}
const bulkPopupCss = fs.readFileSync("src/popup.css", "utf8");
if (!bulkPopupCss.includes(".bulk-bar") || !bulkPopupCss.includes(".is-bulk")) {
  console.error("bulk editor CSS missing"); process.exit(1);
}

// --- Options page (settings) ---------------------------------------
for (const p of ["src/options.html", "src/options.css", "src/options.js"]) {
  if (!fs.existsSync(p)) { console.error("missing options file:", p); process.exit(1); }
}
if (!manifest.options_ui || manifest.options_ui.page !== "src/options.html") {
  console.error("manifest missing options_ui.page"); process.exit(1);
}
const optionsHtml = fs.readFileSync("src/options.html", "utf8");
const optionsJs = fs.readFileSync("src/options.js", "utf8");
for (const needle of ["opt-theme", "opt-idle", "opt-iters", "rekey-run", "rekey-pw"]) {
  if (!optionsHtml.includes(needle)) { console.error("options.html missing", needle); process.exit(1); }
}
for (const needle of ["master:rekey", "settings:set", "bindKdf", "pbkdf2Iterations"]) {
  if (!optionsJs.includes(needle)) { console.error("options.js missing", needle); process.exit(1); }
}
// --- Change master password ---------------------------------------
for (const needle of ["chpw-current", "chpw-new", "chpw-confirm", "chpw-run"]) {
  if (!optionsHtml.includes(needle)) { console.error("options.html missing", needle); process.exit(1); }
}
for (const needle of ["master:changePassword", "bindChangePassword"]) {
  if (!optionsJs.includes(needle)) { console.error("options.js missing", needle); process.exit(1); }
}
const bgChpw = fs.readFileSync("src/background.js", "utf8");
if (!bgChpw.includes('handlers["master:changePassword"]')) {
  console.error("background.js missing master:changePassword handler"); process.exit(1);
}
// End-to-end crypto check: rotate the password and prove old key no longer
// decrypts a re-sealed envelope while the new key does.
{
  const pw1 = "old-pw-correct-horse";
  const pw2 = "new-pw-battery-staple";
  const r1 = await mod.buildSetupRecord(pw1, 60_000);
  const note = notes.normalizeNote({
    origin: "https://example.test",
    authMethod: "password",
    email: "rotate@example.test",
    notes: "rotate me",
  });
  const env1 = await notes.encryptNote(r1.key, note);
  // Verify with new password (rotation) — re-encrypt under new key.
  const r2 = await mod.buildSetupRecord(pw2, 60_000);
  const decrypted = await notes.decryptNote(r1.key, env1);
  const env2 = await notes.encryptNote(r2.key, decrypted);
  let oldRejected = false;
  try { await notes.decryptNote(r1.key, env2); }
  catch { oldRejected = true; }
  if (!oldRejected) { console.error("rotated envelope should not decrypt with old key"); process.exit(1); }
  const back = await notes.decryptNote(r2.key, env2);
  if (back.email !== "rotate@example.test") { console.error("rotated envelope lost data"); process.exit(1); }
  // The new auth record must verify under the new password and reject the old.
  await mod.verifyPassword(pw2, r2.record);
  let oldPwRejected = false;
  try { await mod.verifyPassword(pw1, r2.record); }
  catch { oldPwRejected = true; }
  if (!oldPwRejected) { console.error("old password should not verify against rotated auth"); process.exit(1); }
}
const bgSrc2 = fs.readFileSync("src/background.js", "utf8");
for (const needle of ["master:rekey", "pbkdf2Iterations", "PBKDF2_CHOICES"]) {
  if (!bgSrc2.includes(needle)) { console.error("background.js missing", needle); process.exit(1); }
}
// buildSetupRecord must accept an iterations override.
const { record: customRec, key: customKey } = await mod.buildSetupRecord("pw-test-iters", 60_000);
if (customRec.iterations !== 60_000) {
  console.error("buildSetupRecord did not honor iterations override", customRec.iterations); process.exit(1);
}
const customKey2 = await mod.verifyPassword("pw-test-iters", customRec);
void customKey; void customKey2;


// --- Custom fields (per-note key/value pairs) ---------------------
if (typeof notes.normalizeCustomFields !== "function") {
  console.error("notes.normalizeCustomFields missing"); process.exit(1);
}
if (notes.CUSTOM_FIELD_MAX_COUNT !== 16 || notes.CUSTOM_FIELD_KEY_MAX !== 64 || notes.CUSTOM_FIELD_VALUE_MAX !== 2048) {
  console.error("custom field caps drifted"); process.exit(1);
}
if (notes.normalizeCustomFieldKey("  API   Key  ") !== "API Key") {
  console.error("normalizeCustomFieldKey wrong"); process.exit(1);
}
const cfArr = notes.normalizeCustomFields([
  { key: " Account # ", value: "ABC-123" },
  ["Support PIN", 4242],
  { key: "", value: "drop me" },
  { key: "Account #", value: "override" },
]);
if (cfArr.length !== 2 || cfArr[0].key !== "Account #" || cfArr[0].value !== "override" || cfArr[1].key !== "Support PIN" || cfArr[1].value !== "4242") {
  console.error("normalizeCustomFields array wrong", cfArr); process.exit(1);
}
const cfObj = notes.normalizeCustomFields({ alpha: "a", beta: "b" });
if (cfObj.length !== 2 || cfObj[0].key !== "alpha" || cfObj[1].key !== "beta") {
  console.error("normalizeCustomFields object wrong", cfObj); process.exit(1);
}
if (notes.normalizeCustomFields(null).length !== 0 || notes.normalizeCustomFields("").length !== 0) {
  console.error("normalizeCustomFields should yield [] for empty"); process.exit(1);
}
const _cfLongVal = "x".repeat(notes.CUSTOM_FIELD_VALUE_MAX + 50);
const _cfClipped = notes.normalizeCustomFields([{ key: "k", value: _cfLongVal }]);
if (_cfClipped[0].value.length !== notes.CUSTOM_FIELD_VALUE_MAX) {
  console.error("value clip wrong"); process.exit(1);
}
const _cfMany = [];
for (let i = 0; i < notes.CUSTOM_FIELD_MAX_COUNT + 5; i++) _cfMany.push({ key: `k${i}`, value: `v${i}` });
if (notes.normalizeCustomFields(_cfMany).length !== notes.CUSTOM_FIELD_MAX_COUNT) {
  console.error("count cap wrong"); process.exit(1);
}
const cfNote = notes.normalizeNote({
  origin: "https://example.test",
  authMethod: "password",
  email: "cf@example.test",
  customFields: [{ key: "Account #", value: "acct-9001" }, { key: "PIN", value: "4242" }],
});
if (!Array.isArray(cfNote.customFields) || cfNote.customFields.length !== 2 || cfNote.customFields[0].key !== "Account #") {
  console.error("normalizeNote did not carry customFields", cfNote.customFields); process.exit(1);
}
const cfEnv = await notes.encryptNote(key, cfNote);
notes.assertEnvelopeSealed(cfEnv);
const cfEnvJson = JSON.stringify(cfEnv);
if (cfEnvJson.includes("acct-9001") || cfEnvJson.includes("Account #") || cfEnvJson.includes("\"PIN\"")) {
  console.error("custom fields leaked into envelope"); process.exit(1);
}
const cfBack = await notes.decryptNote(key, cfEnv);
if (!Array.isArray(cfBack.customFields) || cfBack.customFields[0].value !== "acct-9001" || cfBack.customFields[1].key !== "PIN") {
  console.error("customFields round-trip wrong", cfBack.customFields); process.exit(1);
}
let cfLeakRejected = false;
try { notes.assertEnvelopeSealed({ ...env, customFields: [{ key: "x", value: "y" }] }); }
catch { cfLeakRejected = true; }
if (!cfLeakRejected) { console.error("customFields should be forbidden on envelope"); process.exit(1); }
const cfBare = notes.normalizeNote({ origin: "bare.example", authMethod: "passkey" });
if ("customFields" in cfBare) { console.error("bare note should omit customFields"); process.exit(1); }

const _cfPopupHtml = fs.readFileSync("src/popup.html", "utf8");
const _cfPopupJs = fs.readFileSync("src/popup.js", "utf8");
for (const needle of [
  "quick-fields-fieldset", "quick-fields-list", "quick-fields-add",
  "match-row-fields", "match-fields-list",
]) {
  if (!_cfPopupHtml.includes(needle)) { console.error("popup.html missing", needle); process.exit(1); }
}
for (const needle of [
  "renderQuickCustomFields", "collectQuickCustomFields", "renderMatchCustomFields", "appendQuickCustomFieldRow",
]) {
  if (!_cfPopupJs.includes(needle)) { console.error("popup.js missing", needle); process.exit(1); }
}
const _cfPopupCss = fs.readFileSync("src/popup.css", "utf8");
if (!_cfPopupCss.includes(".custom-field-row") || !_cfPopupCss.includes(".custom-fields-readout")) {
  console.error("popup.css missing custom-field styles"); process.exit(1);
}

// --- Markdown rendering + sanitizer ---------------------------------
const md = await import("../src/markdown.js");
if (typeof md.renderMarkdown !== "function" || typeof md.sanitizeUrl !== "function") {
  console.error("markdown module missing exports"); process.exit(1);
}
if (md.sanitizeUrl("javascript:alert(1)") !== null) {
  console.error("sanitizeUrl should reject javascript: URLs"); process.exit(1);
}
if (md.sanitizeUrl("data:text/html,foo") !== null) {
  console.error("sanitizeUrl should reject data: URLs"); process.exit(1);
}
if (md.sanitizeUrl("https://example.com/x?a=1&b=2") !== "https://example.com/x?a=1&b=2") {
  console.error("sanitizeUrl should pass https"); process.exit(1);
}
const rendered = md.renderMarkdown("# Title\n\nHello **world** with <script>alert(1)</script> and a [link](javascript:alert(1)) plus [ok](https://example.com).\n\n- one\n- two\n\n```\n<b>raw</b>\n```");
if (rendered.includes("<script>") || rendered.toLowerCase().includes("javascript:")) {
  console.error("markdown leaked unsafe content:", rendered); process.exit(1);
}
if (!rendered.includes("<h1") || !rendered.includes("<strong>world</strong>")) {
  console.error("markdown failed to render headings/bold:", rendered); process.exit(1);
}
if (!rendered.includes('href="https://example.com"') || !rendered.includes('rel="noopener noreferrer"')) {
  console.error("markdown link not rendered safely:", rendered); process.exit(1);
}
if (!rendered.includes("<ul") || !rendered.includes("<li>one</li>")) {
  console.error("markdown list rendering wrong:", rendered); process.exit(1);
}
if (!rendered.includes("&lt;b&gt;raw&lt;/b&gt;")) {
  console.error("markdown code fence not escaped:", rendered); process.exit(1);
}
const mdPopupJs = fs.readFileSync("src/popup.js", "utf8");
if (!mdPopupJs.includes("renderMarkdown") || !mdPopupJs.includes("markdown-body")) {
  console.error("popup.js not wired to markdown renderer"); process.exit(1);
}
const mdPopupCss = fs.readFileSync("src/popup.css", "utf8");
if (!mdPopupCss.includes(".markdown-body")) {
  console.error("popup.css missing markdown-body styles"); process.exit(1);
}

// --- Trash / soft-delete -------------------------------------------
if (typeof notes.partitionTrash !== "function" || typeof notes.isTrashed !== "function" || typeof notes.trashTtlMs !== "function") {
  console.error("trash helpers missing from notes.js"); process.exit(1);
}
if (notes.TRASH_RETENTION_MS !== 30 * 24 * 60 * 60 * 1000) {
  console.error("TRASH_RETENTION_MS drift"); process.exit(1);
}
const trashNow = 1_800_000_000_000;
const activeNote = notes.normalizeNote({ origin: "keep.test", authMethod: "passkey" }, { now: trashNow });
const freshTrash = notes.normalizeNote({ origin: "drop.test", authMethod: "password", deletedAt: trashNow - 1000 }, { now: trashNow });
const staleTrash = notes.normalizeNote({ origin: "gc.test", authMethod: "password", deletedAt: trashNow - notes.TRASH_RETENTION_MS - 5_000 }, { now: trashNow });
if (!notes.isTrashed(freshTrash) || notes.isTrashed(activeNote)) {
  console.error("isTrashed wrong"); process.exit(1);
}
const part = notes.partitionTrash([activeNote, freshTrash, staleTrash], { now: trashNow });
if (part.active.length !== 1 || part.trashed.length !== 2 || part.expired.length !== 1 || part.expired[0].origin !== "gc.test") {
  console.error("partitionTrash wrong", part); process.exit(1);
}
const ttl = notes.trashTtlMs(freshTrash, { now: trashNow });
if (!(ttl > 0 && ttl <= notes.TRASH_RETENTION_MS)) {
  console.error("trashTtlMs wrong", ttl); process.exit(1);
}
if (notes.trashTtlMs(staleTrash, { now: trashNow }) !== 0) {
  console.error("expired trash ttl should be 0"); process.exit(1);
}
if (notes.trashTtlMs(activeNote) !== null) {
  console.error("active note ttl should be null"); process.exit(1);
}
const forged = notes.normalizeNote({ origin: "forge.test", authMethod: "password", deletedAt: trashNow + 9_999_999 }, { now: trashNow });
if (forged.deletedAt !== trashNow) {
  console.error("deletedAt should clamp to now", forged.deletedAt); process.exit(1);
}
const trashEnv = await notes.encryptNote(key, freshTrash);
notes.assertEnvelopeSealed(trashEnv);
if (JSON.stringify(trashEnv).includes("deletedAt")) {
  console.error("deletedAt must not be plaintext on envelope"); process.exit(1);
}
const trashBack = await notes.decryptNote(key, trashEnv);
if (!notes.isTrashed(trashBack) || trashBack.deletedAt !== freshTrash.deletedAt) {
  console.error("trashed note round-trip lost deletedAt"); process.exit(1);
}
const trashBg = fs.readFileSync("src/background.js", "utf8");
for (const needle of [
  'handlers["notes:restore"]',
  'handlers["notes:trashList"]',
  'handlers["notes:purgeTrash"]',
  'handlers["notes:purgeExpired"]',
  "purgeExpiredTrash",
  "TRASH_RETENTION_MS",
]) {
  if (!trashBg.includes(needle)) { console.error("background.js missing", needle); process.exit(1); }
}
const trashPopupHtml = fs.readFileSync("src/popup.html", "utf8");
for (const needle of ["view-trash", "trash-open", "trash-list", "trash-empty"]) {
  if (!trashPopupHtml.includes(needle)) { console.error("popup.html missing", needle); process.exit(1); }
}
const trashPopupJs = fs.readFileSync("src/popup.js", "utf8");
for (const needle of ["bindTrash", "openTrash", "renderTrash", "notes:trashList", "notes:restore", "notes:purgeTrash"]) {
  if (!trashPopupJs.includes(needle)) { console.error("popup.js missing", needle); process.exit(1); }
}
const trashPopupCss = fs.readFileSync("src/popup.css", "utf8");
if (!trashPopupCss.includes(".trash-list") || !trashPopupCss.includes(".trash-item")) {
  console.error("popup.css missing trash styles"); process.exit(1);
}

// --- Per-note edit history (last 5) --------------------------------
if (typeof notes.appendNoteHistory !== "function" || typeof notes.diffNoteFields !== "function" || typeof notes.normalizeHistory !== "function") {
  console.error("history helpers missing from notes.js"); process.exit(1);
}
if (notes.HISTORY_MAX !== 5) { console.error("HISTORY_MAX drift"); process.exit(1); }
if (!Array.isArray(notes.HISTORY_TRACKED_FIELDS) || !notes.HISTORY_TRACKED_FIELDS.includes("label")) {
  console.error("HISTORY_TRACKED_FIELDS missing"); process.exit(1);
}
// `history` must be forbidden on the storage envelope.
let historyLeakRejected = false;
try { notes.assertEnvelopeSealed({ ...env, history: [{ ts: 1, changes: [] }] }); }
catch { historyLeakRejected = true; }
if (!historyLeakRejected) { console.error("history should be forbidden on envelope"); process.exit(1); }

const hPrev = notes.normalizeNote({
  origin: "hist.test", authMethod: "password",
  label: "Old label", email: "old@example.test", notes: "first draft",
  tags: ["work"],
  passwordHint: { length: 10, complexity: "okay" },
});
const hNext = notes.normalizeNote({
  ...hPrev, createdAt: hPrev.createdAt,
  label: "New label", email: "new@example.test", notes: "second draft",
  tags: ["work", "banking"],
  passwordHint: { length: 18, complexity: "strong" },
}, { now: hPrev.updatedAt + 1_000 });
const hDiff = notes.diffNoteFields(hPrev, hNext);
const hFields = hDiff.map((c) => c.field).sort();
if (!hFields.includes("label") || !hFields.includes("email") || !hFields.includes("notes") || !hFields.includes("tags") || !hFields.includes("passwordHint")) {
  console.error("diffNoteFields missed a change", hDiff); process.exit(1);
}
const pwEntry = hDiff.find((c) => c.field === "passwordHint");
if (!pwEntry || pwEntry.changed !== true || "from" in pwEntry || "to" in pwEntry) {
  console.error("passwordHint diff must be opaque", pwEntry); process.exit(1);
}
const labelEntry = hDiff.find((c) => c.field === "label");
if (!labelEntry || labelEntry.from !== "Old label" || labelEntry.to !== "New label") {
  console.error("label diff wrong", labelEntry); process.exit(1);
}

// Appending preserves order, caps at HISTORY_MAX, and no-op diffs don't grow.
let hCurrent = { ...hPrev };
for (let i = 0; i < 8; i++) {
  const nextStep = notes.normalizeNote({ ...hCurrent, label: `step-${i}`, createdAt: hPrev.createdAt }, { now: hPrev.updatedAt + 1_000 * (i + 1) });
  const history = notes.appendNoteHistory(hCurrent, nextStep, { now: nextStep.updatedAt });
  hCurrent = { ...nextStep, history };
}
if (!Array.isArray(hCurrent.history) || hCurrent.history.length !== notes.HISTORY_MAX) {
  console.error("history did not cap at HISTORY_MAX", hCurrent.history?.length); process.exit(1);
}
for (let i = 1; i < hCurrent.history.length; i++) {
  if (hCurrent.history[i].ts < hCurrent.history[i - 1].ts) {
    console.error("history not chronologically ordered"); process.exit(1);
  }
}
const noopHistory = notes.appendNoteHistory(hCurrent, hCurrent, { now: hPrev.updatedAt + 9999 });
if (noopHistory.length !== hCurrent.history.length) {
  console.error("no-op upsert should not grow history"); process.exit(1);
}

// normalizeHistory drops forged fields + clips overflow.
const forgedHist = notes.normalizeHistory([
  { ts: 1, changes: [{ field: "label", from: "a", to: "b" }, { field: "id", from: "x", to: "y" }] },
  { ts: 2, changes: [] },
  { ts: -5, changes: [{ field: "notes", from: "x", to: "y" }] },
]);
if (forgedHist.length !== 1 || forgedHist[0].changes.length !== 1 || forgedHist[0].changes[0].field !== "label") {
  console.error("normalizeHistory wrong", forgedHist); process.exit(1);
}

// History encrypted at rest: serialize a note with history, ensure no plaintext leakage.
const histNote = notes.normalizeNote({
  origin: "sealed.test", authMethod: "password", label: "Sealed",
  history: hCurrent.history,
});
const histEnv = await notes.encryptNote(key, histNote);
notes.assertEnvelopeSealed(histEnv);
const histEnvJson = JSON.stringify(histEnv);
if (histEnvJson.includes("step-") || histEnvJson.includes("history")) {
  console.error("history leaked into envelope"); process.exit(1);
}
const histBack = await notes.decryptNote(key, histEnv);
if (!Array.isArray(histBack.history) || histBack.history.length !== notes.HISTORY_MAX) {
  console.error("history did not survive round-trip", histBack.history); process.exit(1);
}

// Long values get clipped — log can't balloon to 10 KiB.
const longText = "x".repeat(notes.HISTORY_VALUE_MAX + 200);
const hLong = notes.diffNoteFields({ notes: "" }, { notes: longText });
const longEntry = hLong.find((c) => c.field === "notes");
if (!longEntry || longEntry.to.length > notes.HISTORY_VALUE_MAX + 2) {
  console.error("long history value not clipped", longEntry?.to?.length); process.exit(1);
}

const histBg = fs.readFileSync("src/background.js", "utf8");
if (!histBg.includes('handlers["notes:history"]') || !histBg.includes("appendNoteHistory")) {
  console.error("background.js missing history wiring"); process.exit(1);
}
const histPopupHtml = fs.readFileSync("src/popup.html", "utf8");
for (const needle of ["match-history", "match-history-list", "match-history-count"]) {
  if (!histPopupHtml.includes(needle)) { console.error("popup.html missing", needle); process.exit(1); }
}
const histPopupJs = fs.readFileSync("src/popup.js", "utf8");
for (const needle of ["renderMatchHistory", "notes:history", "historyFieldLabel"]) {
  if (!histPopupJs.includes(needle)) { console.error("popup.js missing", needle); process.exit(1); }
}
const histPopupCss = fs.readFileSync("src/popup.css", "utf8");
if (!histPopupCss.includes(".history-block") || !histPopupCss.includes(".history-entry")) {
  console.error("popup.css missing history styles"); process.exit(1);
}

// --- Per-note attachments (encrypted blobs) -----------------------
if (typeof notes.normalizeAttachment !== "function" || typeof notes.normalizeAttachments !== "function") {
  console.error("attachment helpers missing from notes.js"); process.exit(1);
}
if (notes.ATTACHMENT_MAX_COUNT !== 4 || notes.ATTACHMENT_BYTES_MAX !== 256 * 1024) {
  console.error("attachment caps drift"); process.exit(1);
}
if (!Array.isArray(notes.ATTACHMENT_ALLOWED_MIME) || !notes.ATTACHMENT_ALLOWED_MIME.includes("image/png")) {
  console.error("attachment MIME allowlist missing"); process.exit(1);
}
if (!notes.ENVELOPE_FORBIDDEN_KEYS.includes("attachments")) {
  console.error("attachments must be a forbidden envelope key"); process.exit(1);
}
let attachLeakRejected = false;
try { notes.assertEnvelopeSealed({ ...env, attachments: [{ name: "x.png" }] }); }
catch { attachLeakRejected = true; }
if (!attachLeakRejected) { console.error("attachments must not appear on envelope"); process.exit(1); }

// 4x4 PNG header + ~20 bytes — valid base64, valid MIME.
const tinyPngB64 = "iVBORw0KGgoAAAANSUhEUgAAAAQAAAAECAQAAAAmkwkpAAAADklEQVR42mNkYGBgYAAAAA0AAY3F6lEAAAAASUVORK5CYII=";
const goodAttachment = { name: "codes.png", mimeType: "image/png", data: tinyPngB64, size: 95 };
const normGood = notes.normalizeAttachment(goodAttachment);
if (!normGood || normGood.mimeType !== "image/png" || !normGood.size) {
  console.error("normalizeAttachment rejected a valid PNG", normGood); process.exit(1);
}
if (notes.normalizeAttachment({ name: "x", mimeType: "application/octet-stream", data: tinyPngB64 }) !== null) {
  console.error("normalizeAttachment should reject disallowed MIME"); process.exit(1);
}
if (notes.normalizeAttachment({ name: "x", mimeType: "image/png", data: "" }) !== null) {
  console.error("normalizeAttachment should reject empty data"); process.exit(1);
}
const tooBig = { name: "big.png", mimeType: "image/png", data: tinyPngB64, size: notes.ATTACHMENT_BYTES_MAX + 1 };
if (notes.normalizeAttachment(tooBig) !== null) {
  console.error("normalizeAttachment should reject oversize entries"); process.exit(1);
}

const manyEntries = Array.from({ length: 10 }, (_, i) => ({
  name: `n${i}.png`, mimeType: "image/png", data: tinyPngB64, size: 100,
}));
const capped = notes.normalizeAttachments(manyEntries);
if (capped.length !== notes.ATTACHMENT_MAX_COUNT) {
  console.error("normalizeAttachments did not cap by count", capped.length); process.exit(1);
}
const noteWithAtt = notes.normalizeNote({
  origin: "att.test", authMethod: "password", label: "Att",
  attachments: [goodAttachment],
});
if (!Array.isArray(noteWithAtt.attachments) || noteWithAtt.attachments.length !== 1) {
  console.error("normalizeNote did not carry attachments"); process.exit(1);
}
const attEnv = await notes.encryptNote(key, noteWithAtt);
notes.assertEnvelopeSealed(attEnv);
const attEnvJson = JSON.stringify(attEnv);
if (attEnvJson.includes(tinyPngB64) || attEnvJson.includes("codes.png") || attEnvJson.includes("attachments")) {
  console.error("attachment data leaked into envelope"); process.exit(1);
}
const attBack = await notes.decryptNote(key, attEnv);
if (!Array.isArray(attBack.attachments) || attBack.attachments[0].data !== tinyPngB64) {
  console.error("attachment did not survive round-trip"); process.exit(1);
}

// Diff entry for attachments must be opaque (no leaking base64 in history).
const attPrev = notes.normalizeNote({ origin: "att.test", authMethod: "password", label: "Att" });
const attNext = notes.normalizeNote({
  ...attPrev, createdAt: attPrev.createdAt,
  attachments: [goodAttachment],
}, { now: attPrev.updatedAt + 1000 });
const attDiff = notes.diffNoteFields(attPrev, attNext);
const attDiffEntry = attDiff.find((c) => c.field === "attachments");
if (!attDiffEntry || attDiffEntry.changed !== true || "from" in attDiffEntry || "to" in attDiffEntry) {
  console.error("attachments diff must be opaque", attDiffEntry); process.exit(1);
}
if (!notes.HISTORY_TRACKED_FIELDS.includes("attachments")) {
  console.error("attachments must be in HISTORY_TRACKED_FIELDS"); process.exit(1);
}

const attPopupHtml = fs.readFileSync("src/popup.html", "utf8");
for (const needle of ["quick-attachments-list", "quick-attachments-input", "match-row-attachments", "match-attachments-list", "match-attachments-toggle"]) {
  if (!attPopupHtml.includes(needle)) { console.error("popup.html missing", needle); process.exit(1); }
}
const attPopupJs = fs.readFileSync("src/popup.js", "utf8");
for (const needle of ["renderMatchAttachments", "quickAttachments", "handleQuickAttachmentFiles", "ATTACHMENT_MAX_COUNT"]) {
  if (!attPopupJs.includes(needle)) { console.error("popup.js missing", needle); process.exit(1); }
}
const attPopupCss = fs.readFileSync("src/popup.css", "utf8");
for (const needle of [".attachment-row", ".attachments-readout", ".attachment-thumb"]) {
  if (!attPopupCss.includes(needle)) { console.error("popup.css missing", needle); process.exit(1); }
}

// --- Vault health score (weighted security signals) ---------------
if (!Array.isArray(notes.VAULT_HEALTH_SIGNALS) || notes.VAULT_HEALTH_SIGNALS.length !== 6) {
  console.error("VAULT_HEALTH_SIGNALS missing or wrong length"); process.exit(1);
}
if (typeof notes.computeVaultHealth !== "function") {
  console.error("computeVaultHealth missing"); process.exit(1);
}
const emptyHealth = notes.computeVaultHealth([]);
if (emptyHealth.score !== 0 || emptyHealth.total !== 0 || emptyHealth.grade !== "\u2014") {
  console.error("empty vault health wrong", emptyHealth); process.exit(1);
}
const nowH = 1_800_000_000_000;
const hList = [
  notes.normalizeNote({ origin: "a.test", authMethod: "passkey", email: "a@x.test" }, { now: nowH }),
  notes.normalizeNote({ origin: "b.test", authMethod: "password", email: "b@x.test", twofaBackup: "app", recoveryCodes: ["123","456"], passwordHint: { length: 18, complexity: "strong" } }, { now: nowH }),
  notes.normalizeNote({ origin: "c.test", authMethod: "password", email: "b@x.test", twofaBackup: "none", passwordHint: { length: 4, complexity: "weak" } }, { now: nowH - notes.VAULT_HEALTH_FRESHNESS_MS - 1000 }),
];
const health = notes.computeVaultHealth(hList, { now: nowH });
if (!(health.score >= 0 && health.score <= 100)) { console.error("health.score out of range", health.score); process.exit(1); }
if (typeof health.grade !== "string" || !health.grade.length) { console.error("missing grade"); process.exit(1); }
const sigById = Object.fromEntries(health.signals.map((s) => [s.id, s]));
// 2 of 3 have a 2FA factor (passkey + app backup) -> 67%
if (sigById.twofa.score !== 67) { console.error("twofa share wrong", sigById.twofa); process.exit(1); }
if (sigById.passkey.score !== 33) { console.error("passkey share wrong", sigById.passkey); process.exit(1); }
if (sigById.uniqueEmail.applicable !== 3 || sigById.uniqueEmail.score !== 33) {
  console.error("uniqueEmail share wrong (1 of 3 unique)", sigById.uniqueEmail); process.exit(1);
}
if (sigById.passwordStrength.applicable !== 2 || sigById.passwordStrength.score !== 50) {
  console.error("passwordStrength share wrong", sigById.passwordStrength); process.exit(1);
}
if (sigById.freshness.score !== 67) {
  console.error("freshness share wrong (2 of 3 fresh)", sigById.freshness); process.exit(1);
}
if (sigById.recoveryCodes.applicable !== 2 || sigById.recoveryCodes.score !== 50) {
  console.error("recoveryCodes share wrong", sigById.recoveryCodes); process.exit(1);
}
// Signals with applicable=0 must drop out of the weighted average.
const pkOnly = [notes.normalizeNote({ origin: "p.test", authMethod: "passkey" }, { now: nowH })];
const pkHealth = notes.computeVaultHealth(pkOnly, { now: nowH });
const pkRec = pkHealth.signals.find((s) => s.id === "passwordStrength");
if (!pkRec || pkRec.applicable !== 0) { console.error("passwordStrength should be NA in passkey-only vault"); process.exit(1); }

const healthPopupHtml = fs.readFileSync("src/popup.html", "utf8");
for (const needle of ["stats-health", "stats-health-grade", "stats-health-score", "stats-health-ring-fill", "stats-health-signals"]) {
  if (!healthPopupHtml.includes(needle)) { console.error("popup.html missing", needle); process.exit(1); }
}
const healthPopupJs = fs.readFileSync("src/popup.js", "utf8");
for (const needle of ["renderVaultHealth", "stats-health-ring-fill"]) {
  if (!healthPopupJs.includes(needle)) { console.error("popup.js missing", needle); process.exit(1); }
}
const healthBgSrc = fs.readFileSync("src/background.js", "utf8");
if (!healthBgSrc.includes('handlers["notes:health"]') || !healthBgSrc.includes("computeVaultHealth")) {
  console.error("background.js missing notes:health wiring"); process.exit(1);
}
const healthPopupCss = fs.readFileSync("src/popup.css", "utf8");
if (!healthPopupCss.includes(".stats-health") || !healthPopupCss.includes(".stats-health-signal-fill")) {
  console.error("popup.css missing health styles"); process.exit(1);
}

// --- Inline QR for 2FA backup URIs (offline) ----------------------
const qr = await import("../src/qr.js");
if (typeof qr.extractOtpauthUri !== "function" || typeof qr.qrToSvg !== "function") {
  console.error("qr module missing exports"); process.exit(1);
}
if (qr.extractOtpauthUri("hello world") !== null) { console.error("extractOtpauthUri false-positive"); process.exit(1); }
const sampleUri = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
const extracted = qr.extractOtpauthUri(`enroll: ${sampleUri}.`);
if (extracted !== sampleUri) { console.error("extractOtpauthUri wrong", extracted); process.exit(1); }
const svg = qr.qrToSvg(sampleUri, { ecc: "M", border: 2 });
if (!svg.startsWith("<svg") || !svg.includes("viewBox=") || !svg.includes("<path d=\"")) {
  console.error("qrToSvg malformed svg"); process.exit(1);
}
let qrThrew = false;
try { qr.qrToSvg(""); } catch { qrThrew = true; }
if (!qrThrew) { console.error("qrToSvg should reject empty"); process.exit(1); }
const qrPopupHtml = fs.readFileSync("src/popup.html", "utf8");
for (const needle of ["match-row-qr", "match-qr-canvas", "match-qr-toggle"]) {
  if (!qrPopupHtml.includes(needle)) { console.error("popup.html missing", needle); process.exit(1); }
}
const qrPopupJs = fs.readFileSync("src/popup.js", "utf8");
for (const needle of ["renderMatchQr", "bindMatchQrToggle", "extractOtpauthUri", "qrToSvg"]) {
  if (!qrPopupJs.includes(needle)) { console.error("popup.js missing", needle); process.exit(1); }
}
const qrPopupCss = fs.readFileSync("src/popup.css", "utf8");
if (!qrPopupCss.includes(".qr-canvas") || !qrPopupCss.includes(".qr-head")) {
  console.error("popup.css missing qr styles"); process.exit(1);
}

console.log("\u2713 smoke ok");
