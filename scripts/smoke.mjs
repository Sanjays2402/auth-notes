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

console.log("\u2713 smoke ok");
