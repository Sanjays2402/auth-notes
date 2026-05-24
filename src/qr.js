// Auth Notes — offline QR helpers.
//
// Wraps Project Nayuki's MIT-licensed `qrcodegen` library (vendored at
// `src/qrcodegen.js`) with a small surface area:
//
//   extractOtpauthUri(text)  → first `otpauth://` URI in a string, or null
//   qrToSvg(text, opts?)     → inline SVG string suitable for innerHTML
//
// No network is used at any point. The QR is rendered as a single black `path`
// over a transparent background so popup CSS can theme the surrounding chrome
// (dark and light parity, liquid-glass framing) without re-rasterizing.

import { qrcodegen } from "./qrcodegen.js";

const { QrCode } = qrcodegen;

/** Regex tuned to match `otpauth://totp/...` or `otpauth://hotp/...` URIs as
 *  they appear inline in free-text fields. We accept anything up to the next
 *  whitespace, quote, or angle bracket so URIs in markdown links or quoted
 *  notes still resolve cleanly. */
const OTPAUTH_RE = /otpauth:\/\/[ht]otp\/[^\s"'<>]+/i;

/** Find the first `otpauth://` URI inside a free-text blob. Returns `null` if
 *  the input has none. The match is trimmed of trailing punctuation that is
 *  rarely meaningful in OTP URIs (`,.;:)]}`). */
export function extractOtpauthUri(text) {
  if (typeof text !== "string" || text.length === 0) return null;
  const m = text.match(OTPAUTH_RE);
  if (!m) return null;
  return m[0].replace(/[,.;:)\]}]+$/, "");
}

/** Render `text` as a QR code and return an inline SVG string. The SVG has a
 *  `viewBox` sized to the module grid (plus a quiet zone) so callers can scale
 *  it freely with CSS. The path uses `fill="currentColor"` so the icon takes
 *  its color from the surrounding element — this keeps dark/light parity
 *  without re-rendering. */
export function qrToSvg(text, { ecc = "M", border = 2 } = {}) {
  if (typeof text !== "string" || text.length === 0) {
    throw new Error("qrToSvg: text required");
  }
  const eccLevel = pickEcc(ecc);
  const safeBorder = Number.isFinite(border) && border >= 0 ? Math.min(8, Math.floor(border)) : 2;
  const qr = QrCode.encodeText(text, eccLevel);
  const dim = qr.size + safeBorder * 2;
  // Build a single `path` of module rectangles. This is meaningfully smaller
  // than emitting one `<rect>` per dark module and parses faster in popup.
  const parts = [];
  for (let y = 0; y < qr.size; y++) {
    for (let x = 0; x < qr.size; x++) {
      if (qr.getModule(x, y)) {
        parts.push(`M${x + safeBorder},${y + safeBorder}h1v1h-1z`);
      }
    }
  }
  const d = parts.join("");
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${dim} ${dim}" ` +
    `shape-rendering="crispEdges" role="img" aria-label="QR code">` +
    `<path d="${d}" fill="currentColor"/>` +
    `</svg>`
  );
}

function pickEcc(ecc) {
  switch (String(ecc || "M").toUpperCase()) {
    case "L": return QrCode.Ecc.LOW;
    case "Q": return QrCode.Ecc.QUARTILE;
    case "H": return QrCode.Ecc.HIGH;
    case "M":
    default: return QrCode.Ecc.MEDIUM;
  }
}
