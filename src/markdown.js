// Auth Notes — tiny safe Markdown renderer.
//
// We deliberately roll our own instead of pulling a 200KB dependency. The
// surface is narrow: notes are short, written by the vault owner, and only
// rendered into trusted chrome (the popup). Even so, every input is HTML-
// escaped first and only a fixed set of inline/block patterns are ever
// promoted to real markup. Links are restricted to http/https/mailto.
//
// Supported syntax:
//   # / ## / ### headings
//   **bold**, *italic*, _italic_
//   `inline code`
//   ```fenced code blocks```
//   [text](https://example.com) links (http, https, mailto only)
//   - bullet lists and 1. numbered lists
//   > blockquote lines
//   --- horizontal rule
//   blank line separated paragraphs, single newlines become <br>
//
// Anything else is rendered as escaped text. The output is intended to be
// dropped into innerHTML on an element with the `.markdown-body` class.

const ESCAPE_RE = /[&<>"']/g;
const ESCAPE_MAP = Object.freeze({
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
});

/** HTML-escape a string for safe interpolation into element content. */
export function escapeHtml(input) {
  return String(input ?? "").replace(ESCAPE_RE, (c) => ESCAPE_MAP[c]);
}

const SAFE_URL_RE = /^(https?:|mailto:)/i;

/** Sanitize a URL for use in href. Returns null when the scheme is unsafe. */
export function sanitizeUrl(raw) {
  const trimmed = String(raw ?? "").trim();
  if (!trimmed) return null;
  // Reject control chars (including newlines) — they have no business in URLs.
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) return null;
  if (trimmed.startsWith("//")) return null;
  if (trimmed.startsWith("#") || trimmed.startsWith("/")) return null;
  if (!SAFE_URL_RE.test(trimmed)) return null;
  return trimmed;
}

/** Strip-only renderer: returns plain text with markdown syntax removed. */
export function markdownToText(src) {
  return String(src ?? "")
    .replace(/```([\s\S]*?)```/g, (_, body) => body)
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/(^|[^*])\*([^*\n]+)\*/g, "$1$2")
    .replace(/(^|\s)_([^_\n]+)_/g, "$1$2")
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, "$1")
    .replace(/^#{1,6}\s+/gm, "")
    .replace(/^>\s?/gm, "")
    .replace(/^[-*]\s+/gm, "")
    .replace(/^\d+\.\s+/gm, "")
    .trim();
}

// --- Inline pass ---------------------------------------------------

function renderInline(escapedLine) {
  // We're given an already-HTML-escaped line. Apply inline transforms in a
  // careful order so each pattern can rely on the previous having run.

  // Inline code: must run first so we don't mangle * or _ inside backticks.
  // We pull each code span out into a placeholder, then restore after the
  // rest of the inline pass — this keeps emphasis transforms from touching
  // code contents.
  const codeSpans = [];
  let out = escapedLine.replace(/`([^`]+)`/g, (_, body) => {
    const idx = codeSpans.push(`<code>${body}</code>`) - 1;
    return `\u0000C${idx}\u0000`;
  });

  // Links: [label](url). The label is already escaped; we re-escape the url
  // defensively after sanitizing.
  out = out.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_, label, url) => {
    // The url here may still carry HTML-escaped characters from the outer
    // escape pass (e.g. &amp;). Undo just those before scheme validation.
    const decoded = url
      .replace(/&amp;/g, "&")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'");
    const safe = sanitizeUrl(decoded);
    if (!safe) return label; // drop the link, keep the visible text
    return `<a href="${escapeHtml(safe)}" target="_blank" rel="noopener noreferrer">${label}</a>`;
  });

  // Bold then italic. Bold uses **…**, italic uses *…* or _…_.
  out = out.replace(/\*\*([^*\n]+)\*\*/g, "<strong>$1</strong>");
  out = out.replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<em>$2</em>");
  out = out.replace(/(^|[\s(])_([^_\n]+)_(?=$|[\s).,!?;:])/g, "$1<em>$2</em>");

  // Restore code placeholders.
  out = out.replace(/\u0000C(\d+)\u0000/g, (_, i) => codeSpans[Number(i)] || "");
  return out;
}

// --- Block pass ----------------------------------------------------

/**
 * Render a markdown string to a safe HTML fragment.
 * The output is guaranteed to contain no raw `<script>` or unsafe `<a>`
 * elements; everything that isn't part of the supported syntax is escaped.
 */
export function renderMarkdown(src) {
  const text = String(src ?? "");
  if (!text.trim()) return "";

  // Pull fenced code blocks out first — their contents must never be touched
  // by inline transforms or paragraph splitting.
  const fences = [];
  const stripped = text.replace(/```([\s\S]*?)```/g, (_, body) => {
    const escaped = escapeHtml(body.replace(/^\n+/, "").replace(/\n+$/, ""));
    const idx = fences.push(`<pre class="md-pre"><code>${escaped}</code></pre>`) - 1;
    return `\u0000F${idx}\u0000`;
  });

  // Normalize line endings and split into blocks separated by blank lines.
  const blocks = stripped.replace(/\r\n?/g, "\n").split(/\n{2,}/);
  const out = [];

  for (const rawBlock of blocks) {
    const block = rawBlock.replace(/^\n+|\n+$/g, "");
    if (!block) continue;

    // Restore standalone code-fence placeholders directly.
    const fenceOnly = block.match(/^\u0000F(\d+)\u0000$/);
    if (fenceOnly) {
      out.push(fences[Number(fenceOnly[1])]);
      continue;
    }

    const lines = block.split("\n");

    // Horizontal rule.
    if (lines.length === 1 && /^-{3,}$/.test(lines[0].trim())) {
      out.push('<hr class="md-hr" />');
      continue;
    }

    // Heading (single-line blocks starting with #).
    const heading = lines.length === 1 ? lines[0].match(/^(#{1,3})\s+(.+)$/) : null;
    if (heading) {
      const level = heading[1].length;
      const body = renderInline(escapeHtml(heading[2].trim()));
      out.push(`<h${level} class="md-h md-h${level}">${body}</h${level}>`);
      continue;
    }

    // Blockquote: every line starts with `>`.
    if (lines.every((l) => /^>\s?/.test(l))) {
      const inner = lines.map((l) => l.replace(/^>\s?/, "")).join("\n");
      const rendered = inner
        .split("\n")
        .map((l) => renderInline(escapeHtml(l)))
        .join("<br />");
      out.push(`<blockquote class="md-quote">${rendered}</blockquote>`);
      continue;
    }

    // Unordered list.
    if (lines.every((l) => /^[-*]\s+/.test(l))) {
      const items = lines.map((l) => {
        const body = renderInline(escapeHtml(l.replace(/^[-*]\s+/, "")));
        return `<li>${body}</li>`;
      });
      out.push(`<ul class="md-list">${items.join("")}</ul>`);
      continue;
    }

    // Ordered list.
    if (lines.every((l) => /^\d+\.\s+/.test(l))) {
      const items = lines.map((l) => {
        const body = renderInline(escapeHtml(l.replace(/^\d+\.\s+/, "")));
        return `<li>${body}</li>`;
      });
      out.push(`<ol class="md-list md-list-ordered">${items.join("")}</ol>`);
      continue;
    }

    // Paragraph: escape each line, run inline transforms, join with <br />.
    const rendered = lines
      .map((l) => renderInline(escapeHtml(l)))
      .join("<br />");
    out.push(`<p class="md-p">${rendered}</p>`);
  }

  // Final pass to restore any code-fence placeholders that ended up nested
  // inside paragraphs (shouldn't really happen, but be defensive).
  return out
    .join("")
    .replace(/\u0000F(\d+)\u0000/g, (_, i) => fences[Number(i)] || "");
}

export const MARKDOWN_ALLOWED_SCHEMES = Object.freeze(["http:", "https:", "mailto:"]);
