# Roadmap

This file is the agent's task queue. Unchecked items get implemented in order. When all items are checked, the agent appends a new batch of 10.

- [x] MV3 manifest + service worker scaffolding
- [x] Master password setup (PBKDF2 → AES-GCM key)
- [x] Per-site notes: auth method, email used, 2FA backup location
- [x] Auto-detect current site, surface matching note in popup
- [x] Encrypt all notes at rest in chrome.storage.local
- [x] Lock/unlock with master password
- [x] Auto-lock after N minutes idle
- [x] Search across all sites
- [x] Export encrypted backup (.json.enc)
- [x] Import encrypted backup
- [x] Tag system (work, personal, banking, etc.)
- [x] Quick-add from popup with current URL prefilled
- [x] Audit log of access events (encrypted)
- [x] Liquid-glass popup UI
- [x] Dark/light theme
- [x] Password strength hints recorded per site (length, complexity bucket)
- [x] Recovery codes vault section with masked reveal
- [x] Per-note last-used date + auto-sort by recency
- [x] Bulk tag editor with multi-select
- [x] Keyboard shortcut to open popup on current tab
- [x] Favicon thumbnail next to each site entry
- [x] Settings page (options.html) for idle timeout, theme, PBKDF2 iterations
- [x] Quick-copy button for email-used field with auto-clear clipboard after 20s
- [x] Duplicate-email detector across sites (security hygiene)
- [x] Onboarding tour for first unlock
