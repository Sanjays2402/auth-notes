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
- [ ] Liquid-glass popup UI
- [ ] Dark/light theme
