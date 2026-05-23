# Roadmap

This file is the agent's task queue. Unchecked items get implemented in order. When all items are checked, the agent appends a new batch of 10.

- [x] MV3 manifest + service worker scaffolding
- [ ] Master password setup (PBKDF2 → AES-GCM key)
- [ ] Per-site notes: auth method, email used, 2FA backup location
- [ ] Auto-detect current site, surface matching note in popup
- [ ] Encrypt all notes at rest in chrome.storage.local
- [ ] Lock/unlock with master password
- [ ] Auto-lock after N minutes idle
- [ ] Search across all sites
- [ ] Export encrypted backup (.json.enc)
- [ ] Import encrypted backup
- [ ] Tag system (work, personal, banking, etc.)
- [ ] Quick-add from popup with current URL prefilled
- [ ] Audit log of access events (encrypted)
- [ ] Liquid-glass popup UI
- [ ] Dark/light theme
