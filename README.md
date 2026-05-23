# Auth Notes

Per-site encrypted notes about which auth method/2FA/email you used. Local only, no sync, no cloud.

> Status: **v0.1.0 — scaffold**. Features ship every 15 minutes via an autonomous agent. See `ROADMAP.md` for what's next.

## Install (dev)

```
git clone https://github.com/Sanjays2402/auth-notes.git
cd auth-notes
```

Then in Chrome: `chrome://extensions` → Developer mode → "Load unpacked" → select this folder.

## Permissions

- `storage`
- `activeTab`


## Roadmap

- [ ] MV3 manifest + service worker scaffolding
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

## License

MIT — see [LICENSE](LICENSE).
