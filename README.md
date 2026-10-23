# Auth Notes

Per-site encrypted notes about which auth method/2FA/email you used. Local only, no sync, no cloud.

> Status: **v0.1.0 — scaffold**. Features ship every 15 minutes via an autonomous agent. See `ROADMAP.md` for what's next.

## Install (dev)

```
git clone https://github.com/Sanjays2402/auth-notes.git
cd auth-notes
```

Then in Chrome: `chrome://extensions` → Developer mode → "Load unpacked" → select this folder.

## Site matching

A note saved while browsing `www.example.com` is treated as the same site as
`example.com`: origins are canonicalized by stripping a single leading `www.`
before storage, and site-scoped lookups match on the canonical origin.

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

## Terms & Disclaimer

By using this project you agree to the following.

- **No warranty.** This software is provided "as is", without warranty of any kind, express or implied, including merchantability, fitness for a particular purpose, and non-infringement.
- **No liability.** To the maximum extent permitted by law, the author and contributors are not liable for any claim, loss, or damage (direct, indirect, incidental, or consequential, including lost data or profits) arising from its use.
- **Your responsibility.** You use it at your own risk and are responsible for complying with the laws that apply to you.
- **Your data.** Keep backups; data loss is possible. If you process other people's personal information, you are responsible for complying with privacy laws such as US state privacy laws (e.g. CCPA), PIPEDA and Quebec's Law 25 (Canada), and the Digital Personal Data Protection Act, 2023 (India).
- **Third parties.** Names, logos, APIs, and services of others belong to their owners and are used for identification only; no affiliation or endorsement is implied.
- **Your statutory rights.** Nothing here limits rights that cannot be waived by agreement, including under consumer-protection laws in the USA, Canada (including Quebec), and India (Consumer Protection Act, 2019).
- **License.** Use, copying, and distribution are governed by the [LICENSE](LICENSE) file; if anything here conflicts with it, the license controls.
