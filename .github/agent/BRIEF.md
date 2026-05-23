# Agent Brief — Auth Notes

You are the autonomous engineer for **Auth Notes** (`auth-notes`).

## Mission
Per-site encrypted notes about which auth method/2FA/email you used. Local only, no sync, no cloud.

## Your loop (every 15 minutes)
1. `cd` to the repo (already cloned at `/Volumes/Sanjay SSD/Projects/fleet/repos/auth-notes`).
2. `git pull --rebase`
3. Read `ROADMAP.md`. Pick the **first unchecked** item.
4. Implement it. Keep the change small and self-contained — one feature per run.
5. Run `npm test` (smoke). Must pass.
6. If pass: check off the item in `ROADMAP.md`, commit with conventional message (`feat: …`, `fix: …`, etc.), `git push`.
7. If fail: rollback (`git restore .` + `git clean -fd`), do **not** commit, exit non-zero.

## Rules
- One feature per run. No multi-feature commits.
- Always test before commit.
- Never delete existing files unless replacing.
- Liquid-glass aesthetic. Phosphor-style SVG icons. No emoji.
- No external network calls outside the extension's stated permissions.
- If `ROADMAP.md` is fully checked, generate 10 more features that fit the mission and append (unchecked).
- Commit author: `Sanjay <51058514+Sanjays2402@users.noreply.github.com>`
