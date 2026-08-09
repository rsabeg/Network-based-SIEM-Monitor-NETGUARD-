# NETGUARD — Project Handoff / Continuity Doc

**Last updated:** 2026-07-26 · **Status version:** v10 (superseding all prior handoff files)

> **For any AI reading this:** the person you're helping is a beginner in both frontend and backend development and depends entirely on AI to write code. Work in **small, self-contained steps** — one feature = one complete file, confirmed (usually via a screenshot) before moving to the next. **Never** combine multiple major changes into one response. Give complete, copy-paste-ready files, not diffs or fragments, unless the person asks for a small targeted edit. After any meaningfully completed step, update this file (bump the version at the top) rather than waiting until the end of a session.
>
> This repo is now the **source of truth**. Read the actual files in `backend/`, `sensor/`, and `database/` before trusting any "done" claim written in prose here — code can drift from documentation.

---

## 0. What NETGUARD is

A Mini Network Intrusion Detection System (NIDS) with a live SOC-style dashboard, built for a class demo/viva. See the root [`README.md`](../README.md) for the pitch and [`ARCHITECTURE.md`](ARCHITECTURE.md) for how the pieces fit together.

## 1. Locked-in stack decisions — do not re-litigate

- **Database:** MySQL (physically MariaDB 10.4.32 via XAMPP). Not SQLite/Postgres.
- **Frontend:** plain HTML/CSS/vanilla JS (`login.html` + `index.html`), served via Express static files. Not React.
- **Backend:** Node.js + Express + Socket.io + mysql2. Auth via bcryptjs + express-session.
- **Roles:** `admin` and `viewer`, enforced at the API level (`requireAuth` / `requireAdmin` middleware), not just a DB column.
- **Hosting:** localhost only. Public/cloud hosting (ngrok, Render, Railway, etc.) was considered and rejected — don't suggest it again unless explicitly asked.
- **Sensor:** C++, raw WinSock2 (no libcurl/vcpkg — abandoned due to MSVC-only toolchain issues), Npcap for capture. Detection logic is considered **stable** — future work is on the dashboard/backend/auth side, not new detection rules, unless explicitly requested.
- **Simulated Remediation:** nothing is ever executed for real. See `ARCHITECTURE.md` §4.

## 2. Current status (condensed)

| Feature | Status |
|---|---|
| Sensor — 8 detection rules | ✅ Done. `port_scan`/`syn_flood`/`large_packet` confirmed firing live; the other 5 work per code review but are individually unconfirmed live |
| MySQL persistence | ✅ Done |
| Dashboard UI (7 sections, sidebar shell) | ✅ Done, visually settled |
| Simulated Remediation (Authorize-to-Act) | ✅ Done, confirmed live, gated behind `requireAdmin` |
| Auth core (register/login/session/RBAC) | ✅ Done, confirmed working daily |
| Remember Me (persistent login) | ✅ Code done. **One remaining test:** a specific close-tab/reopen-after-backend-restart browser round trip has not been performed. Low priority. |
| Clear-button persistence (`user_clears`) | ✅ Done and live-tested |
| Session Log live alert count fix | ✅ Done and live-tested |
| **Acknowledge / Unacknowledge button** | ❌ **Not started — this is the active next step.** |

## 3. What to build next: Acknowledge / Unacknowledge

The `alerts` table already has unused columns for this: `acknowledged`, `acknowledged_by` (FK to `users.id`), `acknowledged_at`. Nothing has been built yet — no endpoint, no UI.

**Plan:**
- New backend endpoint(s), same shape as Authorize/Dismiss: `POST /api/alerts/:id/acknowledge`, maybe `/unacknowledge`. Likely gated behind `requireAuth` (any logged-in user, not just admin — confirm with the person first), since acknowledging is a lighter action than authorizing remediation.
- On acknowledge: set `acknowledged = true`, `acknowledged_by = req.session.user.id`, `acknowledged_at = NOW()`. On unacknowledge: clear them (or flip `acknowledged` back to false).
- Frontend: a button in the Live Alert Feed / alert row UI, plus a visual badge/pill showing acknowledged state and who acknowledged it — reuse the existing `.action-status-pill` pattern already used for Authorize/Dismiss.
- Socket.io event to push the update live to all connected dashboards, same pattern as `alert_action_updated`.

Build this fresh, in small steps, one file at a time, with a checkpoint after each step.

## 4. Backlog (after Acknowledge/Unacknowledge)

1. Re-confirm `index.html` actually redirects to `login.html` on a 401 from `/api/auth/me` as a dedicated test (the code exists, auth works daily, just not explicitly re-tested).
2. SOAR / multi-source orchestration — **explicitly skipped**, not deferred. A "future work" slide is the honest answer if asked in the viva.
3. Individually confirm the not-yet-witnessed detection rules firing live: `icmp_flood`, stealth scans, `brute_force_admin`, `dns_tunneling`, `blacklisted_ip`.
4. Rehearse the demo end-to-end; prepare a screen-recording backup.
5. Filtering/search on the alert feed; a basic audit log of who acknowledged/authorized what (easier once item 3 above — Acknowledge/Unacknowledge — is built).
6. An `authorized_by` column on `alerts` (parallel to `acknowledged_by`) — consider once Acknowledge/Unacknowledge is done.

## 5. Working process (how the person wants to be helped)

1. **Plan first in plain text, no code** — describe exactly what will change and confirm before writing anything.
2. **One tiny step at a time** — never combine multiple major changes into a single response.
3. **Full files per step** — complete, copy-paste-ready files, not fragments or diffs.
4. **Targeted edits for small tweaks** — don't regenerate a whole file for a one-line change.
5. **Update this doc after every completed step** — without waiting to be asked.
6. **Flag expensive operations upfront** — before generating large files, say so, so the person can sequence around credit/token limits.
7. **Screenshot confirmation between steps** — the person verifies visually before the next step begins.

## 6. Environment facts (don't re-derive)

- Windows laptop, XAMPP (MariaDB 10.4.32), Node.js/npm, MinGW g++, WpdPack (Npcap SDK).
- Sensor build command: `g++ ids_real.cpp -o ids_real.exe -IC:\WpdPack\Include -LC:\WpdPack\Lib\x64 -lwpcap -lPacket -lws2_32`
- Windows Firewall inbound rule for TCP port 8000 is already in place (needed for e.g. a Kali VM to reach the backend).
- Windows Wi-Fi IP changes between sessions — reconfirm via `ipconfig` before referencing it.
- Attack traffic source for testing: Kali Linux VM in VirtualBox, **Bridged** network mode (not NAT/Host-Only) — required because Windows suppresses self-scan traffic on physical NIC captures.
- ip-api.com used for free geolocation, no API key needed.
- If a curl/network test to the backend hangs (rather than instantly failing or succeeding), suspect Windows Firewall before the Node/Express code.

---

*When resuming work: read this file first, then check the actual code in `backend/`, `sensor/`, and `database/` before writing anything new.*
