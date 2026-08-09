# Database migrations — run in order

Run each file once, in phpMyAdmin's SQL tab, against a database named `netguard`.

| # | File | Adds |
|---|---|---|
| 1 | `netguard_schema.sql` | Base schema — `users`, `alerts`, `traffic_samples` + indexes |
| 2 | `netguard_schema_update_2.sql` | Simulated Remediation columns on `alerts` (`action_recommended`, `action_status`, `action_authorized_at`) |
| 3 | `netguard_schema_update_3.sql` | `sessions` table — one row per backend process run |
| 4 | `netguard_schema_update_4.sql` | `users` table safety-net re-assertion (`IF NOT EXISTS`) |
| 5 | `netguard_schema_update_5.sql` | `remember_tokens` table — persistent "Remember Me" |
| 6 | `netguard_schema_update_6.sql` | `user_clears` table — per-user Clear-button cursors |

All migrations after #1 are additive (`CREATE TABLE IF NOT EXISTS` / `ALTER TABLE ADD COLUMN`) — safe to run in sequence on a fresh database, or against an existing one that only has #1 applied.

> **Provenance note:** files #1, #2, #4, #5, #6 are pulled verbatim from the project's `PROJECT_STATE_HANDOFF*.md` history. File #3 (`sessions` table) was only ever described in prose in every surviving handoff, never pasted as raw SQL — it's been reconstructed from the exact column list in `PROJECT_STATE_HANDOFF9.md` and matches the confirmed-working column semantics described there. If you have direct phpMyAdmin access to the original machine, a quick `DESCRIBE sessions;` is worth running to confirm it matches exactly.
