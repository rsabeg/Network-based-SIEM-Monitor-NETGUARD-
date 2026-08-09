# Database migrations — run in order

1. `netguard_schema.sql` — ⚠️ **naming note:** despite the filename, this file's contents are actually "schema update 4" (the `users` table). The original base schema (`alerts`, `traffic_samples`, `sessions` tables) and `netguard_schema_update_2.sql` / `netguard_schema_update_3.sql` were referenced in the handoff docs but their full SQL text wasn't available in the last exported project snapshot — only `PROJECT_STATE_HANDOFF16.md` (not `17`) has that text. **Before relying on this repo to rebuild the database from scratch, pull those two files from `HANDOFF16.md` or re-export them from the working XAMPP instance**, then rename this file to `netguard_schema_update_4.sql` for consistency.
2. `netguard_schema_update_5.sql` — `remember_tokens` table (persistent "Remember Me")
3. `netguard_schema_update_6.sql` — `user_clears` table (per-user Clear-button cursors)

All migrations are additive (`CREATE TABLE IF NOT EXISTS`) — safe to run once each, in phpMyAdmin's SQL tab, against a database named `netguard`.
