-- NETGUARD - schema update 3: Session lifecycle tracking (`sessions` table)
-- ADDITIVE ONLY - does NOT touch `alerts`, `traffic_samples`, or `users`.
-- Safe to run once in phpMyAdmin's SQL tab (select the `netguard` database first).
--
-- RECONSTRUCTION NOTE: no raw SQL for this migration survived in any of the
-- project's PROJECT_STATE_HANDOFF*.md files - it was only ever described in
-- prose (see PROJECT_STATE_HANDOFF9.md, "Step 1"). This file is reconstructed
-- from that exact column list and confirmed-working column semantics, written
-- in the same style/conventions as the other migration files in this folder.
-- If you still have direct phpMyAdmin access to the original database, it's
-- worth a quick `DESCRIBE sessions;` to confirm this matches exactly before
-- treating it as gospel on a fresh machine.

USE netguard;

CREATE TABLE IF NOT EXISTS sessions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ended_at TIMESTAMP NULL,
  total_alerts INT NULL,
  high_severity_count INT NULL
) ENGINE=InnoDB;

-- What this table is for:
--   One row = one continuous run of the Node backend process - from the
--   instant server.js boots, to a clean Ctrl+C (SIGINT) shutdown. This is
--   completely separate from express-session (login sessions) used
--   elsewhere in the backend - this table tracks BACKEND PROCESS
--   lifecycle, not "who is logged in."
--
-- started_at:
--   Set the instant startSession() runs (before server.listen()), via
--   an INSERT with no explicit value - defaults to NOW().
--
-- ended_at:
--   NULL while the process is running. Only ever written by
--   endSession(), which is ONLY called from the SIGINT handler. A
--   forceful kill (crash, Task Manager "End Task") never runs
--   endSession() - the row is deliberately left with ended_at = NULL
--   forever, which the dashboard's Session Log page interprets as
--   "did not shut down cleanly."
--
-- total_alerts / high_severity_count:
--   NULL until endSession() computes and writes them on a clean
--   shutdown - COUNT(*) and COUNT(*) WHERE severity = 'high' respectively,
--   for every alert with created_at >= this session's started_at. For the
--   CURRENTLY RUNNING session, the backend computes these LIVE on every
--   GET /api/sessions request instead of relying on this column (see
--   server.js) - endSession() then writes the final frozen values here
--   once, on shutdown.
