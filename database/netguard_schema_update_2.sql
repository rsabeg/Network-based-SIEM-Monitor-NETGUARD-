-- NETGUARD - schema update 2: Simulated Remediation / Authorize-to-Act feature
-- ADDITIVE ONLY - does NOT drop or touch existing tables/rows.
-- Safe to run even with real alert data already in the `alerts` table.
-- Run this once in phpMyAdmin's SQL tab (select the `netguard` database first).
-- Pulled verbatim from PROJECT_STATE_HANDOFF6.md section 4.3.

USE netguard;

ALTER TABLE alerts
  ADD COLUMN action_recommended VARCHAR(150) NULL AFTER signature,
  ADD COLUMN action_status ENUM('none','pending','authorized','dismissed')
      NOT NULL DEFAULT 'none' AFTER action_recommended,
  ADD COLUMN action_authorized_at TIMESTAMP NULL AFTER action_status;

-- action_recommended: human-readable suggested response, e.g.
--   "Block source IP — port scan detected"
--   NULL for alert types that don't warrant an action suggestion (e.g. low-severity anomalies).
--
-- action_status:
--   'none'       - no action was recommended for this alert
--   'pending'    - an action IS recommended and is awaiting your authorization
--   'authorized' - you clicked "Authorize" - action is SIMULATED as taken (no real
--                  firewall/network command is ever executed by this system)
--   'dismissed'  - you clicked "Dismiss" - recommendation rejected, no action taken
--
-- action_authorized_at: timestamp of when you authorized it (NULL until then).
--
-- NOTE: This deliberately does NOT add an "authorized_by" column yet, since that
-- would need a real logged-in user (users table exists but auth/login is not built
-- yet at the point this migration was written). Add authorized_by INT + FK to
-- users.id if you want to track which admin authorized each action, the same way
-- acknowledged_by already works.
