-- NETGUARD - schema update 6: Per-user "Clear" cursors
-- ADDITIVE ONLY - does NOT touch users, alerts, traffic_samples, sessions,
-- or remember_tokens. Safe to run once in phpMyAdmin's SQL tab (select the
-- `netguard` database first, same as updates 4-5).

USE netguard;

CREATE TABLE IF NOT EXISTS user_clears (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  view_name ENUM('recent_activity', 'live_alerts', 'traffic') NOT NULL,
  cleared_at DATETIME NOT NULL,
  UNIQUE KEY uq_user_clears_user_view (user_id, view_name),
  CONSTRAINT fk_user_clears_user
    FOREIGN KEY (user_id) REFERENCES users(id)
    ON DELETE CASCADE
) ENGINE=InnoDB;

-- What this table is for:
--   One row = "this user last hit Clear on this view at this moment."
--   It does NOT store which alerts were cleared, and it never touches
--   the `alerts` or `traffic_samples` tables - those keep every row
--   forever, for every user, exactly like today. This table only
--   remembers a per-user, per-view timestamp cursor: "don't show me
--   anything older than this, on this view, until something new
--   actually arrives." That's what makes Clear survive a refresh
--   without deleting anything.
--
-- user_id:
--   Whose cursor this is. ON DELETE CASCADE means if a user account is
--   ever deleted, their clear cursors go with it - no orphaned rows.
--
-- view_name:
--   Which of the three Clear buttons this cursor belongs to -
--   'recent_activity' (Overview page), 'live_alerts' (Live Alerts page),
--   or 'traffic' (Live Traffic Monitor). Kept separate on purpose:
--   clearing one view (e.g. Live Alerts) should NOT also blank out a
--   different view (e.g. Recent Activity) that happens to source from
--   the same underlying alerts.
--
-- cleared_at:
--   The moment this user last clicked Clear on this view. The backend
--   will treat this as "hide anything with a timestamp at or before
--   this, on this view, for this user" - genuinely new alerts (newer
--   timestamp) always show up right away regardless of this cursor.
--
-- UNIQUE KEY uq_user_clears_user_view:
--   Each user has AT MOST one row per view - clicking Clear again just
--   moves the existing cursor forward (an "upsert"), it doesn't pile up
--   old rows. This is what the next server.js step will use
--   (INSERT ... ON DUPLICATE KEY UPDATE) to update-or-create in one query.
--
-- ON DELETE CASCADE:
--   Same reasoning as remember_tokens (update 5) - deleting a user
--   cleans up everything that points at them, no manual cleanup needed.
