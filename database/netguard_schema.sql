-- NETGUARD - schema update 4: Auth system (users table)
-- ADDITIVE ONLY - does NOT touch alerts, traffic_samples, sessions, or
-- any existing table/rows. Safe to run once in phpMyAdmin's SQL tab
-- (select the `netguard` database first, same as update_2 and update_3).

USE netguard;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('admin', 'viewer') NOT NULL DEFAULT 'viewer',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- What this table is for:
--   One row = one user account. This is a completely new table - it has
--   nothing to do with the `sessions` table you already have (that one
--   tracks backend process run history, this one tracks user accounts).
--
-- username:
--   Must be unique - the database itself will reject a duplicate
--   username at the SQL level, as a safety net on top of whatever
--   checking the backend does.
--
-- password_hash:
--   NEVER a plaintext password. This column will store a bcrypt hash
--   (a long scrambled string), which is what the next step (the
--   registration endpoint) will generate. 255 characters is plenty of
--   room for a bcrypt hash.
--
-- role:
--   Only two allowed values: 'admin' or 'viewer'. Defaults to 'viewer'
--   if not specified, so a mistake during registration can't
--   accidentally create an admin account.
--
-- created_at:
--   Set automatically the instant a user registers - no action needed
--   from the backend code for this one.
