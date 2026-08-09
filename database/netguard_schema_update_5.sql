-- NETGUARD - schema update 5: Persistent "Remember Me" tokens
-- ADDITIVE ONLY - does NOT touch users, alerts, traffic_samples, or
-- sessions. Safe to run once in phpMyAdmin's SQL tab (select the
-- `netguard` database first, same as updates 2-4).

USE netguard;

CREATE TABLE IF NOT EXISTS remember_tokens (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  selector VARCHAR(24) NOT NULL UNIQUE,
  validator_hash VARCHAR(255) NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_remember_tokens_user
    FOREIGN KEY (user_id) REFERENCES users(id)
    ON DELETE CASCADE
) ENGINE=InnoDB;

-- What this table is for:
--   One row = one "remember me" token issued to one browser. This is
--   what makes remember-me survive a backend restart or the 8-hour
--   express-session cookie expiring - completely separate from the
--   in-memory session store server.js already uses for normal logins.
--
-- selector:
--   A short random public identifier sent back to the browser inside
--   the remember-me cookie alongside the validator. Used to look the
--   row up quickly (SELECT ... WHERE selector = ?) without ever
--   needing to compare secrets in the query itself. UNIQUE so two
--   tokens can never collide.
--
-- validator_hash:
--   NEVER the raw validator. The raw validator lives only in the
--   cookie on the user's machine; this column stores a one-way hash
--   of it (bcrypt, same as password_hash). On each visit, the server
--   looks up the row by selector, then hashes the validator from the
--   cookie and compares it to this column - so even a full dump of
--   this table can't be used to log in as anyone.
--
-- expires_at:
--   When this token stops being honored. The backend will set this a
--   good distance in the future (e.g. 30 days) when the token is
--   issued, and should delete/ignore any row where expires_at has
--   passed.
--
-- ON DELETE CASCADE:
--   If a user row is ever deleted, their remember-me tokens are
--   deleted automatically - no orphaned tokens left pointing at a
--   user_id that no longer exists.
--
-- created_at:
--   Set automatically the instant a token is issued - useful later if
--   you want a "manage your logged-in devices" list.
