-- NETGUARD - schema update 4: Auth system (users table)
-- ADDITIVE ONLY - does NOT touch alerts, traffic_samples, sessions, or
-- any existing table/rows. Safe to run once in phpMyAdmin's SQL tab.
--
-- NOTE: the original base schema (netguard_schema.sql) already defines a
-- `users` table with the same shape this recreates via IF NOT EXISTS -
-- this is a safety-net re-assertion, not a conflicting second version.

USE netguard;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('admin', 'viewer') NOT NULL DEFAULT 'viewer',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
