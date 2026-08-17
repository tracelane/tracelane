-- 0001_init.sql
-- Creates the notifications table for landing-page email capture.

CREATE TABLE IF NOT EXISTS notifications (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  email       TEXT NOT NULL UNIQUE,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  source      TEXT,
  ip_country  TEXT,
  user_agent  TEXT
);

CREATE INDEX IF NOT EXISTS idx_notifications_email      ON notifications(email);
CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at);
