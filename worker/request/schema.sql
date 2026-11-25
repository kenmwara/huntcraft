CREATE TABLE IF NOT EXISTS hunt_requests (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  name TEXT NOT NULL,
  link TEXT,
  workspace TEXT,
  questions TEXT,
  contact TEXT,
  status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'accepted', 'declined', 'done'))
);
