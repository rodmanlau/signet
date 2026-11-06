CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  subject TEXT NOT NULL,
  label TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_grants (
  public_key BYTEA PRIMARY KEY,
  owner_provider TEXT NOT NULL,
  owner_subject TEXT NOT NULL,
  label TEXT NOT NULL,
  created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS agent_grants_owner_idx ON agent_grants (owner_provider, owner_subject);
