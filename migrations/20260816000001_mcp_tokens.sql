-- MCP bearer tokens: self-contained `s4m_...` credentials used by the S4 MCP
-- server. The full token is the credential; only its SHA-256 hash is stored,
-- so a DB leak does not expose usable tokens (unlike API keys, where the
-- key_id is public and only the secret is hashed).
CREATE TABLE IF NOT EXISTS mcp_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL DEFAULT 'default',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at BIGINT
);

CREATE INDEX IF NOT EXISTS idx_mcp_tokens_user ON mcp_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_mcp_tokens_hash ON mcp_tokens (token_hash);
