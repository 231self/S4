-- Encrypted API key secret envelope for SigV4 verification.
alter table api_keys add column if not exists secret_encrypted text;
