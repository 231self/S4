-- API key expiry (unix seconds) and envelope-encryption public key.
alter table api_keys add column if not exists expires_at bigint;
alter table api_keys add column if not exists public_key_pem text;
