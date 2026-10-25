-- Accounts from a directory: Active Directory / LDAP or single sign-on.
-- They have no local password (password_hash stays empty).
ALTER TABLE users ADD COLUMN source text NOT NULL DEFAULT 'local' CHECK (source IN ('local', 'ldap', 'sso'));
ALTER TABLE users ADD COLUMN email text NOT NULL DEFAULT '';
