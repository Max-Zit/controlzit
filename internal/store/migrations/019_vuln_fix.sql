-- The version that fixes a vulnerability of a Linux package ('none': no
-- fix in that release yet; empty: not known, for example NVD findings).
ALTER TABLE device_vulns ADD COLUMN fix text NOT NULL DEFAULT '';
