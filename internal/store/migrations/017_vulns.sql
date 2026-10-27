-- Vulnerability data from public databases, cached: the CVEs of a product
-- (NVD) or the vulnerabilities of a package version (OSV), and OSV details.
CREATE TABLE vuln_sources (
    key        text PRIMARY KEY, -- nvd:<vendor>:<product> or osv:<ecosystem>:<package>:<version>
    data       jsonb NOT NULL,
    fetched_at timestamptz NOT NULL
);

CREATE TABLE vuln_details (
    id         text PRIMARY KEY,
    data       jsonb NOT NULL,
    fetched_at timestamptz NOT NULL
);

-- The vulnerabilities found on each device by the last scan.
CREATE TABLE device_vulns (
    device_id bigint NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    vuln_id   text NOT NULL,
    product   text NOT NULL,
    version   text NOT NULL,
    severity  text NOT NULL, -- critical, high, medium, low, unknown
    score     real NOT NULL DEFAULT 0,
    summary   text NOT NULL DEFAULT '',
    source    text NOT NULL, -- nvd, osv
    PRIMARY KEY (device_id, vuln_id, product)
);
