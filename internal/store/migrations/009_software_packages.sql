-- Software library: installers (MSI, EXE) uploaded to the server and
-- installed on devices as jobs (script_jobs with shell 'package', the body
-- holds a copy of the install command).
CREATE TABLE software_packages (
    id            bigserial PRIMARY KEY,
    name          text NOT NULL,
    version       text NOT NULL DEFAULT '',
    description   text NOT NULL DEFAULT '',
    file_name     text NOT NULL,
    kind          text NOT NULL CHECK (kind IN ('msi', 'exe')),
    sha256        text NOT NULL,
    size          bigint NOT NULL,
    args          text NOT NULL DEFAULT '',
    success_codes int[] NOT NULL DEFAULT '{0,1641,3010}',
    updated_by    text NOT NULL,
    updated_at    timestamptz NOT NULL,
    UNIQUE (name, version)
);

ALTER TABLE script_runs DROP CONSTRAINT script_runs_shell_check;
ALTER TABLE script_runs ADD CONSTRAINT script_runs_shell_check CHECK (shell IN ('powershell', 'cmd', 'bash', 'sh', 'package'));
