-- Linux agents run bash and sh scripts.
ALTER TABLE script_runs DROP CONSTRAINT script_runs_shell_check;
ALTER TABLE script_runs ADD CONSTRAINT script_runs_shell_check CHECK (shell IN ('powershell', 'cmd', 'bash', 'sh'));
ALTER TABLE scripts DROP CONSTRAINT scripts_shell_check;
ALTER TABLE scripts ADD CONSTRAINT scripts_shell_check CHECK (shell IN ('powershell', 'cmd', 'bash', 'sh'));
