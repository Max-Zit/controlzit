# Contributing to ControlZit

Thank you for helping! ControlZit is free software under the GNU AGPLv3.

## Questions, bugs and ideas

- **Bugs:** open an [issue](https://github.com/Max-Zit/controlzit/issues) (or click *Report a bug* in the console) with the ControlZit version, the operating system of the server and the agent, what you did, what happened and what you expected. *Settings → Diagnostics* in the console shows the server log without secrets.
- **Ideas:** open an issue that describes the problem you want to solve.
- **Security problems:** do not open a public issue; see [SECURITY.md](SECURITY.md).

## Code

1. Go (the version in `go.mod`) is all you need: `go build ./cmd/...` and `go test ./...` (the tests start an embedded PostgreSQL).
2. Keep changes focused, with tests for new behavior.
3. Functional changes update the built-in user guide (`internal/web/templates/doc_*.html`) and the UI texts in all catalogs (`internal/web/i18n/`); `go run ./tools/i18n missing sr` lists missing texts.
4. New dependencies must have a license compatible with the AGPLv3; `go run ./tools/licenses` checks it.

By contributing you agree that your contribution is licensed under the GNU AGPLv3.
