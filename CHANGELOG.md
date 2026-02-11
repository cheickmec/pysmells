# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.5](https://github.com/cheickmec/smellcheck/compare/v0.2.4...v0.2.5) (2026-02-11)


### Features

* baseline support, git hooks, and docs updates ([#17](https://github.com/cheickmec/smellcheck/issues/17)) ([b9683d8](https://github.com/cheickmec/smellcheck/commit/b9683d81f536679389111e30375e2a36e99abc5a))
* implement unified SC code naming system ([#4](https://github.com/cheickmec/smellcheck/issues/4)) ([481bc52](https://github.com/cheickmec/smellcheck/commit/481bc52f1d687d4f1586a4cdcb1316566dce8813))


### Miscellaneous

* add doc-alignment pre-commit hook ([#18](https://github.com/cheickmec/smellcheck/issues/18)) ([89b9e78](https://github.com/cheickmec/smellcheck/commit/89b9e78599c390932adc4790c11d60943044d62e))
* add pre-push hook to block direct pushes to main ([1996ebc](https://github.com/cheickmec/smellcheck/commit/1996ebc61da9134a621c71ac8a4f2e4bd1516339))

## [0.2.4](https://github.com/cheickmec/smellcheck/compare/v0.2.3...v0.2.4) (2026-02-11)


### Bug Fixes

* use absolute URL for logo so it renders on PyPI ([1156796](https://github.com/cheickmec/smellcheck/commit/1156796a40d0c00c5beacb408f4e47429e145612))

## [0.2.3](https://github.com/cheickmec/smellcheck/compare/v0.2.2...v0.2.3) (2026-02-11)


### Bug Fixes

* replace placeholder emails with GitHub contact methods ([da5b152](https://github.com/cheickmec/smellcheck/commit/da5b152004b727a2ff44cdae7005827dd48c8184))


### Documentation

* add CI, downloads, pre-commit, and ruff badges ([b1ad9c0](https://github.com/cheickmec/smellcheck/commit/b1ad9c0ca260aa491d7e6a1e86d9919f79aad3ad))

## [0.2.2](https://github.com/cheickmec/smellcheck/compare/v0.2.1...v0.2.2) (2026-02-11)


### Bug Fixes

* use solid white background for logo ([a4580f3](https://github.com/cheickmec/smellcheck/commit/a4580f3df2c4b944ba7b8814035aa3f8c0b5a4b0))


### Documentation

* add project logo and README badges ([a54f67a](https://github.com/cheickmec/smellcheck/commit/a54f67a4e6523cbc18d063fd5bc71a6eb4e91f28))

## [0.2.1](https://github.com/cheickmec/smellcheck/compare/v0.2.0...v0.2.1) (2026-02-11)


### Features

* initial release -- 82-pattern Python refactoring skill with AST detector ([e96f750](https://github.com/cheickmec/smellcheck/commit/e96f7507e6739bb3463dca93e38ed04bc6cf1597))
* restructure for PyPI, GitHub Action, pre-commit, and Agent Skills distribution ([e1bf50b](https://github.com/cheickmec/smellcheck/commit/e1bf50b2f4f1b8191903a84c7d262a0c312f163d))


### Bug Fixes

* address 9 code review findings (P1-P3) ([39a62c0](https://github.com/cheickmec/smellcheck/commit/39a62c0b2ce9fb0ce00f54e8dc4e4a97fddfc792))


### Documentation

* add community files for OSS maturity ([8b7fc5f](https://github.com/cheickmec/smellcheck/commit/8b7fc5fcc81f27c58469f220fd33483a116ab07c))
* update README for cross-platform compatibility and SEO ([aecccba](https://github.com/cheickmec/smellcheck/commit/aecccba107b831b7206c543e1a1b34641a0c6903))


### Miscellaneous

* add CHANGELOG.md, fix version to 0.1.1 ([82aae13](https://github.com/cheickmec/smellcheck/commit/82aae130e0830ce38e4f0f1d46c26c095619ee33))
* add pre-commit hook to prevent direct commits to main ([b23e812](https://github.com/cheickmec/smellcheck/commit/b23e812f123f551ad181d1262959e47ff503d1c0))
* rename project from pysmells to smellcheck ([71589cc](https://github.com/cheickmec/smellcheck/commit/71589cc6efa36085d7c2bcc0e4d39c11edad1155))

## [0.1.1] - 2026-02-11

### Fixed
- Import analysis now captures full dotted paths, fixing under-reporting of #CYC, #UDE, #FIO on package-based repos
- RFC metric counts distinct external method calls (not class names), correctly measuring response set size
- elif chains no longer produce duplicate #014 and #068 findings
- #058 no longer false-positives on `ExitStack.enter_context(open(...))`
- Single-file scans now run per-class OO metrics (LCOM, CBO, RFC, MID)
- CLI docs updated with correct script path from repo root
- Corrected detection counts: 40 per-file + 10 cross-file + 5 OO metrics = 55
- Added missing #007 (extract class) to per-file detection table
- Fixed SKILL.md smell-to-file mappings (003, 005, 006, 008, MID pointed to wrong reference files)
- `--min-severity` now validates input and rejects invalid values with clear error message

## [0.1.0] - 2026-02-10

### Added
- AST-based smell detector with 55 automated checks (stdlib-only, zero dependencies)
  - 40 per-file patterns (#001-#070, #CC)
  - 10 cross-file patterns (#013, #CYC, #GOD, #FE, #SHO, #DIT, #WHI, #INT, #SPG, #UDE)
  - 5 OO metrics (#LCOM, #CBO, #FIO, #RFC, #MID)
- 82 refactoring patterns with before/after examples across 8 reference files
- Agent Skills plugin structure for Claude Code, Codex CLI, Cursor, Copilot, Gemini CLI, Roo Code
- JSON output mode for CI/CD integration
- Severity filtering (`--min-severity info|warning|error`)

[0.1.1]: https://github.com/cheickmec/smellcheck/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/cheickmec/smellcheck/releases/tag/v0.1.0
