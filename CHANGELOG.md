# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
