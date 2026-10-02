# Changelog

All notable changes to `attackmap-analyzer-terraform` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Walk and read the repo with the shared `attackmap.sdk` helpers (`iter_repo_files`, `read_source`, `rel`, `line_of`) instead of a local `rglob` + `SKIP_DIRS` walk (mlaify/AttackMap#253).
- The skip list is now AttackMap's shared `DEFAULT_SKIP_DIRS` plus `.terraform/`, so `.tf` files under in-repo `build/`, `dist/`, `out/`, `target/`, `venv/` etc. directories are no longer scanned.

### Fixed

- A repo checked out under a directory named like a skip dir (e.g. `.../vendor/...`) was silently not analyzed, because skip dirs were matched against absolute path parts.
- Symlinked files pointing outside the repo are no longer followed and analyzed.
- cp1252/latin-1 encoded files are analyzed instead of silently dropped, and an unreadable file no longer raises out of `analyze()`.
- `files_scanned` no longer counts files that could not be read.

## [0.1.0] - 2026-06-04

### Added

- Initial public release. Terraform / HCL infrastructure-as-code analyzer plugin for AttackMap (AWS, Azure, GCP resources; IAM wildcards; open security groups; secret resources).
- Registered under the `attackmap.analyzers` entry-point group so the core
  AttackMap CLI auto-discovers this analyzer once installed.
- Emits Signal-v2 records (`file:line` citation, evidence text, and confidence
  score) for every signal.

[Unreleased]: https://github.com/mlaify/attackmap-analyzer-terraform/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mlaify/attackmap-analyzer-terraform/releases/tag/v0.1.0
