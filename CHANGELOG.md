# Changelog

All notable changes to `attackmap-analyzer-php-laminas` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed — typed signals instead of overloaded `AuthHint`s (AttackMap#258)

- **`auth_hints` now carries only auth signals** (`session`, `jwt`, `auth`). Laminas framework metadata moved to `FrameworkHint` (`framework_hints`) with the same hint strings, which is where core's MVC chain linker and `_extract_prefixed_hints` already look for the `controller:`, `service:` and `laminas_` prefixes:
  - `controller:<FQCN>`, `laminas_controller_mapping` → `FrameworkHint`
  - `service:<FQCN>`, `laminas_service_manager` → `FrameworkHint`
  - `laminas_dependency` (composer.json) → `FrameworkHint`
- **Every signal now cites a line and quotes it.** Routes, external calls, databases, auth/framework hints and secret hints carry `line` and (where the model has it) `evidence_text` via `attackmap.sdk.line_of` / `line_snippet`. `laminas_dependency` and composer-declared Doctrine point at the package's line in `composer.json`; `laminas_controller_mapping` at the first controller reference; `laminas_service_manager` at the `'service_manager'` key (or the first service reference). Framework hints set `confidence` (0.9 dependency, 0.8 controllers/mappings, 0.7 services).
- **Breaking for direct consumers of `ScanResult.auth_hints`:** code that looked for `controller:`/`service:`/`laminas_*` in `auth_hints` must read `framework_hints`. AttackMap core already does.
- New `tests/test_signal_conformance.py` asserts every emitted `AuthHint.hint` is in an explicit auth allow-list and every signal has an in-range `line` and evidence.

### Fixed — AttackMap#253

- **Repo walking now uses `attackmap.sdk.fs`.** `detect()` and `analyze()` walk with `iter_repo_files` and read with `read_source`. Skip dirs are matched by repo-relative name and pruned, so a repo checked out under a `vendor/` directory is analyzed instead of yielding no PHP files.
- **Symlinked files pointing outside the repo are not analyzed**, unreadable files no longer raise out of `analyze()`, and cp1252/latin-1 PHP sources are decoded instead of silently dropped. AttackMap's own report directories are skipped.
- `detect()`'s `module.config.php` probe stops at the first match and no longer looks inside `vendor/` (a vendored `laminas-mvc` alone no longer makes a repo look like a Laminas app).

### Changed

- **Priority 30 → 70** (AttackMap#221). Core now runs analyzers in `(priority, name)` order and merges first-seen-wins, so this framework-specific analyzer runs after the generic `php-web` analyzer (40). Still experimental and opt-in: `attackmap analyze <repo> -m php-laminas`.
- Skip list is now the SDK's `DEFAULT_SKIP_DIRS` (was `vendor`, `.git`, `node_modules`; adds `build`, `dist`, `out`, `target`, virtualenvs and caches).
- Signal `file` paths are always POSIX-style, including on Windows.
- Requires an AttackMap core that ships `attackmap.sdk.fs`.

## [0.1.0] - 2026-06-04

### Added

- Initial public release. Framework-aware Laminas analyzer plugin for AttackMap
- Registered under the `attackmap.analyzers` entry-point group so the core
  AttackMap CLI auto-discovers this analyzer once installed.
- Emits Signal-v2 records (`file:line` citation, evidence text, and confidence
  score) for every signal.

[Unreleased]: https://github.com/mlaify/attackmap-analyzer-php-laminas/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mlaify/attackmap-analyzer-php-laminas/releases/tag/v0.1.0
