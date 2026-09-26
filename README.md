# attackmap-analyzer-php-laminas

> [!IMPORTANT]
> **Looking for help.** AttackMap is looking for contributors and co-maintainers.
> Development is paused until more hands join — if you'd like to help with the
> core engine, an analyzer, the macOS app, or the docs, open an issue on
> [mlaify/AttackMap](https://github.com/mlaify/AttackMap/issues) to say hello.
> Security reports are still welcome at [security@mlaify.io](mailto:security@mlaify.io).

Framework-aware Laminas analyzer for [AttackMap](https://github.com/mlaify/AttackMap).

This module focuses on structured signal extraction for Laminas/Zend MVC projects:

- route paths from config arrays
- controller mapping hints
- service-manager mapping hints
- broad PHP security signals (outbound calls, datastore, auth, secret hints)

## Analyzer identity

- `name`: `php-laminas`
- `display_name`: `PHP Laminas Analyzer`
- `version`: `0.1.0`
- `experimental`: `true`
- `enabled_by_default`: `false`

## Detection

`detect(repo_path)` returns true when one or more Laminas indicators exist:

- composer dependencies beginning with `laminas/` or `zendframework/`
- `config/application.config.php`
- any `module.config.php`
- `module/` directory

## Notes

This analyzer is heuristic and intentionally avoids AST parsing in this first iteration.
