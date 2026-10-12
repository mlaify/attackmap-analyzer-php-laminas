# attackmap-analyzer-php-laminas

> [!IMPORTANT]
> **Active development, slow pace.** AttackMap is under active development, but
> progress may be slow until more contributors or co-maintainers join. Help is
> very welcome with the core engine, an analyzer, the macOS app, or the docs —
> see [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue on
> [mlaify/AttackMap](https://github.com/mlaify/AttackMap/issues) to say hello.
> Security reports are still welcome at [security@mlaify.io](mailto:security@mlaify.io).

Framework-aware Laminas analyzer for [AttackMap](https://github.com/mlaify/AttackMap).

This module focuses on structured signal extraction for Laminas/Zend MVC projects:

- route paths from the `'router' => ['routes' => [...]]` config tree, walked structurally (see [Routes](#routes)); route *names* such as navigation's `'route' => 'home'` are not routes
- Mezzio/Expressive routes (`$app->get('/x', ...)`, `->post/put/patch/delete/any`, `$app->route('/x', $mw, ['GET', 'POST'])`) in files that reference `Mezzio\` or `Zend\Expressive\`
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

- composer dependencies beginning with `laminas/`, `zendframework/` or `mezzio/`
- a `module/` directory together with `config/application.config.php`
- any `module.config.php` outside `vendor/` (and the other shared skip dirs)

A generic `src/`, `app/` or `config/` directory on its own is not enough.

## Routes

Router config is read with a small PHP-array tokenizer (`phparray.py`) that balances `[`/`]` and `array(`/`)` and skips strings, heredocs and comments, so a route is reported with its full path:

- **`child_routes` are joined** onto the parent path: `'/admin'` → `'/users'` → `'/:id'` is `/admin/users/:id`. A parent with children is itself a route only with `'may_terminate' => true`.
- **Method routes** (`'type' => Method::class, 'options' => ['verb' => 'post']`, or `'get,head'`) set the HTTP method on the parent's path instead of adding a path.
- **Segment optional parts are expanded progressively**: the minimal form, then one more optional group opened at a time in source order, at most 4 paths per route. `/:controller[/:action[/:id]]` gives `/:controller`, `/:controller/:action` and `/:controller/:action/:id`; sibling groups `[/a][/b]` give `''`, `/a`, `/a/b` (not `/b` alone). Children join onto the parent's minimal form. A trailing `[/]` doesn't add a path; `:id{-}` delimiters and translated `{literal}` parts are normalized.
- `Regex` routes use their `spec` (`%id%` → `:id`); `Hostname`/`Scheme` routes add no path; Part, Wildcard, Query and console routes are skipped.
- **Config merged across modules**: a module's `'admin' => ['child_routes' => [...]]` stub (no type or route of its own) joins onto the `admin` route another module defines, as Laminas' config merge does. A stub extending a route no file defines is skipped.
- A file that only `return`s a route map (required from a router config) is walked too, and `'router' => $router` / `'routes' => $routes` follow a same-file `$routes = [...]` assignment.
- Method children apply to every expanded form of the parent: `/user[/:id]` with a `delete` child gives `DELETE /user` and `DELETE /user/:id`.
- Any `'route' => '/path'` literal the walk didn't reach (routes built with `array_merge`, in loops, or past the tokenizer's 500k-token cap) keeps the flat match, except literals inside a `child_routes` array, which are only fragments of a path.

Non-UTF-8 sources (cp1252/latin-1, common in ZF1/ZF2 code) are decoded by `attackmap.sdk.read_source` rather than skipped.

## Notes

This analyzer is heuristic and intentionally avoids AST parsing in this first iteration.

Secret hints are env var names (`getenv`, `$_ENV`, `$_SERVER`) containing `SECRET`, `TOKEN`, `KEY`, `PASSWORD` or `PASSWD`, matched case-sensitively; `DB_HOST`-style connection settings are not secrets. `jwt` needs a JWT library (`Firebase\JWT\JWT`, `JWT::decode/encode`, `Lcobucci\JWT`, `tymon/jwt-auth`), and `auth` needs the `Auth::` facade or a chained `auth()->…` helper.
