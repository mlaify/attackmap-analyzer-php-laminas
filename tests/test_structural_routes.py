"""Structural router walking (mlaify/attackmap-analyzer-php-laminas#2):
child_routes joined, Segment optional parts expanded, Method verbs mapped,
Mezzio routes read, and legacy-encoded files kept."""

from __future__ import annotations

import random
import time
from pathlib import Path

import pytest

from attackmap_analyzer_php_laminas import PhpLaminasAnalyzer
from attackmap_analyzer_php_laminas.phparray import (
    NameContext,
    PhpArray,
    PhpExpr,
    PhpString,
    class_name,
    keyed_arrays,
    parse_call_args,
    tokenize,
)
from attackmap_analyzer_php_laminas.routes import expand_optional, maximal_form, mezzio_routes, minimal_form, route_trees, router_routes

FIXTURES = Path(__file__).parent / "fixtures"
NESTED = FIXTURES / "laminas_nested_app"
ADMIN_CONFIG = "module/Admin/config/module.config.php"


def _keys(repo: Path) -> set[tuple[str, str]]:
    return {(r.path, r.method) for r in PhpLaminasAnalyzer().analyze(repo).routes}


def _routes(source: str) -> set[tuple[str, str]]:
    return {(r.path, r.method) for r in router_routes(route_trees(tokenize(source)))}


# ---------------------------------------------------------------------------
# child_routes
# ---------------------------------------------------------------------------


def test_child_routes_are_joined_onto_parent_path() -> None:
    keys = _keys(NESTED)
    assert ("/admin/users/:id", "ANY") in keys
    # No fragment of a child route leaks out as a top-level path.
    assert not any(path in {"/:id", "/users", "/reports"} for path, _ in keys)


def test_may_terminate_controls_whether_parent_is_a_route() -> None:
    keys = _keys(NESTED)
    # `admin` sets may_terminate; `users` doesn't, so only its children are routes.
    assert ("/admin", "ANY") in keys
    assert ("/admin/users", "ANY") not in keys
    # Legacy `/legacy` sets 'may_terminate' => false explicitly.
    assert not any(path == "/legacy" for path, _ in keys)


def test_route_without_children_terminates_by_default() -> None:
    source = """<?php return ['router' => ['routes' => [
        'about' => ['type' => 'Literal', 'options' => ['route' => '/about']],
    ]]];"""
    assert _routes(source) == {("/about", "ANY")}


def test_deeply_nested_children_join_every_level() -> None:
    source = """<?php return ['router' => ['routes' => [
        'a' => ['type' => 'Literal', 'options' => ['route' => '/a'], 'child_routes' => [
            'b' => ['type' => 'Segment', 'options' => ['route' => '/b/:x'], 'child_routes' => [
                'c' => ['type' => 'Literal', 'options' => ['route' => '/c']],
            ]],
        ]],
    ]]];"""
    assert _routes(source) == {("/a/b/:x/c", "ANY")}


def test_route_line_is_the_route_literal() -> None:
    result = PhpLaminasAnalyzer().analyze(NESTED)
    route = next(r for r in result.routes if (r.path, r.method) == ("/admin/users/:id", "ANY"))
    lines = (NESTED / ADMIN_CONFIG).read_text().split("\n")
    assert route.file == ADMIN_CONFIG
    assert "'route' => '/:id'" in lines[route.line - 1]


# ---------------------------------------------------------------------------
# Method routes
# ---------------------------------------------------------------------------


def test_method_children_set_the_http_method_on_the_parent_path() -> None:
    keys = _keys(NESTED)
    assert ("/admin/users", "POST") in keys
    # `'verb' => 'get,head'` is a comma list.
    assert ("/admin/users", "GET") in keys
    assert ("/admin/users", "HEAD") in keys
    # A Method child of a terminable segment adds a verb next to its ANY.
    assert ("/admin/users/:id", "DELETE") in keys


def test_method_route_with_unknown_verb_is_skipped() -> None:
    source = """<?php return ['router' => ['routes' => [
        'x' => ['type' => 'Literal', 'options' => ['route' => '/x'], 'child_routes' => [
            'm' => ['type' => Method::class, 'options' => ['verb' => 'frobnicate']],
            'n' => ['type' => Method::class, 'options' => ['verb' => $verb]],
        ]],
    ]]];"""
    assert _routes(source) == set()


# ---------------------------------------------------------------------------
# Segment optional parts and other route types
# ---------------------------------------------------------------------------


def test_segment_optional_parts_expand_progressively() -> None:
    keys = _keys(NESTED)
    # '/reports[/:year[/:month]][/]': minimal, then one group opened at a time.
    assert {p for p, m in keys if p.startswith("/admin/reports")} == {
        "/admin/reports",
        "/admin/reports/:year",
        "/admin/reports/:year/:month",
    }


@pytest.mark.parametrize(
    "template,forms",
    [
        ("/a", ["/a"]),
        ("/a[/:b]", ["/a", "/a/:b"]),
        ("/a[/:b[/:c]]", ["/a", "/a/:b", "/a/:b/:c"]),
        ("[/:x]", ["", "/:x"]),
        # Capped at 4 forms: the last one is the maximal form.
        ("/a[/b][/c][/d][/e][/f]", ["/a", "/a/b", "/a/b/c", "/a/b/c/d/e/f"]),
        # Unbalanced brackets never raise.
        ("/a]/b", ["/a]/b"]),
        ("/a[/b", ["/a", "/a/b"]),
    ],
)
def test_expand_optional(template: str, forms: list[str]) -> None:
    assert expand_optional(template) == forms


def test_segment_delimiters_and_translated_literals_are_normalized() -> None:
    assert ("/legacy/item/:slug", "ANY") in _keys(NESTED)
    source = """<?php return ['router' => ['routes' => [
        't' => ['type' => 'Segment', 'options' => ['route' => '/{album}/:id']],
    ]]];"""
    assert _routes(source) == {("/album/:id", "ANY")}


def test_regex_route_uses_spec_and_hostname_adds_no_path() -> None:
    keys = _keys(NESTED)
    assert ("/export/:id.csv", "ANY") in keys
    assert ("/tenant-home", "ANY") in keys
    # The hostname spec `:tenant.example.com` is never a path.
    assert not any(path.startswith("/:tenant") for path, _ in keys)


def test_console_routes_and_navigation_names_are_not_http_routes() -> None:
    keys = _keys(NESTED)
    assert not any("reset" in path or path.startswith("/user") for path, _ in keys)
    assert not any(path == "/admin/users" and method == "ANY" for path, method in keys)


def test_array_syntax_and_string_types_are_supported() -> None:
    assert ("/legacy/item/:slug", "ANY") in _keys(NESTED)


def test_returned_route_map_file_is_walked() -> None:
    # `'router' => ['routes' => require __DIR__ . '/routes.php']`: the
    # required file just returns the route map.
    source = """<?php
return [
    'home' => ['type' => Literal::class, 'options' => ['route' => '/']],
    'blog' => ['type' => Literal::class, 'options' => ['route' => '/blog'], 'may_terminate' => true,
        'child_routes' => ['post' => ['type' => Segment::class, 'options' => ['route' => '/:slug']]]],
];"""
    assert _routes(source) == {("/", "ANY"), ("/blog", "ANY"), ("/blog/:slug", "ANY")}


def test_plain_return_array_is_not_a_route_map() -> None:
    source = "<?php return ['modules' => ['Application'], 'route' => '/not-a-route-map'];"
    assert route_trees(tokenize(source)) == []


def test_child_fragments_are_not_emitted_by_the_flat_fallback(tmp_path: Path) -> None:
    # A route map the walk can't reach (a variable no router uses): the flat
    # fallback keeps its top-level literal but not the child fragment.
    (tmp_path / "composer.json").write_text('{"require": {"laminas/laminas-mvc": "^3.0"}}')
    (tmp_path / "routes.php").write_text(
        "<?php\n$routes = ['x' => ['options' => ['route' => '/x'], 'child_routes' => ["
        "'y' => ['options' => ['route' => '/:id']]]]];\n"
    )
    assert _keys(tmp_path) == {("/x", "ANY")}


def test_flat_fallback_still_reads_a_file_without_a_router_tree(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text('{"require": {"laminas/laminas-mvc": "^3.0"}}')
    (tmp_path / "routes.php").write_text("<?php\n$spec = ['options' => ['route' => '/flat']];\n")
    assert _keys(tmp_path) == {("/flat", "ANY")}


# ---------------------------------------------------------------------------
# Mezzio
# ---------------------------------------------------------------------------


def test_mezzio_routes_are_extracted_with_methods() -> None:
    keys = _keys(FIXTURES / "mezzio_app")
    assert keys == {
        ("/", "GET"),
        ("/api/ping", "GET"),
        ("/api/albums", "POST"),
        ("/api/albums/{id}", "DELETE"),
        ("/api/tracks", "GET"),
        ("/api/tracks", "PATCH"),
        ("/api/tracks/{page}", "GET"),
        ("/api/tracks/{page}", "PATCH"),
        ("/webhook", "ANY"),
    }


def test_mezzio_needs_a_mezzio_file_and_app_receiver(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text('{"require": {"laminas/laminas-mvc": "^3.0"}}')
    # No Mezzio/Expressive reference in the file: a Slim-style `$app->get`
    # is php-web's business, not ours.
    (tmp_path / "slim.php").write_text("<?php\n$app->get('/slim', function () {});\n")
    # Mezzio file but another receiver.
    (tmp_path / "other.php").write_text("<?php\nuse Mezzio\\Application;\n$router->get('/nope', H::class);\n")
    assert _keys(tmp_path) == set()


def test_mezzio_route_with_null_methods_is_any() -> None:
    source = "<?php use Mezzio\\Application;\n$app->route('/r', H::class, null, 'r');\n"
    assert {(r.path, r.method) for r in mezzio_routes(tokenize(source))} == {("/r", "ANY")}


def test_expressive_detected_by_mezzio_composer_package(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text('{"require": {"mezzio/mezzio": "^3.0"}}')
    assert PhpLaminasAnalyzer().detect(tmp_path) is True


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------


def test_latin1_module_config_is_still_analyzed(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text('{"require": {"zendframework/zend-mvc": "^2.7"}}')
    config = tmp_path / "module" / "Catalogue" / "config"
    config.mkdir(parents=True)
    source = (
        "<?php\n// Catalogue: résumés, à la carte © 2014\n"
        "return array('router' => array('routes' => array(\n"
        "    'cat' => array('type' => 'Literal', 'options' => array('route' => '/catalogue', "
        "'defaults' => array('label' => 'Café')), 'may_terminate' => true,\n"
        "        'child_routes' => array('item' => array('type' => 'Segment', "
        "'options' => array('route' => '/:id')))),\n)));\n"
    )
    data = source.encode("latin-1")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    else:  # pragma: no cover - the fixture must not be valid UTF-8
        raise AssertionError("fixture should not be valid UTF-8")
    (config / "module.config.php").write_bytes(data)
    keys = _keys(tmp_path)
    assert keys == {("/catalogue", "ANY"), ("/catalogue/:id", "ANY")}


# ---------------------------------------------------------------------------
# Tokenizer / parser
# ---------------------------------------------------------------------------


def test_brackets_in_strings_and_comments_do_not_unbalance() -> None:
    source = """<?php return ['router' => ['routes' => [
        // a ] in a comment
        /* and [[[ here */
        # and ] here
        'a' => ['type' => 'Literal', 'options' => ['route' => '/a', 'x' => ']]', 'y' => "[[\\"]"]],
        'b' => ['type' => 'Literal', 'options' => ['route' => '/b', 'h' => <<<EOT
            ]]] not code [[[
            EOT
        ]],
        'c' => ['type' => 'Literal', 'options' => ['route' => '/c', 'f' => function () { return [1, 2]; }]],
    ]]];"""
    assert _routes(source) == {("/a", "ANY"), ("/b", "ANY"), ("/c", "ANY")}


def test_parser_reads_strings_exprs_and_nested_arrays() -> None:
    tokens = tokenize("<?php $c = ['k' => 'v', 'n' => [1, 'two'], 'e' => Foo\\Bar::class, 'd' => __DIR__ . '/x'];")
    (array,) = [a for a in keyed_arrays(tokens, "n")]
    assert [type(v) for _, v in array.items] == [PhpExpr, PhpString]
    tokens = tokenize("<?php return ['cfg' => ['k' => 'v', 'e' => Foo\\Bar::class, 'd' => __DIR__ . '/x']];")
    (cfg,) = keyed_arrays(tokens, "cfg")
    assert isinstance(cfg, PhpArray)
    assert isinstance(cfg.get("k"), PhpString) and cfg.get("k").value == "v"
    assert isinstance(cfg.get("e"), PhpExpr) and cfg.get("e").text == "Foo\\Bar::class"
    assert isinstance(cfg.get("d"), PhpExpr)


def test_call_args() -> None:
    tokens = tokenize("x('/a', [1, 2], null)")
    lparen = next(i for i, t in enumerate(tokens) if t.text == "(")
    args, end = parse_call_args(tokens, lparen)
    assert end == len(tokens)
    assert isinstance(args[0], PhpString) and args[0].value == "/a"
    assert isinstance(args[1], PhpArray) and len(args[1].items) == 2
    assert isinstance(args[2], PhpExpr) and args[2].text == "null"


def test_class_names_resolve_through_namespace_and_use() -> None:
    names = NameContext.of("<?php\nnamespace App;\nuse Lib\\Http\\Segment;\nuse Lib\\Other as O;\n")
    assert class_name(PhpExpr("Controller\\Index::class", 0), names) == "App\\Controller\\Index"
    assert class_name(PhpExpr("Segment::class", 0), names) == "Lib\\Http\\Segment"
    assert class_name(PhpExpr("O\\X::class", 0), names) == "Lib\\Other\\X"
    assert class_name(PhpExpr("\\Abs\\X::class", 0), names) == "Abs\\X"
    assert class_name(PhpString("\\Omeka\\Controller\\Api", 0), names) == "Omeka\\Controller\\Api"
    assert class_name(PhpExpr("$x", 0), names) is None


_FUZZ_ALPHABET = list("[](){},'\"=>/\\#*$:;. \n\tarxy") + ["array(", "=>", "'router'", "'routes'", "<<<EOT\n", "\nEOT", "//", "/*", "*/", "child_routes", "'child_routes' => ["]


def _fuzz_inputs() -> list[str]:
    rng = random.Random(20261012)
    seeds = [path.read_text(encoding="utf-8", errors="replace") for path in sorted(FIXTURES.rglob("*.php"))]
    inputs: list[str] = []
    for seed in seeds:
        for _ in range(40):
            cut = rng.randrange(len(seed) + 1)
            inputs.append(seed[:cut])
            # Splice garbage into the middle of real config.
            junk = "".join(rng.choice(_FUZZ_ALPHABET) for _ in range(rng.randrange(1, 30)))
            inputs.append(seed[:cut] + junk + seed[cut:])
    for _ in range(300):
        inputs.append("".join(rng.choice(_FUZZ_ALPHABET) for _ in range(rng.randrange(0, 400))))
    return inputs


def test_tokenizer_and_walkers_never_raise_on_garbage() -> None:
    for text in _fuzz_inputs():
        tokens = tokenize(text)
        router_routes(route_trees(tokens), known={}, index={})
        mezzio_routes(tokens)
        for form in expand_optional(text[:200]):
            assert isinstance(form, str)


@pytest.mark.parametrize(
    "payload",
    [
        "[" * 50_000,
        "array(" * 20_000,
        "'router' => [" * 20_000,
        "'router' => ['routes' => [" + "'a' => ['type' => 'Segment', 'options' => ['route' => '/a'], 'child_routes' => [" * 5_000,
        "'route' => '" + "[" * 50_000 + "'",
        "<<<" + "A" * 50_000,
        "'" + "\\" * 50_000,
        "/*" + "[" * 50_000,
        "$app->route(" * 20_000,
        "$a = [" * 5_000 + "'router' => $a, " * 5_000 + "'router' => ['routes' => $a], " * 5_000,
    ],
    ids=["brackets", "array_calls", "router_keys", "child_routes", "optional_parts", "heredoc", "backslashes", "comment", "mezzio", "variables"],
)
def test_hostile_input_is_bounded(payload: str) -> None:
    start = time.perf_counter()
    tokens = tokenize("<?php use Mezzio\\Application; return [" + payload)
    router_routes(route_trees(tokens), known={}, index={})
    mezzio_routes(tokens)
    expand_optional(payload[:10_000])
    assert time.perf_counter() - start < 5.0


# ---------------------------------------------------------------------------
# Config merged across modules
# ---------------------------------------------------------------------------


def test_child_routes_added_by_another_module_join_the_defining_route() -> None:
    keys = _keys(NESTED)
    assert ("/admin/audit", "ANY") in keys
    assert ("/admin/audit/:page", "ANY") in keys
    result = PhpLaminasAnalyzer().analyze(NESTED)
    audit = next(r for r in result.routes if r.path == "/admin/audit")
    assert audit.file == "module/Audit/config/module.config.php"


def test_stub_extending_an_unknown_route_is_skipped() -> None:
    keys = _keys(NESTED)
    assert not any("orphan" in path for path, _ in keys)


def test_stub_of_a_stub_resolves_across_files(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text('{"require": {"laminas/laminas-mvc": "^3.0"}}')
    (tmp_path / "a.php").write_text(
        "<?php return ['router' => ['routes' => ['api' => ['type' => 'Literal', "
        "'options' => ['route' => '/api'], 'child_routes' => ['v1' => ['type' => 'Literal', "
        "'options' => ['route' => '/v1']]]]]]];"
    )
    # `0-ext.php` is walked first; the route index is built from every file
    # before any route is emitted.
    (tmp_path / "0-ext.php").write_text(
        "<?php return ['router' => ['routes' => ['api' => ['child_routes' => ['v1' => ['child_routes' => ["
        "'users' => ['type' => 'Literal', 'options' => ['route' => '/users']]]]]]]]];"
    )
    keys = _keys(tmp_path)
    assert ("/api/v1/users", "ANY") in keys
    assert ("/users", "ANY") not in keys


def test_children_join_the_parent_maximal_form() -> None:
    # Laminas' Part::match: the parent Segment consumes greedily and never
    # backs off, so `/h/job/5` sets action=job and the child can't match;
    # the child is reached at `/h/:action/job/:id`.
    source = """<?php return ['router' => ['routes' => [
        'h' => ['type' => 'Segment', 'options' => ['route' => '/h[/:action]'], 'child_routes' => [
            'job' => ['type' => 'Segment', 'options' => ['route' => '/job/:id']],
        ]],
    ]]];"""
    assert _routes(source) == {("/h/:action/job/:id", "ANY")}
    assert minimal_form("/a[/:b[/:c]]/d[/:e]") == "/a/d"
    assert maximal_form("/a[/:b[/:c]]/d[/:e]") == "/a/:b/:c/d/:e"


def test_child_that_can_match_nothing_keeps_every_parent_form() -> None:
    source = """<?php return ['router' => ['routes' => [
        'h' => ['type' => 'Segment', 'options' => ['route' => '/h[/:action]'], 'child_routes' => [
            'id' => ['type' => 'Segment', 'options' => ['route' => '[/:id]']],
        ]],
    ]]];"""
    assert _routes(source) == {("/h", "ANY"), ("/h/:action", "ANY"), ("/h/:action/:id", "ANY")}



# ---------------------------------------------------------------------------
# Review fixes: Method children on optional parents, routes in variables,
# the tokenizer cap and route de-duplication
# ---------------------------------------------------------------------------


def test_method_children_apply_to_every_form_of_an_optional_parent() -> None:
    source = """<?php return ['router' => ['routes' => [
        'user' => ['type' => 'Segment', 'options' => ['route' => '/user[/:id]'], 'child_routes' => [
            'get' => ['type' => 'Method', 'options' => ['verb' => 'get']],
            'delete' => ['type' => 'Method', 'options' => ['verb' => 'delete']],
        ]],
    ]]];"""
    assert _routes(source) == {
        ("/user", "GET"),
        ("/user/:id", "GET"),
        ("/user", "DELETE"),
        ("/user/:id", "DELETE"),
    }


def test_routes_held_in_a_same_file_variable_are_walked(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text('{"require": {"laminas/laminas-mvc": "^3.0"}}')
    (tmp_path / "module.config.php").write_text(
        "<?php\n$routes = ['album' => ['type' => 'Literal', 'options' => ['route' => '/album'], "
        "'may_terminate' => true, 'child_routes' => ['view' => ['type' => 'Segment', "
        "'options' => ['route' => '[/:id]']]]]];\n"
        "return ['router' => ['routes' => $routes]];\n"
    )
    assert _keys(tmp_path) == {("/album", "ANY"), ("/album/:id", "ANY")}


def test_router_held_in_a_variable_is_walked() -> None:
    source = """<?php
$router = ['routes' => ['a' => ['type' => 'Literal', 'options' => ['route' => '/a']]]];
$router = ['routes' => ['b' => ['type' => 'Literal', 'options' => ['route' => '/b']]]];
return ['router' => $router];"""
    # The last assignment before the use.
    assert _routes(source) == {("/b", "ANY")}


def test_unfollowable_routes_fall_back_to_flat_literals(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text('{"require": {"laminas/laminas-mvc": "^3.0"}}')
    (tmp_path / "module.config.php").write_text(
        "<?php\nreturn ['router' => ['routes' => array_merge(\n"
        "  ['a' => ['type' => 'Literal', 'options' => ['route' => '/a'], 'child_routes' => [\n"
        "    'c' => ['type' => 'Segment', 'options' => ['route' => '/:id']]]]],\n"
        "  $more)]];\n"
    )
    # `/a` is kept (main reported it too); the child fragment `/:id` is not.
    assert _keys(tmp_path) == {("/a", "ANY")}


def test_routes_past_the_token_cap_fall_back_to_flat_literals(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from attackmap_analyzer_php_laminas import analyzer as analyzer_module

    real = analyzer_module.tokenize
    monkeypatch.setattr(analyzer_module, "tokenize", lambda content: real(content, max_tokens=40))
    (tmp_path / "composer.json").write_text('{"require": {"laminas/laminas-mvc": "^3.0"}}')
    entries = "".join(
        f"'r{i}' => ['type' => 'Literal', 'options' => ['route' => '/r{i}']],\n" for i in range(10)
    )
    (tmp_path / "module.config.php").write_text(f"<?php\nreturn ['router' => ['routes' => [\n{entries}]]];\n")
    tokens = real((tmp_path / "module.config.php").read_text(), max_tokens=40)
    assert tokens.truncated
    # The walk sees only the first route; the rest come from the flat match.
    assert _keys(tmp_path) == {(f"/r{i}", "ANY") for i in range(10)}


def test_many_routes_are_deduplicated_in_linear_time(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text('{"require": {"laminas/laminas-mvc": "^3.0"}}')
    for f in range(30):
        entries = "".join(
            f"'r{i}' => ['type' => 'Literal', 'options' => ['route' => '/f{f}/r{i}']],\n" for i in range(2000)
        )
        (tmp_path / f"m{f}.php").write_text(f"<?php\nreturn ['router' => ['routes' => [\n{entries}]]];\n")
    start = time.perf_counter()
    result = PhpLaminasAnalyzer().analyze(tmp_path)
    assert len(result.routes) == 60_000
    # Linear: ~3 s locally; the old list scan took minutes.
    assert time.perf_counter() - start < 30.0
