import shutil
import sys
from pathlib import Path

import pytest

from attackmap.sdk.contracts import AnalyzerMetadata as SharedAnalyzerMetadata
from attackmap.sdk.models import ScanResult as SharedScanResult
from attackmap_analyzer_php_laminas.contracts import AnalyzerMetadata, ScanResult
from attackmap_analyzer_php_laminas import PhpLaminasAnalyzer

FIXTURES = Path(__file__).parent / "fixtures"


def test_contracts_use_shared_sdk_types() -> None:
    assert AnalyzerMetadata is SharedAnalyzerMetadata
    assert ScanResult is SharedScanResult


def test_metadata_contains_required_fields() -> None:
    analyzer = PhpLaminasAnalyzer()
    metadata = analyzer.metadata

    assert metadata.name == "php-laminas"
    assert metadata.display_name == "PHP Laminas Analyzer"
    assert metadata.version == "0.1.0"
    assert metadata.description
    assert metadata.scope
    assert metadata.targets
    assert metadata.languages == ["php"]
    assert metadata.experimental is True


def test_detect_identifies_laminas_project() -> None:
    analyzer = PhpLaminasAnalyzer()

    assert analyzer.detect(FIXTURES / "laminas_app") is True


def test_analyze_extracts_routes_controllers_and_services() -> None:
    analyzer = PhpLaminasAnalyzer()
    result = analyzer.analyze(FIXTURES / "laminas_app")

    route_keys = {(route.path, route.method) for route in result.routes}
    framework_hints = {hint.hint for hint in result.framework_hints}

    assert ("/", "ANY") in route_keys
    assert ("/admin", "ANY") in route_keys
    assert ("/api[/:id]", "ANY") in route_keys

    # Framework metadata is a FrameworkHint, not an AuthHint (AttackMap#258).
    assert any(hint.startswith("controller:Application\\Controller\\") for hint in framework_hints)
    assert any(hint.startswith("service:Application\\Service\\") for hint in framework_hints)
    assert "laminas_controller_mapping" in framework_hints
    assert "laminas_service_manager" in framework_hints
    assert "laminas_dependency" in framework_hints
    assert result.auth_hints == []


def test_auth_signals_stay_auth_hints_with_line_and_evidence(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text('{"require": {"laminas/laminas-mvc": "^3.0"}}')
    (tmp_path / "Login.php").write_text(
        "<?php\n\nsession_start();\n$token = JWT::decode($raw, $key);\nif (!auth()->check()) { exit; }\n"
    )
    result = PhpLaminasAnalyzer().analyze(tmp_path)
    by_hint = {hint.hint: hint for hint in result.auth_hints}
    assert set(by_hint) == {"session", "jwt", "auth"}
    assert (by_hint["session"].line, by_hint["session"].evidence_text) == (3, "session_start();")
    assert by_hint["jwt"].line == 4
    assert by_hint["auth"].line == 5
    dependency = next(h for h in result.framework_hints if h.hint == "laminas_dependency")
    assert (dependency.file, dependency.line) == ("composer.json", 1)


def test_analyze_returns_core_compatible_scan_shape() -> None:
    analyzer = PhpLaminasAnalyzer()
    result = analyzer.analyze(FIXTURES / "laminas_app")

    assert isinstance(result.root, str)
    assert isinstance(result.files_scanned, int)
    assert isinstance(result.languages, list)
    assert hasattr(result, "routes")
    assert hasattr(result, "external_calls")
    assert hasattr(result, "databases")
    assert hasattr(result, "auth_hints")
    assert hasattr(result, "secret_hints")


def test_metadata_priority_and_opt_in() -> None:
    # Core runs analyzers in (priority, name) order and merges first-seen-wins
    # (AttackMap#221): the framework analyzer runs after the generic php-web
    # one (40) and stays opt-in via `-m php-laminas`.
    metadata = PhpLaminasAnalyzer().metadata
    assert metadata.priority == 70
    assert metadata.enabled_by_default is False


# ---------------------------------------------------------------------------
# Repo walking via attackmap.sdk.fs (AttackMap#253)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("parent", ["build/out", "build/vendor"])
def test_repo_checked_out_under_skip_dir_name_is_still_analyzed(tmp_path: Path, parent: str) -> None:
    # Skip dirs used to be matched against absolute path parts, so a repo
    # under any `vendor/` directory yielded no PHP files at all.
    repo = tmp_path / parent / "repo"
    shutil.copytree(FIXTURES / "laminas_app", repo)
    analyzer = PhpLaminasAnalyzer()
    assert analyzer.detect(repo) is True
    result = analyzer.analyze(repo)
    assert result.files_scanned > 0
    assert result.routes
    assert any(h.hint == "laminas_controller_mapping" for h in result.framework_hints)


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_symlinked_source_outside_repo_is_not_analyzed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.php").write_text("<?php\nreturn ['route' => '/outside-secret', 'k' => getenv('OUTSIDE_SECRET_KEY')];\n")
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURES / "laminas_app", repo)
    (repo / "module" / "Application" / "config" / "linked.php").symlink_to(outside / "secret.php")

    result = PhpLaminasAnalyzer().analyze(repo)
    assert "/outside-secret" not in {r.path for r in result.routes}
    assert "OUTSIDE_SECRET_KEY" not in {s.name for s in result.secret_hints}


def test_detect_ignores_module_config_under_vendor(tmp_path: Path) -> None:
    config = tmp_path / "vendor" / "laminas" / "laminas-mvc" / "config"
    config.mkdir(parents=True)
    (config / "module.config.php").write_text("<?php return [];\n")
    assert PhpLaminasAnalyzer().detect(tmp_path) is False


# ---------------------------------------------------------------------------
# False positives on ordinary PHP (port of mlaify/attackmap-analyzer-php-web#2)
# ---------------------------------------------------------------------------

NOISE = FIXTURES / "laminas_noise_app"
ALBUM_CONTROLLER = "module/Album/src/Controller/AlbumController.php"


def test_navigation_route_names_are_not_routes() -> None:
    # `'navigation' => [['route' => 'home'], ['route' => 'album/view']]` names
    # routes; only the router's path specs are routes.
    result = PhpLaminasAnalyzer().analyze(NOISE)
    assert {(r.path, r.method) for r in result.routes} == {("/album", "ANY"), ("[/:id]", "ANY")}


def test_db_and_api_connection_settings_are_not_secrets() -> None:
    result = PhpLaminasAnalyzer().analyze(NOISE)
    names = {s.name for s in result.secret_hints if s.file == ALBUM_CONTROLLER}
    assert names == {"DB_PASSWORD", "API_KEY"}


def test_lowercase_env_names_are_not_secrets(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text('{"require": {"laminas/laminas-mvc": "^3.0"}}')
    (tmp_path / "a.php").write_text("<?php\n$k = getenv('cache_key_prefix');\n$s = getenv('APP_SECRET');\n")
    names = {s.name for s in PhpLaminasAnalyzer().analyze(tmp_path).secret_hints}
    assert names == {"APP_SECRET"}


def test_jwt_substring_and_auth_method_are_not_auth_hints() -> None:
    result = PhpLaminasAnalyzer().analyze(NOISE)
    assert [h for h in result.auth_hints if h.file == ALBUM_CONTROLLER] == []


def test_firebase_jwt_usage_is_a_jwt_hint() -> None:
    result = PhpLaminasAnalyzer().analyze(NOISE)
    hints = {(h.hint, h.file) for h in result.auth_hints}
    assert ("jwt", "module/Album/src/Controller/TokenController.php") in hints
