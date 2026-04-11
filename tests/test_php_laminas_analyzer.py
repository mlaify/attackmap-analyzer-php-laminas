from pathlib import Path

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
    auth_hints = {hint.hint for hint in result.auth_hints}

    assert ("/", "ANY") in route_keys
    assert ("/admin", "ANY") in route_keys
    assert ("/api[/:id]", "ANY") in route_keys

    assert any(hint.startswith("controller:Application\\Controller\\") for hint in auth_hints)
    assert any(hint.startswith("service:Application\\Service\\") for hint in auth_hints)
    assert "laminas_controller_mapping" in auth_hints
    assert "laminas_service_manager" in auth_hints


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
