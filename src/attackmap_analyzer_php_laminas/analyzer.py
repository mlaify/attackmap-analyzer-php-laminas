from __future__ import annotations

import json
import re
from pathlib import Path

from .contracts import AnalyzerMetadata, AuthHint, DatabaseHint, ExternalCall, Route, ScanResult, SecretHint

LAMINAS_ROUTE_PATTERN = re.compile(r"['\"]route['\"]\s*=>\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
LAMINAS_CONTROLLER_PATTERN = re.compile(
    r"([A-Za-z_\\][A-Za-z0-9_\\]*Controller[A-Za-z0-9_\\]*)::class",
    re.IGNORECASE,
)
LAMINAS_SERVICE_PATTERN = re.compile(
    r"([A-Za-z_\\][A-Za-z0-9_\\]*(?:Service|Manager|Repository|TableGateway|Adapter)[A-Za-z0-9_\\]*)::class",
    re.IGNORECASE,
)

OUTBOUND_PATTERNS = [
    re.compile(r"curl_init\s*\(\s*['\"](https?://[^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"file_get_contents\s*\(\s*['\"](https?://[^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"->request\s*\(\s*['\"](?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)['\"]\s*,\s*['\"](https?://[^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"->(?:get|post|put|patch|delete)\s*\(\s*['\"](https?://[^'\"]+)['\"]", re.IGNORECASE),
]

DATABASE_PATTERNS = [
    (re.compile(r"\bnew\s+PDO\s*\(", re.IGNORECASE), "sql"),
    (re.compile(r"Doctrine\\DBAL|Doctrine\\ORM|EntityManager", re.IGNORECASE), "sql"),
    (re.compile(r"\bmysqli_connect\s*\(", re.IGNORECASE), "mysql"),
    (re.compile(r"\bnew\s+mysqli\s*\(", re.IGNORECASE), "mysql"),
    (re.compile(r"\bpg_connect\s*\(", re.IGNORECASE), "postgresql"),
    (re.compile(r"\bRedis\s*::|\bnew\s+Redis\s*\(", re.IGNORECASE), "redis"),
]

AUTH_PATTERNS = [
    (re.compile(r"\bsession_start\s*\(", re.IGNORECASE), "session"),
    (re.compile(r"\$_SESSION\b", re.IGNORECASE), "session"),
    (re.compile(r"JWT|firebase\\jwt", re.IGNORECASE), "jwt"),
    (re.compile(r"\bAuth::|\bauth\s*\(", re.IGNORECASE), "auth"),
]

SECRET_PATTERNS = [
    re.compile(r"getenv\s*\(\s*['\"]([A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD|API|DB)[A-Z0-9_]*)['\"]", re.IGNORECASE),
    re.compile(r"\$_ENV\s*\[\s*['\"]([A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD|API|DB)[A-Z0-9_]*)['\"]\s*\]", re.IGNORECASE),
    re.compile(r"\$_SERVER\s*\[\s*['\"]([A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD|API|DB)[A-Z0-9_]*)['\"]\s*\]", re.IGNORECASE),
]


class PhpLaminasAnalyzer:
    metadata = AnalyzerMetadata(
        name="php-laminas",
        display_name="PHP Laminas Analyzer",
        version="0.1.0",
        description="Framework-aware Laminas analyzer for route, controller, and service mapping hints.",
        scope="Laminas and Zend Framework MVC projects using module and application config arrays.",
        targets=["php-laminas", "laminas", "zendframework"],
        languages=["php"],
        priority=30,
        experimental=True,
        enabled_by_default=False,
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, repo_path: str | Path) -> bool:
        root = Path(repo_path).resolve()
        if not root.exists() or not root.is_dir():
            return False

        if self._has_laminas_composer_dependencies(root / "composer.json"):
            return True

        if (root / "module").is_dir() and (root / "config" / "application.config.php").exists():
            return True

        if any(root.rglob("module.config.php")):
            return True

        return False

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))

        if not root.exists() or not root.is_dir():
            return result

        composer_path = root / "composer.json"
        if composer_path.exists():
            self._extract_composer_signals(composer_path, result)

        for file_path in root.rglob("*.php"):
            if not file_path.is_file():
                continue
            if any(part in {"vendor", ".git", "node_modules"} for part in file_path.parts):
                continue

            result.files_scanned += 1
            if "php" not in result.languages:
                result.languages.append("php")

            content = self._read_text(file_path)
            if content is None:
                continue

            relative = str(file_path.relative_to(root))
            self._extract_routes(content, relative, result)
            self._extract_laminas_controllers(content, relative, result)
            self._extract_laminas_services(content, relative, result)
            self._extract_external_calls(content, relative, result)
            self._extract_datastores(content, relative, result)
            self._extract_auth_hints(content, relative, result)
            self._extract_secret_hints(content, relative, result)

        result.languages.sort()
        return result

    def _has_laminas_composer_dependencies(self, composer_path: Path) -> bool:
        if not composer_path.exists():
            return False
        try:
            data = json.loads(composer_path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False

        requirements = {
            **(data.get("require", {}) if isinstance(data.get("require", {}), dict) else {}),
            **(data.get("require-dev", {}) if isinstance(data.get("require-dev", {}), dict) else {}),
        }
        for package in requirements:
            lowered = package.lower()
            if lowered.startswith("laminas/") or lowered.startswith("zendframework/"):
                return True
        return False

    def _extract_composer_signals(self, composer_path: Path, result: ScanResult) -> None:
        try:
            data = json.loads(composer_path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return

        requirements = {
            **(data.get("require", {}) if isinstance(data.get("require", {}), dict) else {}),
            **(data.get("require-dev", {}) if isinstance(data.get("require-dev", {}), dict) else {}),
        }

        for package in requirements:
            lowered = package.lower()
            if lowered.startswith("laminas/") or lowered.startswith("zendframework/"):
                self._append_unique_auth(result, "laminas_dependency", "composer.json")
            if "doctrine" in lowered:
                self._append_unique_database(result, "sql", "composer.json")

    def _extract_routes(self, content: str, relative: str, result: ScanResult) -> None:
        for match in LAMINAS_ROUTE_PATTERN.finditer(content):
            self._append_unique_route(result, match.group(1), "ANY", relative)

    def _extract_laminas_controllers(self, content: str, relative: str, result: ScanResult) -> None:
        found = False
        for match in LAMINAS_CONTROLLER_PATTERN.finditer(content):
            found = True
            self._append_unique_auth(result, f"controller:{match.group(1)}", relative)
        if found:
            self._append_unique_auth(result, "laminas_controller_mapping", relative)

    def _extract_laminas_services(self, content: str, relative: str, result: ScanResult) -> None:
        found = False
        for match in LAMINAS_SERVICE_PATTERN.finditer(content):
            found = True
            self._append_unique_auth(result, f"service:{match.group(1)}", relative)
        if found or "'service_manager'" in content or '"service_manager"' in content:
            self._append_unique_auth(result, "laminas_service_manager", relative)

    def _extract_external_calls(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in OUTBOUND_PATTERNS:
            for match in pattern.finditer(content):
                self._append_unique_external(result, match.group(1), relative)

    def _extract_datastores(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, kind in DATABASE_PATTERNS:
            if pattern.search(content):
                self._append_unique_database(result, kind, relative)

    def _extract_auth_hints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint in AUTH_PATTERNS:
            if pattern.search(content):
                self._append_unique_auth(result, hint, relative)

    def _extract_secret_hints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                self._append_unique_secret(result, match.group(1), relative)

    @staticmethod
    def _read_text(path: Path) -> str | None:
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return None

    @staticmethod
    def _append_unique_route(result: ScanResult, path: str, method: str, file: str) -> None:
        key = (path, method, file)
        if any((item.path, item.method, item.file) == key for item in result.routes):
            return
        result.routes.append(Route(path=path, method=method, file=file))

    @staticmethod
    def _append_unique_external(result: ScanResult, target: str, file: str) -> None:
        key = (target, file)
        if any((item.target, item.file) == key for item in result.external_calls):
            return
        result.external_calls.append(ExternalCall(target=target, file=file))

    @staticmethod
    def _append_unique_database(result: ScanResult, kind: str, file: str) -> None:
        key = (kind, file)
        if any((item.kind, item.file) == key for item in result.databases):
            return
        result.databases.append(DatabaseHint(kind=kind, file=file))

    @staticmethod
    def _append_unique_auth(result: ScanResult, hint: str, file: str) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.auth_hints):
            return
        result.auth_hints.append(AuthHint(hint=hint, file=file))

    @staticmethod
    def _append_unique_secret(result: ScanResult, name: str, file: str) -> None:
        key = (name, file)
        if any((item.name, item.file) == key for item in result.secret_hints):
            return
        result.secret_hints.append(SecretHint(name=name, file=file))
