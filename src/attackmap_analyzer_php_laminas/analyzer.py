from __future__ import annotations

import json
import re
from pathlib import Path

from attackmap.sdk import iter_repo_files, read_source, rel

from .contracts import AnalyzerMetadata, AuthHint, DatabaseHint, ExternalCall, Route, ScanResult, SecretHint

LAMINAS_ROUTE_PATTERN = re.compile(r"['\"]route['\"]\s*=>\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
# `Foo\\BarController::class` — whole token matched possessively, keyword
# checked in Python (see the service pattern below; mlaify/AttackMap#236).
LAMINAS_CONTROLLER_PATTERN = re.compile(r"(?<![A-Za-z0-9_\\])([A-Za-z_\\][A-Za-z0-9_\\]*+)::class")
# Match the whole `Foo\\BarService::class` token in one possessive pass, then
# check for a service keyword in Python. The old single regex
# (`[..]*(?:Service|…)[..]*::class`) backtracked quadratically on a long
# identifier-like line, enough to stall a scan (mlaify/AttackMap#236).
LAMINAS_SERVICE_PATTERN = re.compile(r"(?<![A-Za-z0-9_\\])([A-Za-z_\\][A-Za-z0-9_\\]*+)::class")
_SERVICE_WORD = re.compile(r"Service|Manager|Repository|TableGateway|Adapter", re.IGNORECASE)

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
        priority=70,
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

        if self._has_laminas_composer_dependencies(root):
            return True

        if (root / "module").is_dir() and (root / "config" / "application.config.php").exists():
            return True

        if next(iter_repo_files(root, names={"module.config.php"}), None) is not None:
            return True

        return False

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))

        if not root.exists() or not root.is_dir():
            return result

        self._extract_composer_signals(root, result)

        # Pruned by repo-relative dir name (vendor, node_modules, .git, ...);
        # symlinks out of the repo are not followed (AttackMap#253).
        for file_path in iter_repo_files(root, suffixes={".php"}):
            result.files_scanned += 1
            if "php" not in result.languages:
                result.languages.append("php")

            content = read_source(file_path)
            if content is None:
                continue

            relative = rel(file_path, root)
            self._extract_routes(content, relative, result)
            self._extract_laminas_controllers(content, relative, result)
            self._extract_laminas_services(content, relative, result)
            self._extract_external_calls(content, relative, result)
            self._extract_datastores(content, relative, result)
            self._extract_auth_hints(content, relative, result)
            self._extract_secret_hints(content, relative, result)

        result.languages.sort()
        return result

    def _has_laminas_composer_dependencies(self, root: Path) -> bool:
        data = self._load_composer(root)
        if data is None:
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

    def _extract_composer_signals(self, root: Path, result: ScanResult) -> None:
        data = self._load_composer(root)
        if data is None:
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
            if "controller" not in match.group(1).lower():
                continue
            found = True
            self._append_unique_auth(result, f"controller:{match.group(1)}", relative)
        if found:
            self._append_unique_auth(result, "laminas_controller_mapping", relative)

    def _extract_laminas_services(self, content: str, relative: str, result: ScanResult) -> None:
        found = False
        for match in LAMINAS_SERVICE_PATTERN.finditer(content):
            if not _SERVICE_WORD.search(match.group(1)):
                continue
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
    def _load_composer(root: Path) -> dict | None:
        text = read_source(root / "composer.json", root=root)
        if text is None:
            return None
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else None

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
