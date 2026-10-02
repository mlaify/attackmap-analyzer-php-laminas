from __future__ import annotations

import json
import re
from pathlib import Path

from attackmap.sdk import iter_repo_files, line_of, line_snippet, read_source, rel

from .contracts import (
    AnalyzerMetadata,
    AuthHint,
    DatabaseHint,
    ExternalCall,
    FrameworkHint,
    Route,
    ScanResult,
    SecretHint,
)

# Laminas router `'options' => ['route' => '/album[/:id]']`. Only URL path
# specs: rooted (`/...`) or an optional child segment (`[/:id]`). The same
# `'route' =>` key in `navigation` pages and redirects holds a route *name*
# (`'route' => 'home'`, `'route' => 'admin/site'`), which is not a path
# (port of mlaify/attackmap-analyzer-php-web#2's config-path fix).
LAMINAS_ROUTE_PATTERN = re.compile(r"['\"]route['\"]\s*=>\s*['\"]([/\[][^'\"]*)['\"]", re.IGNORECASE)
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
    # A JWT library, not any "jwt" substring (`$jwtSecret`, comments)
    # (port of mlaify/attackmap-analyzer-php-web#2).
    (
        re.compile(
            r"Firebase\\JWT\\JWT|\bJWT::(?:decode|encode)\b|Lcobucci\\JWT|lcobucci/jwt"
            r"|Tymon\\JWTAuth|tymon/jwt-auth|\bJWTAuth::"
        ),
        "jwt",
    ),
    # Laravel-style `Auth::` facade or the `auth()` / `auth('guard')` helper
    # chained into a guard call, not any function or method named `auth(`.
    (re.compile(r"\bAuth::|(?<![\w$>:\\])auth\s*\(\s*(?:['\"][\w-]*['\"]\s*)?\)\s*->"), "auth"),
]

# Secret-shaped env var names only. `API`/`DB` on their own matched
# `DB_HOST`/`API_URL`; `DB_PASSWORD`/`API_KEY`/`API_TOKEN` still match via
# PASSWORD/KEY/TOKEN. Case-sensitive: env var names are upper-case
# (port of mlaify/attackmap-analyzer-php-web#2).
_SECRET_NAME = r"([A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|PASSWD)[A-Z0-9_]*)"
SECRET_PATTERNS = [
    re.compile(r"getenv\s*\(\s*['\"]" + _SECRET_NAME + r"['\"]"),
    re.compile(r"\$_ENV\s*\[\s*['\"]" + _SECRET_NAME + r"['\"]\s*\]"),
    re.compile(r"\$_SERVER\s*\[\s*['\"]" + _SECRET_NAME + r"['\"]\s*\]"),
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
        text = read_source(root / "composer.json", root=root)
        data = self._load_composer(root)
        if data is None or text is None:
            return

        requirements = {
            **(data.get("require", {}) if isinstance(data.get("require", {}), dict) else {}),
            **(data.get("require-dev", {}) if isinstance(data.get("require-dev", {}), dict) else {}),
        }

        for package in requirements:
            lowered = package.lower()
            offset = self._composer_offset(text, package)
            if lowered.startswith("laminas/") or lowered.startswith("zendframework/"):
                self._append_unique_hint(
                    result.framework_hints, FrameworkHint, "laminas_dependency", "composer.json", text, offset, 0.9
                )
            if "doctrine" in lowered:
                self._append_unique_database(result, "sql", "composer.json", text, offset)

    def _extract_routes(self, content: str, relative: str, result: ScanResult) -> None:
        for match in LAMINAS_ROUTE_PATTERN.finditer(content):
            self._append_unique_route(result, match.group(1), "ANY", relative, line_of(content, match.start()))

    def _extract_laminas_controllers(self, content: str, relative: str, result: ScanResult) -> None:
        first: int | None = None
        for match in LAMINAS_CONTROLLER_PATTERN.finditer(content):
            if "controller" not in match.group(1).lower():
                continue
            if first is None:
                first = match.start()
            self._append_unique_hint(
                result.framework_hints, FrameworkHint, f"controller:{match.group(1)}", relative, content, match.start(), 0.8
            )
        if first is not None:
            self._append_unique_hint(
                result.framework_hints, FrameworkHint, "laminas_controller_mapping", relative, content, first, 0.8
            )

    def _extract_laminas_services(self, content: str, relative: str, result: ScanResult) -> None:
        first: int | None = None
        for match in LAMINAS_SERVICE_PATTERN.finditer(content):
            if not _SERVICE_WORD.search(match.group(1)):
                continue
            if first is None:
                first = match.start()
            self._append_unique_hint(
                result.framework_hints, FrameworkHint, f"service:{match.group(1)}", relative, content, match.start(), 0.7
            )
        manager = re.search(r"['\"]service_manager['\"]", content)
        anchor = manager.start() if manager else first
        if anchor is not None:
            self._append_unique_hint(
                result.framework_hints, FrameworkHint, "laminas_service_manager", relative, content, anchor, 0.8
            )

    def _extract_external_calls(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in OUTBOUND_PATTERNS:
            for match in pattern.finditer(content):
                self._append_unique_external(result, match.group(1), relative, content, match.start())

    def _extract_datastores(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, kind in DATABASE_PATTERNS:
            match = pattern.search(content)
            if match:
                self._append_unique_database(result, kind, relative, content, match.start())

    def _extract_auth_hints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint in AUTH_PATTERNS:
            match = pattern.search(content)
            if match:
                self._append_unique_hint(result.auth_hints, AuthHint, hint, relative, content, match.start())

    def _extract_secret_hints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                self._append_unique_secret(result, match.group(1), relative, content, match.start())

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
    def _composer_offset(text: str, package: str) -> int:
        """Offset of a package's `"name": "constraint"` entry in composer.json (0 if not found)."""
        index = text.find(f'"{package}"')
        return index if index >= 0 else 0

    @staticmethod
    def _append_unique_route(result: ScanResult, path: str, method: str, file: str, line: int) -> None:
        key = (path, method, file)
        if any((item.path, item.method, item.file) == key for item in result.routes):
            return
        result.routes.append(Route(path=path, method=method, file=file, line=line))

    @staticmethod
    def _append_unique_external(result: ScanResult, target: str, file: str, content: str, offset: int) -> None:
        key = (target, file)
        if any((item.target, item.file) == key for item in result.external_calls):
            return
        line = line_of(content, offset)
        result.external_calls.append(
            ExternalCall(target=target, file=file, line=line, evidence_text=line_snippet(content, line) or target)
        )

    @staticmethod
    def _append_unique_database(result: ScanResult, kind: str, file: str, content: str, offset: int) -> None:
        key = (kind, file)
        if any((item.kind, item.file) == key for item in result.databases):
            return
        line = line_of(content, offset)
        result.databases.append(
            DatabaseHint(kind=kind, file=file, line=line, evidence_text=line_snippet(content, line) or kind)
        )

    @staticmethod
    def _append_unique_hint(
        bucket: list,
        model: type,
        hint: str,
        file: str,
        content: str,
        offset: int,
        confidence: float | None = None,
    ) -> None:
        """Append an AuthHint/FrameworkHint once per (hint, file), located at ``offset``."""
        if any((item.hint, item.file) == (hint, file) for item in bucket):
            return
        line = line_of(content, offset)
        extra = {"confidence": confidence} if confidence is not None else {}
        bucket.append(
            model(hint=hint, file=file, line=line, evidence_text=line_snippet(content, line) or hint, **extra)
        )

    @staticmethod
    def _append_unique_secret(result: ScanResult, name: str, file: str, content: str, offset: int) -> None:
        key = (name, file)
        if any((item.name, item.file) == key for item in result.secret_hints):
            return
        line = line_of(content, offset)
        result.secret_hints.append(
            SecretHint(name=name, file=file, line=line, evidence_text=line_snippet(content, line) or name)
        )
