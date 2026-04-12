"""Auto-detector: identifies artifact type from file input.

Detection order (most reliable first):
1. Magic bytes (libmagic)
2. Shebang line
3. File extension
4. Content heuristics
5. Mismatch detection (extension vs actual type = security finding)
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class ArtifactType(str, Enum):
    CODE = "code"
    CONFIG = "config"
    REPOSITORY = "repository"
    PACKAGE = "package"
    MCP_SERVER = "mcp_server"
    BINARY = "binary"
    DIRECTORY = "directory"
    UNKNOWN = "unknown"


class Language(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    POWERSHELL = "powershell"
    BASH = "bash"
    PHP = "php"
    HTML = "html"
    RUBY = "ruby"
    GO = "go"
    RUST = "rust"
    PERL = "perl"
    JAVA = "java"
    KOTLIN = "kotlin"
    C = "c"
    CPP = "cpp"
    CSHARP = "csharp"
    LUA = "lua"
    R = "r"
    SWIFT = "swift"
    YAML = "yaml"
    JSON = "json"
    TOML = "toml"
    INI = "ini"
    XML = "xml"
    DOCKERFILE = "dockerfile"
    DOCKER_COMPOSE = "docker_compose"
    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    JENKINSFILE = "jenkinsfile"
    TERRAFORM = "terraform"
    KUBERNETES = "kubernetes"
    ENV_FILE = "env_file"
    SHELL_GENERIC = "shell_generic"
    BATCH = "batch"
    VBS = "vbscript"
    MCP_MANIFEST = "mcp_manifest"
    PE_EXE = "pe_exe"
    ELF = "elf"
    APK = "apk"
    UNKNOWN = "unknown"


@dataclass
class DetectionResult:
    artifact_type: ArtifactType
    language: Language
    file_path: Path
    detection_method: str
    confidence: float
    is_polyglot: bool = False
    secondary_languages: list[Language] = field(default_factory=list)
    type_mismatch: bool = False
    mismatch_detail: Optional[str] = None
    magic_description: Optional[str] = None


EXTENSION_MAP: dict[str, Language] = {
    ".py": Language.PYTHON, ".pyw": Language.PYTHON, ".pyi": Language.PYTHON,
    ".js": Language.JAVASCRIPT, ".mjs": Language.JAVASCRIPT, ".cjs": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT, ".ts": Language.TYPESCRIPT, ".tsx": Language.TYPESCRIPT,
    ".ps1": Language.POWERSHELL, ".psm1": Language.POWERSHELL, ".psd1": Language.POWERSHELL,
    ".sh": Language.BASH, ".bash": Language.BASH, ".zsh": Language.BASH,
    ".php": Language.PHP, ".phtml": Language.PHP, ".html": Language.HTML, ".htm": Language.HTML,
    ".rb": Language.RUBY, ".rake": Language.RUBY,
    ".go": Language.GO, ".rs": Language.RUST,
    ".pl": Language.PERL, ".pm": Language.PERL,
    ".java": Language.JAVA, ".kt": Language.KOTLIN, ".kts": Language.KOTLIN,
    ".c": Language.C, ".h": Language.C, ".cpp": Language.CPP, ".hpp": Language.CPP,
    ".cs": Language.CSHARP, ".lua": Language.LUA, ".r": Language.R, ".swift": Language.SWIFT,
    ".yml": Language.YAML, ".yaml": Language.YAML, ".json": Language.JSON,
    ".toml": Language.TOML, ".ini": Language.INI, ".cfg": Language.INI,
    ".xml": Language.XML, ".tf": Language.TERRAFORM, ".hcl": Language.TERRAFORM,
    ".env": Language.ENV_FILE, ".bat": Language.BATCH, ".cmd": Language.BATCH,
    ".vbs": Language.VBS,
}

SHEBANG_MAP: dict[str, Language] = {
    "python": Language.PYTHON, "python3": Language.PYTHON,
    "node": Language.JAVASCRIPT, "nodejs": Language.JAVASCRIPT,
    "bash": Language.BASH, "sh": Language.BASH, "zsh": Language.BASH,
    "ruby": Language.RUBY, "perl": Language.PERL, "php": Language.PHP,
    "pwsh": Language.POWERSHELL, "powershell": Language.POWERSHELL,
}

CONTENT_PATTERNS: list[tuple[str, Language, float]] = [
    ("if __name__", Language.PYTHON, 0.8),
    ("import ", Language.PYTHON, 0.3),
    ("def ", Language.PYTHON, 0.3),
    ("console.log", Language.JAVASCRIPT, 0.6),
    ("require(", Language.JAVASCRIPT, 0.5),
    ("module.exports", Language.JAVASCRIPT, 0.7),
    ("function ", Language.JAVASCRIPT, 0.3),
    ("<?php", Language.PHP, 0.9),
    ("<!DOCTYPE html", Language.HTML, 0.5),
    ("<html", Language.HTML, 0.3),
    ("[CmdletBinding()]", Language.POWERSHELL, 0.9),
    ("Invoke-", Language.POWERSHELL, 0.5),
    ("Get-", Language.POWERSHELL, 0.4),
    ("$PSVersionTable", Language.POWERSHELL, 0.8),
    ("package main", Language.GO, 0.9),
    ("fmt.Print", Language.GO, 0.7),
    ("use std::", Language.RUST, 0.8),
    ("pub fn", Language.RUST, 0.7),
    ("public static void main", Language.JAVA, 0.9),
    ("@echo off", Language.BATCH, 0.9),
    ("set ", Language.BATCH, 0.3),
    ("goto ", Language.BATCH, 0.5),
    ("REM ", Language.BATCH, 0.4),
    ("pause", Language.BATCH, 0.3),
]


class AutoDetector:
    def __init__(self, config: Optional["ConfigManager"] = None):
        self.config = config
        self._magic_available = False
        try:
            import magic
            self._magic = magic
            self._magic_available = True
        except ImportError:
            self._magic = None

    def detect(self, target: str) -> DetectionResult:
        path = Path(target).resolve()

        if not path.exists():
            return self._handle_non_file_target(target)
            
        # Check size limit from config (default 10MB)
        if path.is_file():
            max_mb = 10
            if self.config:
                max_mb = self.config.get("scanners.code.max_file_size_mb", 10)
            
            if path.stat().st_size > (max_mb * 1024 * 1024):
                 return DetectionResult(
                    artifact_type=ArtifactType.BINARY,
                    language=Language.UNKNOWN,
                    file_path=path,
                    detection_method="size_limit_exceeded",
                    confidence=1.0,
                    magic_description=f"File exceeds {max_mb}MB limit set in config.",
                    type_mismatch=True,
                    mismatch_detail=f"File too large to scan ({path.stat().st_size / (1024*1024):.1f} MB)"
                )

        if path.is_dir():
            return self._detect_directory(path)

        return self._detect_file(path)

    def _handle_non_file_target(self, target: str) -> DetectionResult:
        if target.startswith(("http://", "https://", "git@")):
            if any(host in target for host in ["github.com", "gitlab.com", "bitbucket.org"]):
                return DetectionResult(
                    artifact_type=ArtifactType.REPOSITORY,
                    language=Language.UNKNOWN,
                    file_path=Path(target),
                    detection_method="url_pattern",
                    confidence=0.9,
                )
            return DetectionResult(
                artifact_type=ArtifactType.MCP_SERVER,
                language=Language.UNKNOWN,
                file_path=Path(target),
                detection_method="url_pattern",
                confidence=0.5,
                is_polyglot=False # Added to match struct
            )

        # If it looks like a local path (starts with ./, ../, / or contains path separators)
        # but doesn't exist, don't assume it's a package.
        if any(target.startswith(p) for p in ["./", "../", "/"]) or os.path.sep in target:
            return DetectionResult(
                artifact_type=ArtifactType.UNKNOWN,
                language=Language.UNKNOWN,
                file_path=Path(target),
                detection_method="path_not_found",
                confidence=1.0,
                magic_description=f"Local path not found: {target}"
            )

        # If it's a simple name without extensions or slashes, it's likely a package
        if "." not in target and "/" not in target and "\\" not in target:
            return DetectionResult(
                artifact_type=ArtifactType.PACKAGE,
                language=Language.UNKNOWN,
                file_path=Path(target),
                detection_method="assumed_package_name",
                confidence=0.4,
            )

        return DetectionResult(
            artifact_type=ArtifactType.UNKNOWN,
            language=Language.UNKNOWN,
            file_path=Path(target),
            detection_method="unrecognized_local_input",
            confidence=1.0,
            magic_description="Not a file, directory, or valid URL."
        )

    def _detect_directory(self, path: Path) -> DetectionResult:
        if (path / ".git").exists():
            return DetectionResult(
                artifact_type=ArtifactType.REPOSITORY,
                language=Language.UNKNOWN,
                file_path=path,
                detection_method="git_directory",
                confidence=0.95,
            )
        return DetectionResult(
            artifact_type=ArtifactType.DIRECTORY,
            language=Language.UNKNOWN,
            file_path=path,
            detection_method="local_directory",
            confidence=1.0,
        )

    def _detect_file(self, path: Path) -> DetectionResult:
        magic_lang = self._detect_magic_bytes(path)
        magic_desc = self._get_magic_description(path)
        shebang_lang = self._detect_shebang(path)
        ext_lang = self._detect_extension(path)
        content_lang = self._detect_content_heuristics(path)

        detected_lang = Language.UNKNOWN
        method = "unknown"
        confidence = 0.0

        if magic_lang and magic_lang != Language.UNKNOWN:
            detected_lang = magic_lang
            method = "magic_bytes"
            confidence = 0.95
        elif shebang_lang and shebang_lang != Language.UNKNOWN:
            detected_lang = shebang_lang
            method = "shebang"
            confidence = 0.9
        elif ext_lang and ext_lang != Language.UNKNOWN:
            detected_lang = ext_lang
            method = "extension"
            confidence = 0.7
        elif content_lang and content_lang != Language.UNKNOWN:
            detected_lang = content_lang
            method = "content_heuristics"
            confidence = 0.5

        artifact_type = self._language_to_artifact_type(detected_lang)

        # Downgrade BATCH if no heuristics or shebang matches (avoids generic text files)
        if detected_lang == Language.BATCH and method == "extension":
            if not content_lang == Language.BATCH and not shebang_lang:
                # If it's a very small file (< 10 bytes) or has no batch markers, it's just text
                detected_lang = Language.UNKNOWN
                method = "downgraded_from_extension"

        special = self._check_special_filenames(path)
        if special:
            detected_lang = special
            artifact_type = self._language_to_artifact_type(special)
            method = "filename_match"
            confidence = 0.95

        # JSON MCP client configs often register as generic JSON — detect by marker
        if path.suffix.lower() == ".json" or detected_lang == Language.JSON:
            try:
                head = path.read_text(encoding="utf-8", errors="ignore")[:8192]
            except OSError:
                head = ""
            if '"mcpServers"' in head or '"mcp_servers"' in head:
                if detected_lang != Language.MCP_MANIFEST:
                    detected_lang = Language.MCP_MANIFEST
                    artifact_type = ArtifactType.MCP_SERVER
                    method = "mcp_manifest_content"
                confidence = max(confidence, 0.92)

        # Mismatch detection
        type_mismatch = False
        mismatch_detail = None
        if (ext_lang and magic_lang
                and ext_lang != magic_lang
                and magic_lang != Language.UNKNOWN
                and ext_lang != Language.UNKNOWN):
            type_mismatch = True
            mismatch_detail = (
                f"Extension suggests {ext_lang.value} but "
                f"magic bytes indicate {magic_lang.value}"
            )

        # Polyglot detection
        all_detected = set()
        for lang in [magic_lang, shebang_lang, ext_lang, content_lang]:
            if lang and lang != Language.UNKNOWN:
                all_detected.add(lang)
        is_polyglot = len(all_detected) > 1 and not type_mismatch
        secondary = [l for l in all_detected if l != detected_lang]

        return DetectionResult(
            artifact_type=artifact_type,
            language=detected_lang,
            file_path=path,
            detection_method=method,
            confidence=confidence,
            is_polyglot=is_polyglot,
            secondary_languages=secondary,
            type_mismatch=type_mismatch,
            mismatch_detail=mismatch_detail,
            magic_description=magic_desc,
        )

    def _detect_magic_bytes(self, path: Path) -> Optional[Language]:
        if not self._magic_available:
            return None
        try:
            mime = self._magic.from_file(str(path), mime=True)
            mime_map = {
                "text/x-python": Language.PYTHON,
                "text/x-script.python": Language.PYTHON,
                "text/javascript": Language.JAVASCRIPT,
                "application/javascript": Language.JAVASCRIPT,
                "text/x-shellscript": Language.BASH,
                "text/x-sh": Language.BASH,
                "text/x-php": Language.PHP,
                "text/html": Language.HTML,
                "text/x-ruby": Language.RUBY,
                "text/x-perl": Language.PERL,
                "text/x-c": Language.C,
                "text/x-c++": Language.CPP,
                "text/x-java": Language.JAVA,
                "application/x-executable": Language.ELF,
                "application/x-dosexec": Language.PE_EXE,
                "application/x-yaml": Language.YAML,
                "application/json": Language.JSON,
                "application/xml": Language.XML,
                "text/xml": Language.XML,
            }
            return mime_map.get(mime)
        except Exception:
            return None

    def _get_magic_description(self, path: Path) -> Optional[str]:
        if not self._magic_available:
            return None
        try:
            return self._magic.from_file(str(path))
        except Exception:
            return None

    def _detect_shebang(self, path: Path) -> Optional[Language]:
        try:
            with open(path, "rb") as f:
                first_bytes = f.read(256)
            if not first_bytes.startswith(b"#!"):
                return None
            first_line = first_bytes.split(b"\n")[0].decode("utf-8", errors="ignore")
            shebang = first_line[2:].strip()
            for key, lang in SHEBANG_MAP.items():
                if key in shebang:
                    return lang
            return Language.SHELL_GENERIC
        except Exception:
            return None

    def _detect_extension(self, path: Path) -> Optional[Language]:
        return EXTENSION_MAP.get(path.suffix.lower())

    def _detect_content_heuristics(self, path: Path) -> Optional[Language]:
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")[:5000]
        except Exception:
            return None

        scores: dict[Language, float] = {}
        for pattern, lang, weight in CONTENT_PATTERNS:
            if pattern in content:
                scores[lang] = scores.get(lang, 0) + weight

        if not scores:
            return None
        best = max(scores, key=scores.get)
        return best if scores[best] >= 0.5 else None

    def _check_special_filenames(self, path: Path) -> Optional[Language]:
        name = path.name.lower()
        special = {
            "dockerfile": Language.DOCKERFILE,
            "containerfile": Language.DOCKERFILE,
            "docker-compose.yml": Language.DOCKER_COMPOSE,
            "docker-compose.yaml": Language.DOCKER_COMPOSE,
            "compose.yml": Language.DOCKER_COMPOSE,
            "compose.yaml": Language.DOCKER_COMPOSE,
            "jenkinsfile": Language.JENKINSFILE,
            "gemfile": Language.RUBY,
            "rakefile": Language.RUBY,
            "makefile": Language.SHELL_GENERIC,
            ".env": Language.ENV_FILE,
            ".env.local": Language.ENV_FILE,
            ".env.production": Language.ENV_FILE,
            ".env.example": Language.ENV_FILE,
        }
        if name in special:
            return special[name]
        if name in ("mcp-config.json", "mcp.json", "mcp_config.json"):
            return Language.MCP_MANIFEST
        if ".github/workflows" in str(path).replace("\\", "/") and name.endswith((".yml", ".yaml")):
            return Language.GITHUB_ACTIONS
        if name == ".gitlab-ci.yml":
            return Language.GITLAB_CI
        return None

    def _language_to_artifact_type(self, lang: Language) -> ArtifactType:
        config_langs = {
            Language.YAML, Language.JSON, Language.TOML, Language.INI, Language.XML,
            Language.DOCKERFILE, Language.DOCKER_COMPOSE, Language.GITHUB_ACTIONS,
            Language.GITLAB_CI, Language.JENKINSFILE, Language.TERRAFORM,
            Language.KUBERNETES, Language.ENV_FILE,
        }
        binary_langs = {Language.PE_EXE, Language.ELF, Language.APK}
        if lang in config_langs:
            return ArtifactType.CONFIG
        if lang in binary_langs:
            return ArtifactType.BINARY
        if lang == Language.MCP_MANIFEST:
            return ArtifactType.MCP_SERVER
        if lang != Language.UNKNOWN:
            return ArtifactType.CODE
        return ArtifactType.UNKNOWN
