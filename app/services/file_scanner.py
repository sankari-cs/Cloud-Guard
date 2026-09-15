"""Recursive file scanner.

Walks a directory, filters by extension/filename, detects binary files,
and yields text content for the detector. Does not follow symlinks or
read files beyond the size cap.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)


SUPPORTED_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
    ".env", ".yaml", ".yml", ".json", ".xml", ".ini", ".cfg", ".conf",
    ".properties", ".toml", ".txt", ".sh", ".bash", ".ps1", ".sql",
    ".md", ".html", ".htm", ".css", ".vue", ".gradle", ".tf",
})

SUPPORTED_FILENAMES: frozenset[str] = frozenset({
    "Dockerfile", "dockerfile", ".env", ".env.local", ".env.production",
    "Makefile", "makefile", ".npmrc", ".pypirc", ".netrc", ".htaccess",
    "Jenkinsfile", "Procfile",
})

EXCLUDED_DIRS: frozenset[str] = frozenset({
    ".git", ".svn", ".hg", "node_modules", ".venv", "venv", "env",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".tox", "dist", "build", ".idea", ".vscode", ".next", ".nuxt",
    "target", "vendor", "bower_components",
})

EXCLUDED_FILENAMES: frozenset[str] = frozenset({
    ".DS_Store", "Thumbs.db", "desktop.ini",
})

DEFAULT_MAX_FILE_SIZE: int = 5 * 1024 * 1024  # 5 MB
BINARY_SAMPLE_SIZE: int = 8192


@dataclass
class ScannedFile:
    """A single supported text file successfully read from disk."""
    path: Path
    relative_path: str
    size: int
    content: str
    language: str


def _language_for(path: Path) -> str:
    name = path.name.lower()
    if name == "dockerfile":
        return "dockerfile"
    if name == "jenkinsfile":
        return "groovy"
    if name == "makefile":
        return "makefile"
    ext = path.suffix.lower().lstrip(".")
    return ext or "text"


def is_binary(path: Path, sample_size: int = BINARY_SAMPLE_SIZE) -> bool:
    """Heuristic binary check: NUL bytes or high ratio of non-printable bytes."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(sample_size)
    except OSError:
        return True
    if not chunk:
        return False
    if b"\x00" in chunk:
        return True
    text_chars = bytes(range(32, 127)) + b"\n\r\t\f\b"
    nontext = sum(1 for b in chunk if b not in text_chars)
    return nontext / len(chunk) > 0.30


def _read_text(path: Path, max_bytes: int) -> str | None:
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size == 0 or size > max_bytes:
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def scan_directory(
    root: Path | str,
    *,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    supported_extensions: frozenset[str] = SUPPORTED_EXTENSIONS,
    supported_filenames: frozenset[str] = SUPPORTED_FILENAMES,
    excluded_dirs: frozenset[str] = EXCLUDED_DIRS,
    excluded_filenames: frozenset[str] = EXCLUDED_FILENAMES,
) -> Iterator[ScannedFile]:
    """Yield ScannedFile objects for each supported text file under root."""
    root = Path(root).resolve(strict=True)

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [
            d for d in dirnames
            if d not in excluded_dirs and not d.startswith(".")
        ]

        current_dir = Path(dirpath)

        for filename in filenames:
            if filename in excluded_filenames:
                continue

            file_path = current_dir / filename

            if file_path.is_symlink():
                continue

            ext = file_path.suffix.lower()
            if filename not in supported_filenames and ext not in supported_extensions:
                continue

            if is_binary(file_path):
                continue

            content = _read_text(file_path, max_file_size)
            if content is None:
                continue

            try:
                rel = str(file_path.relative_to(root))
            except ValueError:
                rel = str(file_path)

            try:
                size = file_path.stat().st_size
            except OSError:
                size = len(content)

            yield ScannedFile(
                path=file_path,
                relative_path=rel,
                size=size,
                content=content,
                language=_language_for(file_path),
            )