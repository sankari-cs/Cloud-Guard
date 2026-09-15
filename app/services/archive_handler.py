"""Safe ZIP extraction.

Guards against Zip Slip, absolute paths, drive-letter paths, zip bombs,
excessive entry counts, and oversized single/total uncompressed sizes.
"""
from __future__ import annotations

import logging
import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


class ArchiveError(Exception):
    """Base class for archive handling errors."""


class UnsafeArchiveError(ArchiveError):
    """Archive contains path traversal or other unsafe entries."""


class ArchiveLimitsExceeded(ArchiveError):
    """Archive exceeds configured extraction limits."""


@dataclass(frozen=True)
class ArchiveLimits:
    max_files: int = 5000
    max_total_size: int = 200 * 1024 * 1024        # 200 MB
    max_single_file: int = 50 * 1024 * 1024        # 50 MB
    max_compression_ratio: float = 100.0           # zip-bomb heuristic


def _is_within_directory(base: Path, target: Path) -> bool:
    """True only if target resolves inside base."""
    try:
        base_r = base.resolve(strict=False)
        target_r = target.resolve(strict=False)
    except OSError:
        return False
    return base_r == target_r or base_r in target_r.parents


def _check_member_name(name: str) -> None:
    """Reject absolute, drive-letter, and traversal paths."""
    if not name:
        return
    if name.startswith(("/", "\\")):
        raise UnsafeArchiveError(f"Absolute path in archive: {name!r}")
    if len(name) >= 2 and name[1] == ":":
        raise UnsafeArchiveError(f"Drive-letter path in archive: {name!r}")
    parts = Path(name.replace("\\", "/")).parts
    if any(part == ".." for part in parts):
        raise UnsafeArchiveError(f"Path traversal in archive: {name!r}")


def safe_extract_zip(
    zip_path: Path | str,
    dest_dir: Path | str,
    limits: ArchiveLimits | None = None,
) -> Path:
    """Safely extract a ZIP into dest_dir. Returns resolved destination."""
    limits = limits or ArchiveLimits()
    zip_path = Path(zip_path)
    dest_dir = Path(dest_dir).resolve(strict=False)

    if not zip_path.is_file():
        raise ArchiveError(f"ZIP file not found: {zip_path}")
    if not zipfile.is_zipfile(zip_path):
        raise ArchiveError("File is not a valid ZIP archive")

    dest_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path) as zf:
        members = zf.infolist()

        if len(members) > limits.max_files:
            raise ArchiveLimitsExceeded(
                f"Archive has {len(members)} entries, limit {limits.max_files}"
            )

        total_uncompressed = 0
        for info in members:
            _check_member_name(info.filename)
            if info.is_dir():
                continue
            if info.file_size > limits.max_single_file:
                raise ArchiveLimitsExceeded(
                    f"Entry {info.filename!r} size {info.file_size} > "
                    f"limit {limits.max_single_file}"
                )
            if info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > limits.max_compression_ratio:
                    raise ArchiveLimitsExceeded(
                        f"Suspicious compression ratio for {info.filename!r}: "
                        f"{ratio:.1f}"
                    )
            total_uncompressed += info.file_size
            if total_uncompressed > limits.max_total_size:
                raise ArchiveLimitsExceeded(
                    f"Total uncompressed size exceeds {limits.max_total_size}"
                )

        # Extraction
        for info in members:
            name = info.filename
            if not name or name.endswith("/"):
                (dest_dir / name).mkdir(parents=True, exist_ok=True)
                continue
            target = dest_dir / name
            if not _is_within_directory(dest_dir, target):
                raise UnsafeArchiveError(f"Entry escapes destination: {name!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            if not _is_within_directory(dest_dir, target):
                raise UnsafeArchiveError(f"Entry escapes destination: {name!r}")
            with zf.open(info) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst, length=64 * 1024)

    logger.info(
        "Extracted %s to %s (%d entries)",
        zip_path.name, dest_dir, len(members),
    )
    return dest_dir