"""Tests for safe ZIP extraction."""
import zipfile
from pathlib import Path

import pytest

from app.services.archive_handler import (
    ArchiveError,
    ArchiveLimits,
    ArchiveLimitsExceeded,
    UnsafeArchiveError,
    safe_extract_zip,
)


def _make_zip(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


def test_extracts_normal_zip(tmp_path):
    zip_path = _make_zip(tmp_path / "in.zip", {"a.txt": b"hello", "sub/b.txt": b"world"})
    dest = tmp_path / "out"
    result = safe_extract_zip(zip_path, dest)
    assert result == dest.resolve(strict=False)
    assert (dest / "a.txt").read_bytes() == b"hello"
    assert (dest / "sub" / "b.txt").read_bytes() == b"world"


def test_rejects_zip_slip_dotdot(tmp_path):
    zip_path = _make_zip(tmp_path / "bad.zip", {"../evil.txt": b"x"})
    with pytest.raises(UnsafeArchiveError):
        safe_extract_zip(zip_path, tmp_path / "out")


def test_rejects_absolute_path(tmp_path):
    zip_path = _make_zip(tmp_path / "bad.zip", {"/etc/passwd": b"x"})
    with pytest.raises(UnsafeArchiveError):
        safe_extract_zip(zip_path, tmp_path / "out")


def test_rejects_drive_letter_path(tmp_path):
    zip_path = _make_zip(tmp_path / "bad.zip", {"C:/evil.txt": b"x"})
    with pytest.raises(UnsafeArchiveError):
        safe_extract_zip(zip_path, tmp_path / "out")


def test_rejects_too_many_files(tmp_path):
    entries = {f"f{i}.txt": b"x" for i in range(5)}
    zip_path = _make_zip(tmp_path / "many.zip", entries)
    with pytest.raises(ArchiveLimitsExceeded):
        safe_extract_zip(zip_path, tmp_path / "out", limits=ArchiveLimits(max_files=3))


def test_rejects_oversized_single_file(tmp_path):
    zip_path = _make_zip(tmp_path / "big.zip", {"big.txt": b"A" * 2048})
    with pytest.raises(ArchiveLimitsExceeded):
        safe_extract_zip(zip_path, tmp_path / "out", limits=ArchiveLimits(max_single_file=1024))


def test_rejects_non_zip(tmp_path):
    bad = tmp_path / "not.zip"
    bad.write_bytes(b"this is not a zip")
    with pytest.raises(ArchiveError):
        safe_extract_zip(bad, tmp_path / "out")


def test_missing_zip(tmp_path):
    with pytest.raises(ArchiveError):
        safe_extract_zip(tmp_path / "missing.zip", tmp_path / "out")