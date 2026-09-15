

"""Service layer for CloudGuard. Pure logic, no Flask imports."""
"""Tests for the recursive file scanner."""
from pathlib import Path

from app.services.file_scanner import is_binary, scan_directory


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_finds_supported_extensions(tmp_path):
    _write(tmp_path / "a.py", "print('hi')")
    _write(tmp_path / "b.js", "console.log('hi')")
    _write(tmp_path / "c.txt", "hello")
    _write(tmp_path / "d.exe", "binary stuff")

    files = list(scan_directory(tmp_path))
    names = sorted(f.relative_path for f in files)
    assert "a.py" in names
    assert "b.js" in names
    assert "c.txt" in names
    assert "d.exe" not in names


def test_recursive_subdirectories(tmp_path):
    _write(tmp_path / "src" / "app.py", "x = 1")
    _write(tmp_path / "src" / "nested" / "deep.js", "y = 2")

    files = list(scan_directory(tmp_path))
    rels = [f.relative_path for f in files]
    assert any("app.py" in r for r in rels)
    assert any("deep.js" in r for r in rels)


def test_skips_excluded_dirs(tmp_path):
    _write(tmp_path / "node_modules" / "lib.js", "x = 1")
    _write(tmp_path / ".git" / "config", "[core]")
    _write(tmp_path / "src" / "app.py", "x = 1")

    files = list(scan_directory(tmp_path))
    rels = [f.relative_path for f in files]
    assert any("app.py" in r for r in rels)
    assert not any("node_modules" in r for r in rels)
    assert not any(".git" in r for r in rels)


def test_detects_binary(tmp_path):
    b = tmp_path / "blob.bin"
    b.write_bytes(b"\x00\x01\x02\x03" * 100)
    assert is_binary(b) is True


def test_detects_text(tmp_path):
    t = tmp_path / "readme.txt"
    t.write_text("hello world", encoding="utf-8")
    assert is_binary(t) is False


def test_skips_binary_in_scan(tmp_path):
    _write(tmp_path / "app.py", "x = 1")
    (tmp_path / "data.txt").write_bytes(b"\x00" * 500)
    files = list(scan_directory(tmp_path))
    rels = [f.relative_path for f in files]
    assert "app.py" in rels
    assert "data.txt" not in rels


def test_respects_max_file_size(tmp_path):
    _write(tmp_path / "big.py", "x" * 5000)
    _write(tmp_path / "small.py", "y")
    files = list(scan_directory(tmp_path, max_file_size=100))
    rels = [f.relative_path for f in files]
    assert "small.py" in rels
    assert "big.py" not in rels


def test_reads_dockerfile_and_env(tmp_path):
    _write(tmp_path / "Dockerfile", "FROM python:3.12")
    _write(tmp_path / ".env", "FOO=bar")
    files = list(scan_directory(tmp_path))
    rels = sorted(f.relative_path for f in files)
    assert "Dockerfile" in rels
    assert ".env" in rels


def test_language_detection(tmp_path):
    _write(tmp_path / "app.py", "x = 1")
    _write(tmp_path / "Dockerfile", "FROM python")
    files = {f.relative_path: f for f in scan_directory(tmp_path)}
    assert files["app.py"].language == "py"
    assert files["Dockerfile"].language == "dockerfile"