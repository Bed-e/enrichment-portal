"""No committed fixture may contain a key (design.md D13)."""

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures"


def key_variable_names() -> list[str]:
    lines = (ROOT / ".env.example").read_text().splitlines()
    return [
        line.split("=", 1)[0].strip()
        for line in lines
        if "=" in line and not line.lstrip().startswith("#")
    ]


def committed_fixture_files() -> list[Path]:
    return [p for p in FIXTURES.rglob("*") if p.is_file() and "_raw" not in p.parts]


def test_fixtures_exist() -> None:
    assert committed_fixture_files()


def test_no_fixture_contains_a_key_name_or_value() -> None:
    names = key_variable_names()
    assert names, ".env.example should list the key variables"
    values = [os.environ[n] for n in names if os.environ.get(n)]
    for path in committed_fixture_files():
        text = path.read_text()
        for name in names:
            assert name not in text, f"{path.name} mentions {name}"
        for value in values:
            assert value not in text, f"{path.name} contains a configured key value"


def test_gitignore_covers_every_path_that_must_stay_local() -> None:
    import shutil
    import subprocess

    import pytest

    if shutil.which("git") is None:
        pytest.skip("git not available")
    paths = [
        ".env",
        "backend/tests/fixtures/_raw/x.json",
        "backend/data/lookups.db",
        "data/x",
        "logs/app.log",
        "anything.db",
    ]
    for path in paths:
        result = subprocess.run(
            ["git", "check-ignore", "-q", path], cwd=ROOT, capture_output=True, check=False
        )
        assert result.returncode == 0, f"{path} is not gitignored"
    example = subprocess.run(
        ["git", "check-ignore", "-q", ".env.example"], cwd=ROOT, capture_output=True, check=False
    )
    assert example.returncode == 1, ".env.example must stay committed"
