"""The core's purity boundary, enforced rather than promised.

``docs/BOUNDARY.md`` claims this package has no live scanner, service API,
database, user login or target-changing capability. That claim is only worth
anything if something checks it, so these tests fail the build if the core ever
grows an import that could reach the network, a database, the filesystem, a
subprocess or the wall clock.

The wall-clock rule deserves its own note. Every contract takes ``now`` as a
parameter. If any module called ``datetime.now()`` internally, the testing-window,
EPSS-freshness, anchor-overdue and stop-budget scenarios would all become
unrepeatable -- and C01-D (crash between receipt verification and commit) would
be untestable, because its whole point is replaying a decision at a later time.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

CORE = pathlib.Path(__file__).resolve().parents[1] / "src" / "seal" / "core"

#: Modules the core must never import. A dependency on any of these would mean
#: the decision layer can reach outside itself.
FORBIDDEN_IMPORTS = frozenset(
    {
        # network
        "socket",
        "ssl",
        "http",
        "urllib",
        "urllib3",
        "requests",
        "httpx",
        "aiohttp",
        "ftplib",
        "smtplib",
        "telnetlib",
        "asyncio",
        # database and cache
        "sqlite3",
        "psycopg",
        "psycopg2",
        "sqlalchemy",
        "redis",
        "celery",
        "pymysql",
        # process and filesystem
        "subprocess",
        "os",
        "shutil",
        "pathlib",
        "tempfile",
        "glob",
        "io",
        "pickle",
        "shelve",
        "multiprocessing",
        "threading",
        "signal",
        "ctypes",
        "importlib",
        # web frameworks
        "fastapi",
        "starlette",
        "flask",
        "django",
        "uvicorn",
        "pydantic",
        # anything scanner-shaped
        "zapv2",
        "docker",
    }
)

#: Calls that would read the wall clock or produce unrepeatable values.
FORBIDDEN_CALLS = {
    ("datetime", "now"),
    ("datetime", "utcnow"),
    ("datetime", "today"),
    ("time", "time"),
    ("time", "sleep"),
    ("time", "monotonic"),
    ("random", "random"),
    ("uuid", "uuid4"),
    ("os", "urandom"),
}

CORE_MODULES = sorted(path.name for path in CORE.glob("*.py"))


def parsed(name: str) -> ast.Module:
    return ast.parse((CORE / name).read_text(encoding="utf-8"), filename=name)


def imported_roots(tree: ast.Module) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def test_the_core_has_modules_to_check():
    """Guards the guard: an empty glob would make every test below vacuous."""
    assert len(CORE_MODULES) >= 12
    assert "closure.py" in CORE_MODULES
    assert "integrity.py" in CORE_MODULES


@pytest.mark.parametrize("module", CORE_MODULES)
def test_no_core_module_imports_an_io_capable_library(module):
    forbidden = imported_roots(parsed(module)) & FORBIDDEN_IMPORTS
    assert not forbidden, f"{module} imports {sorted(forbidden)}"


@pytest.mark.parametrize("module", CORE_MODULES)
def test_no_core_module_reads_the_wall_clock_or_a_random_source(module):
    """``now`` is always a parameter, never something a module fetches itself."""
    offenders = []
    for node in ast.walk(parsed(module)):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        if isinstance(function, ast.Attribute) and isinstance(function.value, ast.Name):
            pair = (function.value.id, function.attr)
            if pair in FORBIDDEN_CALLS:
                offenders.append(f"{pair[0]}.{pair[1]}()")
    assert not offenders, f"{module} calls {offenders}"


@pytest.mark.parametrize("module", CORE_MODULES)
def test_no_core_module_opens_a_file_or_evaluates_code(module):
    forbidden_builtins = {"open", "eval", "exec", "compile", "__import__", "input"}
    offenders = [
        node.func.id
        for node in ast.walk(parsed(module))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in forbidden_builtins
    ]
    assert not offenders, f"{module} calls {offenders}"


def test_the_core_declares_no_runtime_dependencies():
    """F01's pinned-dependency policy: the decision layer stays dependency-free.

    Read from pyproject.toml as text rather than with a TOML parser, because
    this test is itself part of the boundary -- it should not need a dependency
    to check that there are no dependencies.
    """
    pyproject = (CORE.parents[2] / "pyproject.toml").read_text(encoding="utf-8")
    assert "dependencies = []" in pyproject


def test_every_core_module_is_importable_without_side_effects():
    """Importing the core must not require anything to be running."""
    import importlib

    for module in CORE_MODULES:
        if module.startswith("__"):
            continue
        importlib.import_module(f"seal.core.{module[:-3]}")
