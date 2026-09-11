"""Static checks, so `make test` covers style and self-consistency too.

The ruff test skips cleanly when the optional dev extra is missing: the runtime
must stay stdlib-only, so a linter is a nicety, never a dependency of the suite.
"""

from __future__ import annotations

import ast
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Modules that are libraries (never talk to a terminal) vs CLI entry points.
LIBRARY = (
    "seeds/report.py", "seeds/profile.py", "seeds/distribution.py", "seeds/activity.py",
    "seeds/db.py", "seeds/text.py", "seeds/rng.py", "seeds/corpus.py",
    "mockapi/client.py", "load/scenarios.py",
)


def ruff_command() -> list[str] | None:
    if (exe := shutil.which("ruff")):
        return [exe]
    for candidate in (ROOT / ".venv/bin/ruff", ROOT / ".venv/Scripts/ruff.exe"):
        if candidate.exists():
            return [str(candidate)]
    return None


@unittest.skipUnless(ruff_command(), "ruff not installed (`pip install ruff` enables this)")
class LintTest(unittest.TestCase):
    def test_ruff_is_clean(self) -> None:
        proc = subprocess.run([*ruff_command(), "check", "--no-cache", "--quiet", "."],
                              cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"ruff said:\n{proc.stdout[-4000:]}{proc.stderr[-1500:]}")


class HygieneTest(unittest.TestCase):
    def test_library_modules_never_print(self) -> None:
        offenders: list[str] = []
        for rel in LIBRARY:
            tree = ast.parse((ROOT / rel).read_text(), filename=rel)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "print":
                    offenders.append(f"{rel}:{node.lineno}")
        self.assertEqual(offenders, [], f"print() inside a library module: {offenders}")

    def test_no_unfinished_markers(self) -> None:
        # Built by concatenation so this file does not match its own pattern.
        bad = re.compile(r"\b(" + "TODO|FIXME|XXX|HACK" + r")\b")
        found = []
        for path in ROOT.rglob("*.py"):
            if ".venv" in path.parts or "__pycache__" in path.parts:
                continue
            for i, line in enumerate(path.read_text().splitlines(), 1):
                if bad.search(line):
                    found.append(f"{path.relative_to(ROOT)}:{i}")
        self.assertEqual(found, [], f"unfinished markers shipped: {found}")


class ConsistencyTest(unittest.TestCase):
    def test_schema_columns_cover_what_the_seeder_writes(self) -> None:
        """The seeder once gained a column in USER_COLS without a matching
        `users` column (and vice versa) and only blew up at the first INSERT."""
        sql = (ROOT / "seeds" / "schema.sql").read_text()
        block = sql.split("CREATE TABLE IF NOT EXISTS users", 1)[1].split(");", 1)[0]
        columns = {m.group(1) for m in re.finditer(r"^\s{4}(\w+)\s+\w", block, re.M)}
        src = (ROOT / "seeds" / "seed.py").read_text()
        tree = ast.parse(src)
        written: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "USER_COLS":
                written = {e.value for e in node.value.elts}  # type: ignore[attr-defined]
        self.assertTrue(written, "USER_COLS not found in seeds/seed.py")
        self.assertEqual(written - columns, set(), "seeder writes columns the schema does not declare")
        required = written | {"id"}
        unused = columns - required
        self.assertLessEqual(unused, {"id"}, f"schema declares columns the seeder never fills: {unused}")

    def test_corpus_lists_have_no_duplicates_or_blanks(self) -> None:
        sys.path.insert(0, str(ROOT))
        from seeds import corpus

        for name in ("FIRST_NAMES", "LAST_NAMES", "ADJECTIVES", "NOUNS", "LANGUAGES"):
            values = list(getattr(corpus, name))
            self.assertTrue(values, f"{name} is empty")
            self.assertEqual(len(values), len(set(values)), f"{name} has duplicates")
            self.assertFalse([v for v in values if not v.strip()], f"{name} has blank entries")

    def test_every_entry_point_has_working_help(self) -> None:
        for mod in ("seeds.seed", "seeds.report_cli", "abuse.detector", "mockapi.server", "load.engine"):
            proc = subprocess.run([sys.executable, "-m", mod, "--help"], cwd=ROOT,
                                  capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, f"{mod} --help failed: {proc.stderr[-400:]}")
            self.assertIn("usage:", proc.stdout.lower(), f"{mod} has no usage line")

    def test_readme_flags_exist_in_cli_help(self) -> None:
        """Docs drift silently. Every `--flag` the README names must be a real
        option on one of the four entry points."""
        readme = (ROOT / "README.md").read_text()
        documented = set(re.findall(r"`(--[a-z][a-z0-9-]+)`", readme))
        self.assertGreater(len(documented), 12, "README stopped documenting flags?")
        help_text = ""
        for mod in ("seeds.seed", "seeds.report_cli", "abuse.detector", "mockapi.server", "load.engine"):
            help_text += subprocess.run([sys.executable, "-m", mod, "--help"], cwd=ROOT,
                                       capture_output=True, text=True).stdout
        self.assertEqual(sorted(f for f in documented if f not in help_text), [],
                         "README documents flags the CLIs do not accept")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
