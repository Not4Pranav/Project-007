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


# Every module the README/Makefile tells people to run with `python3 -m`. A new CLI
# has to be listed here, which is the point: the two tests below then check its help
# output and every flag the README promises for it.
CLI_MODULES = ("seeds.seed", "seeds.report_cli", "seeds.export", "abuse.detector",
               "mockapi.server", "load.engine", "load.accounts", "console")


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
        # Assembled from split literals so this file cannot match its own pattern.
        markers = ("TO" "DO", "FIX" "ME", "XX" "X", "HA" "CK")
        bad = re.compile(r"\b(" + "|".join(markers) + r")\b")
        found = []
        for path in ROOT.rglob("*.py"):
            if ".venv" in path.parts or "__pycache__" in path.parts:
                continue
            for i, line in enumerate(path.read_text().splitlines(), 1):
                if bad.search(line):
                    found.append(f"{path.relative_to(ROOT)}:{i}")
        self.assertEqual(found, [], f"unfinished markers shipped: {found}")


class ConsistencyTest(unittest.TestCase):
    def test_make_targets_actually_run(self) -> None:
        """`make load` was a silent no-op for as long as the `load/` package existed:
        make found a *directory* named `load`, considered the target up to date, and
        printed nothing. Every documented target must therefore be .PHONY."""
        makefile = (ROOT / "Makefile").read_text()
        targets = sorted(set(re.findall(r"^([a-z][a-z-]*):.*?## ", makefile, re.M)))
        self.assertGreater(len(targets), 6, "help stopped documenting targets?")
        phony = set()
        for line in makefile.splitlines():
            if line.startswith(".PHONY:"):
                phony.update(line.split(":", 1)[1].split())
        shadowed = [t_ for t_ in targets if t_ not in phony and (ROOT / t_).exists()]
        self.assertEqual(shadowed, [], f"targets shadowed by a path of the same name: {shadowed}")
        self.assertTrue(set(targets) <= phony, f"not .PHONY: {set(targets) - phony}")


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
        for mod in CLI_MODULES:
            proc = subprocess.run([sys.executable, "-m", mod, "--help"], cwd=ROOT,
                                  capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, f"{mod} --help failed: {proc.stderr[-400:]}")
            self.assertIn("usage:", proc.stdout.lower(), f"{mod} has no usage line")

    def test_the_windows_launchers_say_things_that_work(self) -> None:
        """A `.bat` file is only ever executed by someone double-clicking it on Windows, so
        this box cannot run it — which is exactly why its contents get checked against the
        tools it calls instead of against a shell. A typo'd flag in here is noticed by the
        first person who tries the tool, not by whoever changed it."""
        help_text = subprocess.run([sys.executable, "-m", "console", "--help"], cwd=ROOT,
                                   capture_output=True, text=True).stdout
        run = (ROOT / "run.bat").read_text(encoding="utf-8", errors="replace")
        line = next((ln for ln in run.splitlines() if "-m console" in ln), "")
        self.assertTrue(line, "run.bat stopped launching the console")
        flags = set(re.findall(r"--[a-z][a-z0-9-]+", line))
        self.assertEqual({"--bootstrap", "--open-browser"}, flags,
                         f"the launcher is supposed to pass the first-run pair, saw {flags}")
        self.assertEqual(sorted(f for f in flags if f not in help_text), [],
                         f"run.bat passes a flag console refuses: {line!r}")
        raw = (ROOT / "run.bat").read_bytes() + (ROOT / "build_exe.bat").read_bytes()
        self.assertNotIn(b"\n", raw.replace(b"\r\n", b""),
                         "batch files need CRLF endings or goto/labels misbehave on Windows")

        build = (ROOT / "build_exe.bat").read_text(encoding="utf-8", errors="replace")
        self.assertIn("console\\__main__.py", build, "the .exe has to start where -m console starts")
        self.assertTrue((ROOT / "console" / "__main__.py").exists())
        data = re.search(r'--add-data "([^"]+)"', build)
        self.assertIsNotNone(data, "the seeder reads schema.sql next to its own module, so the "
                                   "bundle must carry it or the .exe fails on its first Generate")
        source = data.group(1).split(";")[0].replace("\\", "/")
        self.assertTrue((ROOT / source).is_file(), f"build_exe.bat bundles a path not in the repo: {source}")
        for pkg in re.findall(r"--collect-submodules\s+([a-z_]+)", build):
            self.assertTrue((ROOT / pkg / "__init__.py").is_file(),
                            f"--collect-submodules {pkg}: no such package to collect")
        # A bundled .exe has no interpreter to hand a child process, so every module the
        # console runs has to be called in-process. Spawning anywhere in the runtime
        # packages would turn build_exe.bat into an .exe that works until you press a button.
        spawn_calls = ("import subprocess", "os.system(", "os.popen(", "os.exec", "posix_spawn",
                       "os.spawn")
        spawners = [f"{path.relative_to(ROOT)}:{needle}" for pkg in
                    ("console", "load", "seeds", "mockapi", "abuse")
                    for path in sorted(ROOT.joinpath(pkg).glob("*.py"))
                    for needle in spawn_calls if needle in path.read_text()]
        self.assertEqual(spawners, [], f"{spawners} would break the frozen build")
        # `sys.executable` is allowed for exactly one thing: finding the .exe's own folder, so
        # relative paths land next to it. Anywhere else and it is a re-exec in disguise.
        readers = [str(path.relative_to(ROOT)) for pkg in ("console", "load", "seeds", "mockapi", "abuse")
                   for path in sorted(ROOT.joinpath(pkg).glob("*.py")) if "sys.executable" in path.read_text()]
        self.assertEqual(readers, ["console/server.py"], f"unexpected sys.executable readers: {readers}")
        server = (ROOT / "console" / "server.py").read_text()
        self.assertEqual(server.count("sys.executable"), 1, "only bundle_home() may name the interpreter path")

    def test_the_ci_build_and_the_bat_agree_on_their_flags(self) -> None:
        """`build_exe.bat` cannot run in CI (it ends in `pause`, which would hang the runner), so
        `.github/workflows/windows-exe.yml` repeats the PyInstaller command. Two copies of a
        build command is exactly where a bundle starts missing a data file and fails only on the
        other machine, so the two are compared here."""
        bat = (ROOT / "build_exe.bat").read_text(encoding="utf-8", errors="replace")
        wf_path = ROOT / ".github" / "workflows" / "windows-exe.yml"
        self.assertTrue(wf_path.is_file(), "the workflow that produces the .exe is gone")
        wf = wf_path.read_text(encoding="utf-8", errors="replace")
        block = wf[wf.index("Build SignupFixtureLab.exe"):]
        block = block[: block.index("- name:")]

        def flags(text: str) -> set[str]:
            return set(re.findall(r"--(?:name|onefile|clean|console|windowed|noconsole|add-data"
                                  r"|collect-submodules|hidden-import|paths)", text))

        self.assertEqual(flags(block), flags(bat), "the CI build passes different flags than build_exe.bat")
        self.assertEqual(set(re.findall(r"--collect-submodules\s+([a-z_]+)", block)),
                         set(re.findall(r"--collect-submodules\s+([a-z_]+)", bat)),
                         "a package collected in one and not the other is an ImportError on Windows")
        self.assertEqual(re.findall(r'--add-data "([^"]+)"', block),
                         re.findall(r'--add-data "([^"]+)"', bat), "the bundled data files must match")
        self.assertIn("console\__main__.py", block)
        # the smoke test has to look for the thing the product promises, not just for a port
        smoke = wf[wf.index("Smoke test the bundle"):]
        for probe in ("/api/state", r"dist\var\accounts.txt"):
            self.assertIn(probe, smoke, f"the CI smoke test stopped checking {probe!r}")

    def test_readme_flags_exist_in_cli_help(self) -> None:
        """Docs drift silently. Every `--flag` the README names must be a real
        option on one of the entry points in CLI_MODULES."""
        readme = (ROOT / "README.md").read_text()
        documented = set(re.findall(r"`(--[a-z][a-z0-9-]+)`", readme))
        self.assertGreater(len(documented), 12, "README stopped documenting flags?")
        help_text = ""
        for mod in CLI_MODULES:
            help_text += subprocess.run([sys.executable, "-m", mod, "--help"], cwd=ROOT,
                                       capture_output=True, text=True).stdout
        self.assertEqual(sorted(f for f in documented if f not in help_text), [],
                         "README documents flags the CLIs do not accept")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
