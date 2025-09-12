from __future__ import annotations
import sys, os, io, importlib, subprocess
from typing import Dict, List, Tuple

class DependencyManager:
    """
    Minimal dependency manager for Ghidra Python (PyGhidra/CPython).
    - Takes a dict {import_name: pip_name}.
    - Prompts the user to install missing ones via a Swing/Ghidra popup.
    - Reloads site/import caches so new installs are importable immediately.
    """

    def __init__(self, packages: Dict[str, str], *, title: str = "Missing Python Packages"):
        self.packages = packages
        self.title = title

    # -------- public API --------
    def ensure_or_prompt(self) -> bool:
        _, missing = self._try_imports(list(self.packages.keys()))
        if not missing:
            return True

        if not self._ask_to_install(missing):
            return False

        pip_names = [self.packages[name] for name in missing]
        if not self._pip_install(pip_names):
            return False

        self._reload_paths()
        _, still = self._try_imports(missing)
        if still:
            print("[deps] Still missing after install:", still)
            return False
        return True

    # -------- internals --------
    def _try_imports(self, names: List[str]) -> Tuple[List[str], List[str]]:
        ok, missing = [], []
        for n in names:
            try:
                importlib.import_module(n)
                ok.append(n)
            except Exception:
                missing.append(n)
        return ok, missing

    def _ask_to_install(self, missing: List[str]) -> bool:
        # Prefer Ghidra OptionDialog (GUI-safe)
        try:
            from docking.widgets import OptionDialog
            lines = ["The following Python packages are required and missing:\n"]
            lines += [f"  • import '{name}'   (pip install {self.packages[name]})" for name in missing]
            lines += ["", "Install them now with pip?"]
            msg = "\n".join(lines)
            return OptionDialog.showYesNoDialog(None, self.title, msg) == OptionDialog.YES_OPTION
        except Exception:
            # Headless fallback is unlikely in-tool, but just in case:
            print(f"{self.title}: will install {', '.join(self.packages[n] for n in missing)}")
            return True

    def _pip_install(self, pip_names: List[str]) -> bool:
        args = ["install", "--upgrade", "--no-input"] + pip_names
        print(f"[deps] pip {' '.join(args)}")

        # Suppress pip’s version check and ensure no interactive prompts
        env = dict(os.environ)
        env.setdefault("PIP_DISABLE_PIP_VERSION_CHECK", "1")
        env.setdefault("PYTHONWARNINGS", "ignore")  # optional: quiet noisy warnings


        # pip 20+: use cli.main
        from pip._internal.cli.main import main as pip_main  # type: ignore

        try:
            code = pip_main(args)
        except SystemExit as e:  # pip may call sys.exit()
            code = int(e.code) if e.code is not None else 0

        if int(code) == 0:
            return True
        print(f"[deps] pip (in-process) failed with code {code}")


    def _reload_paths(self) -> None:
        importlib.invalidate_caches()
        try:
            import site
            importlib.reload(site)  # process site-packages & .pth files
        except Exception:
            pass
        try:
            import pkg_resources  # type: ignore
            pkg_resources.working_set.__init__()  # rebuild dist cache
        except Exception:
            pass
