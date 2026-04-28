#!/usr/bin/env python3

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BUILD_ROOT = ROOT / "build" / "tune_exe"
DIST_ROOT = ROOT / "dist"
HELPER_NAME = "meshtastic_listen_helper"
APP_NAME = "meshLoggerTune"


def _run(cmd: list[str]) -> None:
    print("+", " ".join(str(part) for part in cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def _shell_add_path_arg(src: Path, dest: str) -> str:
    separator = ";" if os.name == "nt" else ":"
    return f"{src}{separator}{dest}"


def _clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def _helper_exe_name() -> str:
    return f"{HELPER_NAME}.exe" if os.name == "nt" else HELPER_NAME


def _app_exe_name() -> str:
    return f"{APP_NAME}.exe" if os.name == "nt" else APP_NAME


def _build_mode_args(onefile: bool) -> list[str]:
    return ["--onefile"] if onefile else ["--onedir"]


def _ensure_pyinstaller() -> None:
    _run([sys.executable, "-m", "PyInstaller", "--version"])


def _resolve_meshtastic_python() -> Path | None:
    env_python = os.environ.get("MESHTASTIC_PYTHON")
    if env_python and Path(env_python).is_file():
        return Path(env_python)

    meshtastic_bin = shutil.which("meshtastic")
    if not meshtastic_bin:
        return None

    meshtastic_path = Path(meshtastic_bin)
    if meshtastic_path.suffix.lower() == ".exe":
        return None

    try:
        first_line = meshtastic_path.read_text(encoding="utf-8", errors="ignore").splitlines()[0].strip()
    except Exception:
        return None

    if not first_line.startswith("#!"):
        return None

    candidate = first_line[2:].strip()
    if candidate.startswith("/usr/bin/env "):
        candidate = candidate.split(None, 1)[1].strip()

    resolved = shutil.which(candidate) if not os.path.isabs(candidate) else candidate
    if resolved and Path(resolved).is_file():
        return Path(resolved)
    return None


def _resolve_meshtastic_site_packages() -> Path | None:
    python_exe = _resolve_meshtastic_python()
    if python_exe is None:
        return None

    cmd = [
        str(python_exe),
        "-c",
        "import sysconfig; print(sysconfig.get_paths()['purelib'])",
    ]
    result = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        return None

    purelib = Path(result.stdout.strip())
    if purelib.is_dir():
        return purelib
    return None


def _pyinstaller_base_cmd(
    *,
    name: str,
    distpath: Path,
    workpath: Path,
    specpath: Path,
    onefile: bool,
    extra_args: list[str] | None = None,
) -> list[str]:
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        *(_build_mode_args(onefile)),
        "--name",
        name,
        "--distpath",
        str(distpath),
        "--workpath",
        str(workpath),
        "--specpath",
        str(specpath),
    ]
    if extra_args:
        cmd.extend(extra_args)
    return cmd


def build_helper(*, onefile: bool, meshtastic_purelib: Path | None) -> Path:
    helper_dist_root = BUILD_ROOT / "helper-dist"
    helper_work_root = BUILD_ROOT / "helper-work"
    helper_spec_root = BUILD_ROOT / "helper-spec"

    _clean_dir(helper_dist_root)
    _clean_dir(helper_work_root)
    _clean_dir(helper_spec_root)

    extra_args: list[str] = []
    if meshtastic_purelib is not None:
        extra_args.extend(["--paths", str(meshtastic_purelib)])
    extra_args.extend(
        [
            "--collect-all",
            "meshtastic",
            "--collect-all",
            "pubsub",
            str(ROOT / "meshtastic_listen_helper.py"),
        ]
    )

    cmd = _pyinstaller_base_cmd(
        name=HELPER_NAME,
        distpath=helper_dist_root,
        workpath=helper_work_root,
        specpath=helper_spec_root,
        onefile=onefile,
        extra_args=extra_args,
    )
    _run(cmd)

    if onefile:
        helper_exe = helper_dist_root / _helper_exe_name()
    else:
        helper_exe = helper_dist_root / HELPER_NAME / _helper_exe_name()
    if not helper_exe.is_file():
        raise FileNotFoundError(f"helper executable was not created: {helper_exe}")
    return helper_exe


def build_main(*, onefile: bool, helper_exe: Path) -> Path:
    main_work_root = BUILD_ROOT / "main-work"
    main_spec_root = BUILD_ROOT / "main-spec"

    _clean_dir(main_work_root)
    _clean_dir(main_spec_root)
    DIST_ROOT.mkdir(parents=True, exist_ok=True)

    cmd = _pyinstaller_base_cmd(
        name=APP_NAME,
        distpath=DIST_ROOT,
        workpath=main_work_root,
        specpath=main_spec_root,
        onefile=onefile,
        extra_args=[
            "--add-binary",
            _shell_add_path_arg(helper_exe, "."),
            str(ROOT / "meshLogger_tune_entry.py"),
        ],
    )
    _run(cmd)

    if onefile:
        app_path = DIST_ROOT / _app_exe_name()
    else:
        app_path = DIST_ROOT / APP_NAME
    if not app_path.exists():
        raise FileNotFoundError(f"main artifact was not created: {app_path}")
    return app_path


def main() -> int:
    ap = argparse.ArgumentParser(description="Build meshLoggerTune executable with PyInstaller.")
    ap.add_argument(
        "--onedir",
        action="store_true",
        help="build an onedir package instead of the default onefile executable",
    )
    args = ap.parse_args()

    onefile = not args.onedir

    _ensure_pyinstaller()
    meshtastic_purelib = _resolve_meshtastic_site_packages()
    helper_exe = build_helper(onefile=True, meshtastic_purelib=meshtastic_purelib)
    app_path = build_main(onefile=onefile, helper_exe=helper_exe)

    print()
    print(f"Done: {app_path}")
    if onefile:
        print(f"Run:  {app_path}")
    else:
        print(f"Run:  {app_path / _app_exe_name()}")
    print("Note: meshtastic CLI must still be available in PATH for --info/--traceroute.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
